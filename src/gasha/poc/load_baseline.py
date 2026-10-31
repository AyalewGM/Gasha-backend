"""Synthetic-only UC-01/02/03 shadow workload baseline for POC Issue #47.

Not a bank adapter, SLA test, production load generator, or deployment gate.
All events and principals are synthetic; dependencies are deliberately in-memory.
A result cannot assert bank KPI acceptance or authorize enforcement.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from math import ceil, isfinite
from statistics import fmean
from time import perf_counter_ns
from types import MappingProxyType

from gasha.domain.models import DecisionAction, DecisionPolicy
from gasha.ingestion.reference import ReferenceJsonAdapter
from gasha.ingestion.service import IngestionOutcome, IngestionService
from gasha.journey.features import JourneyWindows
from gasha.journey.ingestion import JourneyIngestionOutcome, JourneyIngestionService
from gasha.journey.policy import JourneyRiskPolicy
from gasha.journey.provider import PolicyBoundJourneyIntelligence
from gasha.journey.repository import InMemoryJourneyEventRepository
from gasha.orchestration import InMemoryShadowEvaluationRepository, ShadowOrchestrator
from gasha.poc.bank_simulator import SyntheticBankSimulator, is_journey_inbound


@dataclass(frozen=True)
class SyntheticLoadConfig:
    measured_iterations: int = 1
    warmup_iterations: int = 0

    def __post_init__(self) -> None:
        if type(self.measured_iterations) is not int or self.measured_iterations < 1:
            raise ValueError("measured_iterations must be a positive integer")
        if type(self.warmup_iterations) is not int or self.warmup_iterations < 0:
            raise ValueError("warmup_iterations must be a nonnegative integer")


@dataclass(frozen=True)
class SyntheticLoadReport:
    config: SyntheticLoadConfig
    attempted_events: int
    evaluated_payments: int
    accepted_journey_events: int
    duplicate_events: int
    failed_events: int
    failure_types: Mapping[str, int]
    elapsed_seconds: float
    event_latencies_ms: tuple[float, ...]

    def __post_init__(self) -> None:
        """Require one consistent, non-identifying measured event population.

        This guards a locally constructed report against contradictory counts,
        non-finite timestamps and unsafe failure labels. It is not bank provenance.
        """
        if type(self.config) is not SyntheticLoadConfig:
            raise ValueError("config must be a SyntheticLoadConfig")
        for name in (
            "attempted_events",
            "evaluated_payments",
            "accepted_journey_events",
            "duplicate_events",
            "failed_events",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if (
            self.evaluated_payments
            + self.accepted_journey_events
            + self.duplicate_events
            + self.failed_events
            != self.attempted_events
        ):
            raise ValueError("outcome counts must reconcile with attempted events")
        if type(self.failure_types) is not dict:
            raise ValueError("failure_types must be a dictionary")
        for name, count in self.failure_types.items():
            if (
                type(name) is not str
                or not name.isascii()
                or not name.isidentifier()
                or len(name) > 80
                or type(count) is not int
                or count <= 0
            ):
                raise ValueError("failure_types require safe exception names and positive counts")
        if sum(self.failure_types.values()) != self.failed_events:
            raise ValueError("failure types must reconcile with failed events")
        if (
            type(self.elapsed_seconds) not in (int, float)
            or not isfinite(self.elapsed_seconds)
            or self.elapsed_seconds < 0
        ):
            raise ValueError("elapsed_seconds must be finite and nonnegative")
        if type(self.event_latencies_ms) is not tuple:
            raise ValueError("event_latencies_ms must be an immutable tuple")
        if len(self.event_latencies_ms) != self.attempted_events:
            raise ValueError("latency sample count must equal attempted events")
        if any(
            type(value) not in (int, float) or not isfinite(value) or value < 0
            for value in self.event_latencies_ms
        ):
            raise ValueError("latency samples must be finite and nonnegative")
        object.__setattr__(self, "failure_types", MappingProxyType(dict(self.failure_types)))

    def to_dict(self) -> dict[str, object]:
        sorted_ms = sorted(self.event_latencies_ms)
        count = len(sorted_ms)
        elapsed = self.elapsed_seconds
        observed_rate = self.attempted_events / elapsed if elapsed > 0 else None
        if observed_rate is not None and not isfinite(observed_rate):
            observed_rate = None
        return {
            "schema_version": "gasha-synthetic-load-1",
            "source": "synthetic_only",
            "workload": "sequential_in_memory_uc01_uc02_uc03_shadow",
            "bank_kpi_approved": False,
            "bank_delivery_accepted": False,
            "enforcement_activated": False,
            "assessment": "BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT",
            "measured_iterations": self.config.measured_iterations,
            "warmup_iterations": self.config.warmup_iterations,
            "attempted_events": self.attempted_events,
            "evaluated_payments": self.evaluated_payments,
            "accepted_journey_events": self.accepted_journey_events,
            "duplicate_events": self.duplicate_events,
            "failed_events": self.failed_events,
            "failure_types": dict(sorted(self.failure_types.items())),
            "elapsed_seconds": elapsed,
            "observed_events_per_second": observed_rate,
            "latency_ms": {
                "sample_count": count,
                "mean": fmean(sorted_ms) if count else None,
                "p95": sorted_ms[ceil(0.95 * count) - 1] if count else None,
                "p99": sorted_ms[ceil(0.99 * count) - 1] if count else None,
                "max": sorted_ms[-1] if count else None,
                "undefined_reason": None if count else "no_completed_event_samples",
            },
            "limitations": [
                "Not representative of bank arrival rates, concurrency, resource usage or latency.",
                "No PostgreSQL/Kafka outages, process recovery, reverse proxy or bank adapter.",
                "Measured transaction path is synthetic and in-memory, not protected production API.",
                "No bank-approved workload, KPI thresholds, timeout budgets or SLO verdict.",
            ],
        }


def run_synthetic_shadow_baseline(
    config: SyntheticLoadConfig,
    *,
    clock_ns: Callable[[], int] = perf_counter_ns,
) -> SyntheticLoadReport:
    """Measure the existing shared shadow path, not a parallel fraud engine.

    Each iteration resets in-memory stores and replays the same synthetic
    scenario distribution; warmup iterations are excluded from metrics.
    A duplicate payment is submitted once per iteration to observe dedupe.
    This deliberately measures sequential local execution only.
    """
    attempts = decisions = journeys_count = duplicates = failed = 0
    failure_types: dict[str, int] = {}
    latencies: list[float] = []
    total_elapsed_ns = 0

    for iteration in range(config.warmup_iterations + config.measured_iterations):
        measured = iteration >= config.warmup_iterations
        simulator = SyntheticBankSimulator()
        adapter = ReferenceJsonAdapter()
        payments = IngestionService({simulator.source_system: adapter})
        journey_repository = InMemoryJourneyEventRepository()
        journeys = JourneyIngestionService(
            {simulator.source_system: adapter}, journey_repository
        )
        policies = {
            simulator.tenant_id: DecisionPolicy(
                configuration_version="synthetic-config-1",
                policy_version="synthetic-policy-1",
                rule_version="synthetic-rules-1",
            )
        }
        journey_policies = {
            simulator.tenant_id: JourneyRiskPolicy(
                configuration_version="synthetic-journey-config-1",
                policy_version="synthetic-journey-policy-1",
                windows=JourneyWindows(authentication_window=timedelta(hours=3)),
            )
        }
        orchestrator = ShadowOrchestrator(
            policies,
            evaluations=InMemoryShadowEvaluationRepository(),
            journey=PolicyBoundJourneyIntelligence(journey_repository, journey_policies),
        )
        stream = (*simulator.ato_scenario(), *simulator.scenario_events())
        # An exact transport replay must not generate a second evaluation.
        stream = (*stream, stream[-1])

        window_start = clock_ns()
        for event in stream:
            started = clock_ns()
            error_name: str | None = None
            kind = ""
            try:
                if is_journey_inbound(event):
                    kind = "journey"
                    outcome = journeys.ingest(event)
                    if outcome.outcome is not JourneyIngestionOutcome.ACCEPTED:
                        raise RuntimeError("synthetic journey event not accepted")
                else:
                    result = payments.ingest(event)
                    if result.outcome is IngestionOutcome.DUPLICATE:
                        kind = "duplicate"
                    elif result.outcome is IngestionOutcome.ACCEPTED and result.envelope is not None:
                        kind = "decision"
                        evaluation = orchestrator.evaluate(result.envelope)
                        if evaluation.effective_action is not DecisionAction.NO_ACTION_SHADOW:
                            raise RuntimeError("synthetic shadow effective action is enforcing")
                    else:
                        raise RuntimeError("synthetic payment event not accepted")
            except Exception as exc:  # noqa: BLE001 - benchmark counts failures without PII
                error_name = type(exc).__name__
            ended = clock_ns()
            if ended < started:
                raise ValueError("measurement clock moved backwards")
            if not measured:
                continue
            attempts += 1
            latencies.append((ended - started) / 1_000_000)
            if error_name is not None:
                failed += 1
                failure_types[error_name] = failure_types.get(error_name, 0) + 1
            elif kind == "journey":
                journeys_count += 1
            elif kind == "decision":
                decisions += 1
            elif kind == "duplicate":
                duplicates += 1

        window_end = clock_ns()
        if window_end < window_start:
            raise ValueError("measurement clock moved backwards")
        if measured:
            total_elapsed_ns += window_end - window_start

    return SyntheticLoadReport(
        config=config,
        attempted_events=attempts,
        evaluated_payments=decisions,
        accepted_journey_events=journeys_count,
        duplicate_events=duplicates,
        failed_events=failed,
        failure_types=failure_types,
        elapsed_seconds=total_elapsed_ns / 1_000_000_000,
        event_latencies_ms=tuple(latencies),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Synthetic in-memory shadow baseline only; NOT bank performance acceptance"
    )
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=0)
    args = parser.parse_args()
    report = run_synthetic_shadow_baseline(
        SyntheticLoadConfig(
            measured_iterations=args.iterations,
            warmup_iterations=args.warmup,
        )
    )
    print(json.dumps(report.to_dict(), sort_keys=True))


if __name__ == "__main__":
    main()
