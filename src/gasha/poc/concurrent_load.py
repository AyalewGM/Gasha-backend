"""Bounded concurrent synthetic shadow profiling for POC Issue #47.

This is a local *threaded*, isolated-store extension of the existing #47
sequential benchmark. It is not a bank arrival process, an installed broker/DB
workload, an incumbent payment adapter or a latency/SLA acceptance test.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from time import perf_counter_ns

from gasha.poc.load_baseline import (
    SyntheticLoadConfig,
    SyntheticLoadReport,
    run_synthetic_shadow_baseline,
)


@dataclass(frozen=True, slots=True)
class ConcurrentSyntheticConfig:
    workers: int = 2
    iterations_per_worker: int = 1
    warmup_per_worker: int = 0

    def __post_init__(self) -> None:
        if type(self.workers) is not int or not 1 <= self.workers <= 32:
            raise ValueError("workers must be an integer from 1 through 32")
        if type(self.iterations_per_worker) is not int or not 1 <= self.iterations_per_worker <= 1000:
            raise ValueError("iterations_per_worker must be an integer from 1 through 1000")
        if type(self.warmup_per_worker) is not int or not 0 <= self.warmup_per_worker <= 1000:
            raise ValueError("warmup_per_worker must be an integer from 0 through 1000")
        if self.workers * (self.iterations_per_worker + self.warmup_per_worker) > 20000:
            raise ValueError("synthetic local workload exceeds the bounded cycle budget")


@dataclass(frozen=True, slots=True)
class ConcurrentSyntheticReport:
    config: ConcurrentSyntheticConfig
    aggregate: SyntheticLoadReport

    def __post_init__(self) -> None:
        if type(self.config) is not ConcurrentSyntheticConfig:
            raise ValueError("typed concurrent configuration required")
        if type(self.aggregate) is not SyntheticLoadReport:
            raise ValueError("typed reconciled aggregate required")
        if self.aggregate.config != SyntheticLoadConfig(
            measured_iterations=self.config.workers * self.config.iterations_per_worker,
            warmup_iterations=self.config.workers * self.config.warmup_per_worker,
        ):
            raise ValueError("aggregate iterations do not match concurrent worker configuration")

    def to_dict(self) -> dict[str, object]:
        # Reuse the existing, strictly validated one-population count and
        # nearest-rank quantile reporting, rather than averaging worker P95s.
        result = self.aggregate.to_dict()
        # The worker baseline executes warm-up *inside* each worker call.
        # This outer clock therefore covers both warm-up and measured attempts.
        # Until a synchronized post-warm-up window is available, do not
        # divide a measured-only event count by that mixed elapsed duration.
        warmup_present = self.config.warmup_per_worker > 0
        if warmup_present:
            result["observed_events_per_second"] = None
        result.update({
            "schema_version": "gasha-synthetic-concurrent-load-1",
            "workload": "threaded_isolated_in_memory_uc01_uc02_uc03_shadow",
            "workers": self.config.workers,
            "iterations_per_worker": self.config.iterations_per_worker,
            "warmup_per_worker": self.config.warmup_per_worker,
            "measurement_window": (
                "unavailable_warmup_not_isolated"
                if warmup_present else "whole_run_without_warmup"
            ),
            "whole_run_elapsed_seconds": self.aggregate.elapsed_seconds,
            "measured_window_elapsed_seconds": (
                None if warmup_present else self.aggregate.elapsed_seconds
            ),
            "throughput_undefined_reason": (
                "warmup_not_separately_timed"
                if warmup_present
                else (
                    "zero_elapsed_window"
                    if result["observed_events_per_second"] is None else None
                )
            ),
            "limitations": [
                "Synthetic threads use isolated in-memory services; no shared PostgreSQL or Kafka.",
                "Python threads do not establish bank CPU scaling or representative arrival rates.",
                "No real protected API, proxy, identity provider, network timeout or incumbent adapter.",
                "No Bank-approved workload, resource profile, KPI, SLO or failure-isolation proof.",
            ],
        })
        return result


def run_concurrent_synthetic_shadow(
    config: ConcurrentSyntheticConfig,
    *,
    worker_runner: Callable[[SyntheticLoadConfig], SyntheticLoadReport] = (
        run_synthetic_shadow_baseline
    ),
    clock_ns: Callable[[], int] = perf_counter_ns,
) -> ConcurrentSyntheticReport:
    """Measure overlapping independent #47 shadow baseline cycles.

    All worker stores are created inside the existing baseline runner. Wall
    time spans dispatch through join (including worker warm-up). When warm-up
    is nonzero the measured-only rate is explicitly undefined; the full-run
    elapsed time is retained for diagnostics only. Latency quantiles use *all*
    measured per-event samples, including failures. An unexpected worker exception
    aborts the report rather than silently dropping a workload segment.
    """
    if type(config) is not ConcurrentSyntheticConfig:
        raise ValueError("typed concurrent configuration required")
    worker_config = SyntheticLoadConfig(
        measured_iterations=config.iterations_per_worker,
        warmup_iterations=config.warmup_per_worker,
    )
    started = clock_ns()
    if type(started) is not int or started < 0:
        raise ValueError("monotonic clock must return nonnegative integer nanoseconds")
    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        reports = tuple(
            executor.map(worker_runner, (worker_config for _ in range(config.workers)))
        )
    ended = clock_ns()
    if type(ended) is not int or ended < started:
        raise ValueError("monotonic clock moved backward or returned an invalid value")

    for report in reports:
        if type(report) is not SyntheticLoadReport or report.config != worker_config:
            raise ValueError("worker returned a mismatched synthetic baseline report")

    failures: Counter[str] = Counter()
    for report in reports:
        failures.update(report.failure_types)
    aggregate = SyntheticLoadReport(
        config=SyntheticLoadConfig(
            measured_iterations=config.workers * config.iterations_per_worker,
            warmup_iterations=config.workers * config.warmup_per_worker,
        ),
        attempted_events=sum(report.attempted_events for report in reports),
        evaluated_payments=sum(report.evaluated_payments for report in reports),
        accepted_journey_events=sum(report.accepted_journey_events for report in reports),
        duplicate_events=sum(report.duplicate_events for report in reports),
        failed_events=sum(report.failed_events for report in reports),
        failure_types=dict(failures),
        elapsed_seconds=(ended - started) / 1_000_000_000,
        event_latencies_ms=tuple(
            latency for report in reports for latency in report.event_latencies_ms
        ),
    )
    return ConcurrentSyntheticReport(config, aggregate)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Threaded synthetic shadow baseline ONLY; not bank performance evidence"
    )
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=0)
    args = parser.parse_args()
    report = run_concurrent_synthetic_shadow(
        ConcurrentSyntheticConfig(
            workers=args.workers,
            iterations_per_worker=args.iterations,
            warmup_per_worker=args.warmup,
        )
    )
    print(json.dumps(report.to_dict(), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
