"""Issue #47: concurrent synthetic shadow profiling, never Bank acceptance."""

from __future__ import annotations

import json
from itertools import count

import pytest

from gasha.poc.concurrent_load import (
    ConcurrentSyntheticConfig,
    ConcurrentSyntheticReport,
    run_concurrent_synthetic_shadow,
)
from gasha.poc.load_baseline import SyntheticLoadConfig, SyntheticLoadReport


@pytest.mark.parametrize(
    ("workers", "iterations", "warmup"),
    [
        (0, 1, 0),
        (-1, 1, 0),
        (True, 1, 0),
        (33, 1, 0),
        (2, 0, 0),
        (2, -1, 0),
        (2, True, 0),
        (2, 1.5, 0),
        (2, 1001, 0),
        (2, 1, -1),
        (2, 1, True),
        (2, 1, 1001),
        (32, 1000, 0),
    ],
)
def test_bounded_concurrent_config_rejects_unsafe_values(
    workers: int, iterations: int, warmup: int,
) -> None:
    with pytest.raises(ValueError):
        ConcurrentSyntheticConfig(
            workers=workers, iterations_per_worker=iterations, warmup_per_worker=warmup
        )


def test_actual_existing_uc01_uc02_uc03_path_across_two_isolated_workers() -> None:
    config = ConcurrentSyntheticConfig(workers=2, iterations_per_worker=1, warmup_per_worker=1)
    report = run_concurrent_synthetic_shadow(config)
    assert report.aggregate.attempted_events == 34
    assert report.aggregate.evaluated_payments == 18
    assert report.aggregate.accepted_journey_events == 14
    assert report.aggregate.duplicate_events == 2
    assert report.aggregate.failed_events == 0
    assert len(report.aggregate.event_latencies_ms) == 34

    payload = report.to_dict()
    assert payload["schema_version"] == "gasha-synthetic-concurrent-load-1"
    assert payload["workers"] == 2
    assert payload["iterations_per_worker"] == 1
    assert payload["warmup_per_worker"] == 1
    assert payload["measured_iterations"] == 2
    assert payload["warmup_iterations"] == 2
    assert payload["latency_ms"]["sample_count"] == 34
    assert payload["latency_ms"]["p95"] <= payload["latency_ms"]["p99"]
    assert payload["latency_ms"]["p99"] <= payload["latency_ms"]["max"]
    assert payload["measurement_window"] == "unavailable_warmup_not_isolated"
    assert payload["observed_events_per_second"] is None
    assert payload["throughput_undefined_reason"] == "warmup_not_separately_timed"
    assert payload["measured_window_elapsed_seconds"] is None
    assert payload["whole_run_elapsed_seconds"] == payload["elapsed_seconds"]
    assert payload["source"] == "synthetic_only"
    assert payload["bank_kpi_approved"] is False
    assert payload["bank_delivery_accepted"] is False
    assert payload["enforcement_activated"] is False
    assert payload["assessment"] == "BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT"
    strict_json = json.dumps(payload, allow_nan=False)
    for forbidden in ("sim-customer", "sim-account", "Traceback"):
        assert forbidden not in strict_json


def test_aggregate_uses_all_event_samples_and_one_overlapping_wall_clock() -> None:
    sequence = count()

    def fake_worker(config: SyntheticLoadConfig) -> SyntheticLoadReport:
        latency = 1.0 if next(sequence) == 0 else 100.0
        return SyntheticLoadReport(
            config=config, attempted_events=1, evaluated_payments=1,
            accepted_journey_events=0, duplicate_events=0, failed_events=0,
            failure_types={}, elapsed_seconds=10.0,
            event_latencies_ms=(latency,),
        )

    times = iter((100, 100_000_100))
    report = run_concurrent_synthetic_shadow(
        ConcurrentSyntheticConfig(workers=2),
        worker_runner=fake_worker,
        clock_ns=lambda: next(times),
    )
    assert report.aggregate.elapsed_seconds == 0.1
    payload = report.to_dict()
    assert payload["attempted_events"] == 2
    assert payload["observed_events_per_second"] == 20.0
    assert payload["measurement_window"] == "whole_run_without_warmup"
    assert payload["throughput_undefined_reason"] is None
    assert payload["measured_window_elapsed_seconds"] == 0.1
    assert payload["latency_ms"]["mean"] == 50.5
    assert payload["latency_ms"]["p95"] == 100.0
    assert payload["latency_ms"]["p99"] == 100.0
    assert payload["latency_ms"]["sample_count"] == 2


def test_worker_failures_reconcile_as_failed_attempts_not_lost_samples() -> None:
    def fake_worker(config: SyntheticLoadConfig) -> SyntheticLoadReport:
        return SyntheticLoadReport(
            config=config, attempted_events=1, evaluated_payments=0,
            accepted_journey_events=0, duplicate_events=0, failed_events=1,
            failure_types={"TimeoutError": 1}, elapsed_seconds=1.0,
            event_latencies_ms=(5.0,),
        )

    report = run_concurrent_synthetic_shadow(
        ConcurrentSyntheticConfig(workers=3), worker_runner=fake_worker,
    )
    assert report.aggregate.attempted_events == 3
    assert report.aggregate.failed_events == 3
    assert report.aggregate.failure_types == {"TimeoutError": 3}
    payload = report.to_dict()
    assert payload["latency_ms"]["sample_count"] == 3
    assert payload["failure_types"] == {"TimeoutError": 3}
    assert payload["bank_kpi_approved"] is False


def test_nonpositive_clock_window_cannot_invent_throughput() -> None:
    report = run_concurrent_synthetic_shadow(
        ConcurrentSyntheticConfig(workers=1),
        clock_ns=lambda: 42,
    )
    assert report.to_dict()["observed_events_per_second"] is None


def test_clock_backwards_or_bad_type_rejected() -> None:
    times = iter((100, 99))
    with pytest.raises(ValueError, match="clock"):
        run_concurrent_synthetic_shadow(
            ConcurrentSyntheticConfig(workers=1),
            clock_ns=lambda: next(times),
        )
    with pytest.raises(ValueError, match="clock"):
        run_concurrent_synthetic_shadow(
            ConcurrentSyntheticConfig(workers=1),
            clock_ns=lambda: True,
        )


def test_mismatched_worker_evidence_is_not_aggregated() -> None:
    def wrong_config(_: SyntheticLoadConfig) -> SyntheticLoadReport:
        return SyntheticLoadReport(
            config=SyntheticLoadConfig(measured_iterations=99),
            attempted_events=0, evaluated_payments=0, accepted_journey_events=0,
            duplicate_events=0, failed_events=0, failure_types={},
            elapsed_seconds=0.0, event_latencies_ms=(),
        )

    with pytest.raises(ValueError, match="mismatched"):
        run_concurrent_synthetic_shadow(
            ConcurrentSyntheticConfig(workers=1), worker_runner=wrong_config,
        )


@pytest.mark.parametrize("warmup", [0, 1, 5])
def test_unexpected_worker_exception_aborts_without_emitting_partial_report(
    warmup: int,
) -> None:
    def crashed(_: SyntheticLoadConfig) -> SyntheticLoadReport:
        raise RuntimeError("synthetic-test-worker-failed")

    with pytest.raises(RuntimeError, match="synthetic-test-worker-failed"):
        run_concurrent_synthetic_shadow(
            ConcurrentSyntheticConfig(workers=2, warmup_per_worker=warmup),
            worker_runner=crashed,
        )


def test_concurrent_report_rejects_wrong_aggregate_iteration_identity() -> None:
    aggregate = SyntheticLoadReport(
        config=SyntheticLoadConfig(measured_iterations=1),
        attempted_events=0, evaluated_payments=0, accepted_journey_events=0,
        duplicate_events=0, failed_events=0, failure_types={},
        elapsed_seconds=0.0, event_latencies_ms=(),
    )
    with pytest.raises(ValueError, match="aggregate iterations"):
        ConcurrentSyntheticReport(
            ConcurrentSyntheticConfig(workers=2), aggregate,
        )


@pytest.mark.parametrize(
    ("workers", "warmup", "duration_ns", "expected_rate"),
    [
        (1, 0, 50_000_000, 20.0),
        (2, 0, 50_000_000, 40.0),
        (1, 1, 50_000_000, None),
        (1, 5, 500_000_000, None),
        (2, 1, 50_000_000, None),
        (2, 5, 500_000_000, None),
    ],
)
def test_measured_rate_never_divides_by_warmup_contaminated_window(
    workers: int, warmup: int, duration_ns: int, expected_rate: float | None,
) -> None:
    # The controlled clock represents either a short warm-up or a slow worker
    # warm-up; measured attempt counts stay fixed. The true measured-window
    # clock is unavailable if the baseline performs warm-up in its worker.
    def fake_worker(config: SyntheticLoadConfig) -> SyntheticLoadReport:
        return SyntheticLoadReport(
            config=config, attempted_events=1, evaluated_payments=1,
            accepted_journey_events=0, duplicate_events=0, failed_events=0,
            failure_types={}, elapsed_seconds=0.01,
            event_latencies_ms=(1.0,),
        )

    clock_times = iter((10_000_000, 10_000_000 + duration_ns))
    payload = run_concurrent_synthetic_shadow(
        ConcurrentSyntheticConfig(
            workers=workers, warmup_per_worker=warmup,
        ),
        worker_runner=fake_worker,
        clock_ns=lambda: next(clock_times),
    ).to_dict()
    assert payload["attempted_events"] == workers
    assert payload["observed_events_per_second"] == expected_rate
    assert payload["whole_run_elapsed_seconds"] == duration_ns / 1_000_000_000
    assert payload["measured_window_elapsed_seconds"] == (
        None if warmup else duration_ns / 1_000_000_000
    )
    assert payload["throughput_undefined_reason"] == (
        "warmup_not_separately_timed" if warmup else None
    )
    assert payload["latency_ms"]["sample_count"] == workers
    assert payload["enforcement_activated"] is False
    json.dumps(payload, allow_nan=False)


def test_zero_duration_without_warmup_has_explicit_undefined_reason() -> None:
    payload = run_concurrent_synthetic_shadow(
        ConcurrentSyntheticConfig(workers=1),
        clock_ns=lambda: 42,
    ).to_dict()
    assert payload["observed_events_per_second"] is None
    assert payload["throughput_undefined_reason"] == "zero_elapsed_window"
    assert payload["measured_window_elapsed_seconds"] == 0.0
