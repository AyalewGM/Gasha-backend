"""Issue #47 synthetic baseline: no invented bank throughput or acceptance."""

from __future__ import annotations

import json

import pytest

from gasha.poc.load_baseline import (
    SyntheticLoadConfig,
    SyntheticLoadReport,
    run_synthetic_shadow_baseline,
)


@pytest.mark.parametrize(
    ("iterations", "warmup"),
    [(0, 0), (-1, 0), (True, 0), (1.0, 0), (1, -1), (1, True), (1, "1")],
)
def test_load_config_rejects_invalid_runtime_values(iterations, warmup) -> None:
    with pytest.raises(ValueError):
        SyntheticLoadConfig(measured_iterations=iterations, warmup_iterations=warmup)


def test_synthetic_uc01_uc02_uc03_shadow_and_duplicate_baseline() -> None:
    report = run_synthetic_shadow_baseline(
        SyntheticLoadConfig(measured_iterations=2, warmup_iterations=1)
    )
    assert report.attempted_events == 34
    assert report.accepted_journey_events == 14
    assert report.evaluated_payments == 18
    assert report.duplicate_events == 2
    assert report.failed_events == 0
    assert report.failure_types == {}
    assert len(report.event_latencies_ms) == 34
    assert all(elapsed >= 0 for elapsed in report.event_latencies_ms)

    payload = report.to_dict()
    assert payload["source"] == "synthetic_only"
    assert payload["enforcement_activated"] is False
    assert payload["bank_kpi_approved"] is False
    assert payload["bank_delivery_accepted"] is False
    assert payload["assessment"] == "BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT"
    assert payload["warmup_iterations"] == 1
    assert payload["measured_iterations"] == 2
    assert payload["latency_ms"]["sample_count"] == 34
    assert payload["latency_ms"]["p95"] <= payload["latency_ms"]["p99"]
    assert payload["latency_ms"]["p99"] <= payload["latency_ms"]["max"]
    # The machine-readable payload contains aggregates, never raw synthetic IDs.
    serialized = json.dumps(payload)
    assert "sim-customer" not in serialized
    assert "sim-account" not in serialized


def test_nearest_rank_quantiles_and_measured_throughput() -> None:
    config = SyntheticLoadConfig()
    report = SyntheticLoadReport(
        config=config,
        attempted_events=5,
        evaluated_payments=5,
        accepted_journey_events=0,
        duplicate_events=0,
        failed_events=0,
        failure_types={},
        elapsed_seconds=2.0,
        event_latencies_ms=(5.0, 1.0, 4.0, 2.0, 3.0),
    )
    payload = report.to_dict()
    latency = payload["latency_ms"]
    assert payload["observed_events_per_second"] == 2.5
    assert latency["mean"] == 3.0
    assert latency["p95"] == 5.0
    assert latency["p99"] == 5.0
    assert latency["max"] == 5.0


def test_no_elapsed_time_cannot_claim_observed_throughput() -> None:
    report = run_synthetic_shadow_baseline(
        SyntheticLoadConfig(), clock_ns=lambda: 100
    )
    payload = report.to_dict()
    assert payload["observed_events_per_second"] is None
    assert payload["failed_events"] == 0
    assert payload["latency_ms"]["mean"] == 0.0
    assert payload["bank_kpi_approved"] is False


def test_nonmonotonic_measurement_clock_is_rejected() -> None:
    times = iter((100, 200, 199))
    with pytest.raises(ValueError, match="clock moved backwards"):
        run_synthetic_shadow_baseline(
            SyntheticLoadConfig(), clock_ns=lambda: next(times)
        )


def test_zero_successful_samples_have_null_metrics_and_reason() -> None:
    payload = SyntheticLoadReport(
        config=SyntheticLoadConfig(),
        attempted_events=0,
        evaluated_payments=0,
        accepted_journey_events=0,
        duplicate_events=0,
        failed_events=0,
        failure_types={},
        elapsed_seconds=0.0,
        event_latencies_ms=(),
    ).to_dict()
    assert payload["latency_ms"] == {
        "sample_count": 0,
        "mean": None,
        "p95": None,
        "p99": None,
        "max": None,
        "undefined_reason": "no_completed_event_samples",
    }
    assert payload["observed_events_per_second"] is None
