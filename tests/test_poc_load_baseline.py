"""Issue #47 synthetic baseline: no invented bank throughput or acceptance."""

from __future__ import annotations

import json

import pytest

from gasha.orchestration import ShadowOrchestrator
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


@pytest.mark.parametrize(
    "overrides",
    [
        {"config": None},
        {"attempted_events": True},
        {"attempted_events": -1},
        {"evaluated_payments": 2},
        {"failed_events": 0},
        {"failure_types": {}},
        {"failure_types": {"TimeoutError": 0}},
        {"failure_types": {"TimeoutError": True}},
        {"failure_types": {"customer-123": 1}},
        {"failure_types": {"TïmeoutError": 1}},
        {"failure_types": {"TimeoutError": 2}},
        {"failure_types": ["TimeoutError"]},
        {"elapsed_seconds": -1.0},
        {"elapsed_seconds": True},
        {"elapsed_seconds": float("nan")},
        {"elapsed_seconds": float("inf")},
        {"event_latencies_ms": [1.0, 2.0]},
        {"event_latencies_ms": (1.0,)},
        {"event_latencies_ms": (-1.0, 2.0)},
        {"event_latencies_ms": (float("nan"), 2.0)},
        {"event_latencies_ms": (float("inf"), 2.0)},
        {"event_latencies_ms": (True, 2.0)},
    ],
)
def test_synthetic_report_rejects_unreconciled_or_unsafe_evidence(overrides) -> None:
    candidate = {
        "config": SyntheticLoadConfig(),
        "attempted_events": 2,
        "evaluated_payments": 1,
        "accepted_journey_events": 0,
        "duplicate_events": 0,
        "failed_events": 1,
        "failure_types": {"TimeoutError": 1},
        "elapsed_seconds": 2.0,
        "event_latencies_ms": (1.0, 2.0),
    }
    candidate.update(overrides)
    with pytest.raises(ValueError):
        SyntheticLoadReport(**candidate)


def test_failure_categories_are_snapshotted_and_immutable() -> None:
    errors = {"TimeoutError": 1}
    report = SyntheticLoadReport(
        config=SyntheticLoadConfig(),
        attempted_events=2,
        evaluated_payments=1,
        accepted_journey_events=0,
        duplicate_events=0,
        failed_events=1,
        failure_types=errors,
        elapsed_seconds=1.0,
        event_latencies_ms=(1.0, 2.0),
    )
    errors["raw_customer_reference"] = 99
    assert dict(report.failure_types) == {"TimeoutError": 1}
    assert report.to_dict()["failure_types"] == {"TimeoutError": 1}
    json.dumps(report.to_dict(), allow_nan=False)
    with pytest.raises(TypeError):
        report.failure_types["OtherError"] = 1


def test_nonfinite_observed_rate_is_not_serialized() -> None:
    report = SyntheticLoadReport(
        config=SyntheticLoadConfig(),
        attempted_events=1,
        evaluated_payments=1,
        accepted_journey_events=0,
        duplicate_events=0,
        failed_events=0,
        failure_types={},
        elapsed_seconds=5e-324,
        event_latencies_ms=(0.0,),
    )
    payload = report.to_dict()
    assert payload["observed_events_per_second"] is None
    assert payload["bank_kpi_approved"] is False
    assert payload["enforcement_activated"] is False


def test_unrepresentable_finite_latency_mean_is_rejected_before_serialization() -> None:
    with pytest.raises(ValueError, match="latency mean must be finite"):
        SyntheticLoadReport(
            config=SyntheticLoadConfig(),
            attempted_events=2,
            evaluated_payments=2,
            accepted_journey_events=0,
            duplicate_events=0,
            failed_events=0,
            failure_types={},
            elapsed_seconds=1.0,
            event_latencies_ms=(1e308, 1e308),
        )


def test_large_representable_latency_mean_keeps_finite_quantiles() -> None:
    report = SyntheticLoadReport(
        config=SyntheticLoadConfig(),
        attempted_events=2,
        evaluated_payments=2,
        accepted_journey_events=0,
        duplicate_events=0,
        failed_events=0,
        failure_types={},
        elapsed_seconds=5e-324,
        event_latencies_ms=(1.0, 1e308),
    )
    payload = report.to_dict()
    assert payload["latency_ms"]["mean"] == 5e307
    assert payload["latency_ms"]["p95"] == 1e308
    assert payload["latency_ms"]["p99"] == 1e308
    assert payload["latency_ms"]["max"] == 1e308
    assert payload["observed_events_per_second"] is None
    assert payload["source"] == "synthetic_only"
    assert payload["bank_kpi_approved"] is False
    assert payload["bank_delivery_accepted"] is False
    assert payload["enforcement_activated"] is False
    assert payload["assessment"] == "BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT"
    json.dumps(payload, allow_nan=False)


def test_configuration_counters_must_serialize_strictly() -> None:
    config = SyntheticLoadConfig(measured_iterations=10**5000)
    with pytest.raises(ValueError, match="JSON serializable"):
        SyntheticLoadReport(
            config=config,
            attempted_events=0,
            evaluated_payments=0,
            accepted_journey_events=0,
            duplicate_events=0,
            failed_events=0,
            failure_types={},
            elapsed_seconds=0.0,
            event_latencies_ms=(),
        )


def test_measured_producer_failure_does_not_export_exception_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive = "synthetic-customer-123 synthetic-account-456 reference-789"

    def raise_sensitive_error(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(sensitive)

    monkeypatch.setattr(ShadowOrchestrator, "evaluate", raise_sensitive_error)
    report = run_synthetic_shadow_baseline(SyntheticLoadConfig())
    assert report.failed_events > 0
    assert dict(report.failure_types) == {"RuntimeError": report.failed_events}
    payload = report.to_dict()
    serialized = json.dumps(payload, allow_nan=False)
    for forbidden in ("synthetic-customer-123", "synthetic-account-456", "reference-789", "Traceback"):
        assert forbidden not in serialized
    assert payload["source"] == "synthetic_only"
    assert payload["bank_kpi_approved"] is False
    assert payload["bank_delivery_accepted"] is False
    assert payload["enforcement_activated"] is False
    assert payload["assessment"] == "BLOCKED_EXTERNAL_BANK_WORKLOAD_AND_DEPLOYMENT"
