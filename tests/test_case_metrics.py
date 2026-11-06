"""Issue #45 synthetic case operations aggregate metrics; no Bank authority."""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
from hashlib import sha256
from uuid import NAMESPACE_URL, UUID, uuid5
from zoneinfo import ZoneInfo

import pytest

from gasha.cases.metrics import (
    CaseMetricsRejected,
    SyntheticAlertClock,
    summarize_synthetic_case_metrics,
)
from gasha.cases.timeline import (
    BankExecution,
    CaseDisposition,
    CaseEvent,
    CaseOperation,
    CaseReason,
    CaseRejected,
)

AS_OF = datetime(2026, 11, 1, 20, tzinfo=UTC)


def _uuid(value: str) -> UUID:
    return uuid5(NAMESPACE_URL, "synthetic-analyst-metrics:" + value)


def _steps(
    name: str,
    *steps: tuple[CaseOperation, int, CaseDisposition | None],
    tenant: str = "tenant-a",
) -> tuple[CaseEvent, ...]:
    case_id = _uuid("case-" + name)
    source_id = _uuid("source-" + name)
    events: list[CaseEvent] = []
    for index, (operation, minutes_before, disposition) in enumerate(steps, 1):
        reason = {
            CaseOperation.CREATE: CaseReason.SOURCE_EVALUATION,
            CaseOperation.TRIAGE: CaseReason.ANALYST_TRIAGE,
            CaseOperation.ASSIGN: CaseReason.INVESTIGATION_ASSIGNED,
            CaseOperation.DISPOSE: {
                CaseDisposition.FRAUD: CaseReason.FRAUD_EVIDENCE,
                CaseDisposition.LEGITIMATE: CaseReason.LEGITIMATE_EVIDENCE,
                CaseDisposition.UNRESOLVED: CaseReason.NEEDS_REVIEW,
            }.get(disposition, CaseReason.NEEDS_REVIEW),
            CaseOperation.CORRECT: CaseReason.CORRECTED_FINDING,
            CaseOperation.RECONCILE: CaseReason.FEEDBACK_RECONCILED,
        }[operation]
        token = sha256(f"{name}:{index}".encode()).hexdigest()
        events.append(CaseEvent(
            tenant_id=tenant,
            case_id=case_id,
            source_event_id=source_id,
            source_context_ref="a" * 64,
            revision=index,
            previous_revision=index - 1 if index > 1 else None,
            operation=operation,
            actor_ref="b" * 64,
            recorded_at=AS_OF - timedelta(minutes=minutes_before),
            reason_code=reason,
            disposition=disposition,
            assignee_ref="c" * 64 if operation is CaseOperation.ASSIGN else None,
            idempotency_ref=token,
            command_ref=sha256(("command:" + token).encode()).hexdigest(),
            bank_execution=BankExecution.UNKNOWN,
        ))
    return tuple(events)


CREATE = CaseOperation.CREATE
TRIAGE = CaseOperation.TRIAGE
ASSIGN = CaseOperation.ASSIGN
DISPOSE = CaseOperation.DISPOSE
CORRECT = CaseOperation.CORRECT
RECONCILE = CaseOperation.RECONCILE


def _done(name: str = "a") -> tuple[CaseEvent, ...]:
    return _steps(
        name,
        (CREATE, 60, None),
        (TRIAGE, 55, None),
        (ASSIGN, 50, None),
        (DISPOSE, 20, CaseDisposition.FRAUD),
        (RECONCILE, 10, None),
    )


def _unresolved(name: str = "b") -> tuple[CaseEvent, ...]:
    return _steps(
        name,
        (CREATE, 50, None),
        (TRIAGE, 45, None),
        (ASSIGN, 40, None),
        (DISPOSE, 30, CaseDisposition.UNRESOLVED),
    )


def _open(name: str = "c") -> tuple[CaseEvent, ...]:
    return _steps(name, (CREATE, 10, None))


def _clock(history: tuple[CaseEvent, ...]) -> SyntheticAlertClock:
    return SyntheticAlertClock(
        tenant_id=history[0].tenant_id,
        case_id=history[0].case_id,
        source_event_id=history[0].source_event_id,
        source_event_at=AS_OF - timedelta(minutes=80),
        alert_emitted_at=AS_OF - timedelta(minutes=78),
    )


def _report(
    *histories: tuple[CaseEvent, ...],
    clocks: tuple[SyntheticAlertClock, ...] = (),
    as_of: datetime = AS_OF,
) -> dict[str, object]:
    return summarize_synthetic_case_metrics(
        tenant_id="tenant-a", histories=histories, as_of=as_of, alert_clocks=clocks,
    )


def test_synthetic_case_snapshot_counts_rates_ages_and_unknown_clocks() -> None:
    done, unresolved, opened = _done(), _unresolved(), _open()
    snapshot = _report(done, unresolved, opened, clocks=(_clock(done),))
    assert snapshot["source"] == "caller_supplied_synthetic_case_histories_only"
    assert snapshot["bank_data_verified"] is False
    assert snapshot["bank_operational_kpi_authorized"] is False
    assert snapshot["enforcement_activated"] is False
    assert snapshot["counts"] == {
        "total_cases": 3,
        "open_investigations": 2,
        "dispositioned_cases": 2,
        "confirmed_fraud": 1,
        "confirmed_legitimate": 0,
        "unresolved": 1,
        "feedback_pending": 1,
        "reconciled": 1,
        "alert_timing_unknown": 2,
    }
    assert snapshot["backlog_age"] == {
        "count": 2, "denominator": 3, "eligible_count": 2,
        "missing_count": 0, "censored_count": 0, "excluded_count": 1,
        "coverage_rate": 2 / 3, "eligible_coverage_rate": 1.0,
        "mean_seconds": 1800.0, "max_seconds": 3000.0, "undefined_reason": None,
    }
    assert snapshot["investigation_turnaround"] == {
        "count": 2, "denominator": 3, "eligible_count": 2,
        "missing_count": 0, "censored_count": 1, "excluded_count": 0,
        "coverage_rate": 2 / 3, "eligible_coverage_rate": 1.0,
        "mean_seconds": 1200.0, "max_seconds": 1800.0, "undefined_reason": None,
    }
    assert snapshot["alert_latency"] == {
        "count": 1, "denominator": 3, "eligible_count": 3,
        "missing_count": 2, "censored_count": 0, "excluded_count": 0,
        "coverage_rate": 1 / 3, "eligible_coverage_rate": 1 / 3,
        "mean_seconds": 120.0, "max_seconds": 120.0, "undefined_reason": None,
    }
    assert snapshot["unresolved_rate"] == {
        "count": 1, "denominator": 2, "rate": 0.5, "undefined_reason": None,
    }
    text = json.dumps(snapshot, sort_keys=True, allow_nan=False)
    for history in (done, unresolved, opened):
        assert str(history[0].case_id) not in text
        assert str(history[0].source_event_id) not in text
        assert history[0].actor_ref not in text


def test_empty_snapshot_and_only_untriaged_cases_have_defined_missing_values() -> None:
    empty = _report()
    assert empty["counts"]["total_cases"] == 0
    for name in ("backlog_age", "investigation_turnaround", "alert_latency"):
        summary = empty[name]
        assert summary["denominator"] == 0
        assert summary["eligible_count"] == 0
        assert summary["missing_count"] == 0
        assert summary["censored_count"] == 0
        assert summary["excluded_count"] == 0
        assert summary["coverage_rate"] is None
        assert summary["eligible_coverage_rate"] is None
        assert summary["mean_seconds"] is None
    assert "NaN" not in json.dumps(empty, allow_nan=False)
    assert empty["alert_latency"]["mean_seconds"] is None
    assert empty["alert_latency"]["undefined_reason"] == "no_synthetic_alert_clocks"
    assert empty["unresolved_rate"]["rate"] is None
    assert empty["unresolved_rate"]["undefined_reason"] == "no_dispositions"
    opened = _report(_open())
    assert opened["counts"]["open_investigations"] == 1
    assert opened["investigation_turnaround"]["count"] == 0
    assert opened["investigation_turnaround"]["denominator"] == 1
    assert opened["investigation_turnaround"]["eligible_count"] == 0
    assert opened["investigation_turnaround"]["censored_count"] == 1
    assert opened["investigation_turnaround"]["eligible_coverage_rate"] is None
    assert opened["investigation_turnaround"]["coverage_rate"] == 0.0
    assert opened["alert_latency"]["missing_count"] == 1
    assert opened["investigation_turnaround"]["undefined_reason"] == (
        "no_completed_investigations"
    )
    assert opened["alert_latency"]["count"] == 0
    assert opened["alert_latency"]["denominator"] == 1


def test_last_corrected_disposition_changes_unresolved_not_first_turnaround() -> None:
    history = _steps(
        "corrected", (CREATE, 60, None), (TRIAGE, 55, None),
        (ASSIGN, 50, None), (DISPOSE, 20, CaseDisposition.FRAUD),
        (CORRECT, 15, CaseDisposition.UNRESOLVED),
    )
    report = _report(history)
    assert report["counts"]["confirmed_fraud"] == 0
    assert report["counts"]["unresolved"] == 1
    assert report["counts"]["feedback_pending"] == 1
    assert report["counts"]["open_investigations"] == 1
    assert report["investigation_turnaround"]["mean_seconds"] == 1800.0
    assert report["unresolved_rate"]["rate"] == 1.0


def test_legitimate_and_reconciled_unresolved_are_not_assumed_fraud_or_prevention() -> None:
    legitimate = _steps(
        "legitimate", (CREATE, 60, None), (TRIAGE, 55, None),
        (ASSIGN, 50, None), (DISPOSE, 40, CaseDisposition.LEGITIMATE),
    )
    unresolved_closed = _unresolved() + (
        replace(
            _unresolved()[-1],
            revision=5, previous_revision=4,
            operation=RECONCILE, reason_code=CaseReason.FEEDBACK_RECONCILED,
            disposition=None, recorded_at=AS_OF - timedelta(minutes=20),
            idempotency_ref="d" * 64, command_ref="e" * 64,
        ),
    )
    snapshot = _report(legitimate, unresolved_closed)
    assert snapshot["counts"]["confirmed_legitimate"] == 1
    assert snapshot["counts"]["unresolved"] == 1
    assert snapshot["counts"]["reconciled"] == 1
    assert snapshot["counts"]["open_investigations"] == 0
    assert snapshot["counts"]["feedback_pending"] == 1
    assert snapshot["backlog_age"]["mean_seconds"] is None
    assert snapshot["unresolved_rate"]["rate"] == 0.5


@pytest.mark.parametrize("histories", [
    [ _done() ],
    ((),),
    (_done(), _done()),
    (_steps("other", (CREATE, 5, None), tenant="tenant-b"),),
])
def test_untrusted_or_ambiguous_case_histories_fail_closed(histories: object) -> None:
    with pytest.raises((CaseMetricsRejected, CaseRejected)):
        summarize_synthetic_case_metrics(
            tenant_id="tenant-a", histories=histories, as_of=AS_OF,  # type: ignore[arg-type]
        )


def test_duplicate_source_evaluation_under_other_case_id_rejected() -> None:
    first, second = _open("one"), _open("two")
    substituted = (replace(second[0], source_event_id=first[0].source_event_id),)
    with pytest.raises(CaseMetricsRejected, match="duplicate case or source"):
        _report(first, substituted)


@pytest.mark.parametrize("change", [
    {"revision": 9},
    {"previous_revision": 9},
    {"bank_execution": "executed"},
    {"source_context_ref": "raw-customer-id"},
    {"actor_ref": "raw-analyst"},
])
def test_corrupted_case_event_is_not_counted(change: dict[str, object]) -> None:
    history = _done()
    corrupted = (replace(history[0], **change),) + history[1:]
    with pytest.raises((CaseRejected, CaseMetricsRejected)):
        _report(corrupted)


def test_future_event_and_regressed_event_clock_rejected_before_metrics() -> None:
    future = (replace(_open()[0], recorded_at=AS_OF + timedelta(seconds=1)),)
    with pytest.raises(CaseMetricsRejected, match="future-dated"):
        _report(future)
    history = _done()
    bad = history[:1] + (
        replace(history[1], recorded_at=history[0].recorded_at - timedelta(seconds=1)),
    ) + history[2:]
    with pytest.raises(CaseRejected):
        _report(bad)


@pytest.mark.parametrize("invalid_now", [
    datetime(2026, 11, 1, 20),
    "2026-11-01T20:00:00Z",
    None,
])
def test_malformed_as_of_rejected(invalid_now: object) -> None:
    with pytest.raises(CaseMetricsRejected):
        _report(_done(), as_of=invalid_now)  # type: ignore[arg-type]


def test_synthetic_alert_clocks_are_optional_but_must_match_case_and_source() -> None:
    done = _done()
    good = _clock(done)
    with pytest.raises(CaseMetricsRejected, match="wrong-tenant"):
        _report(done, clocks=(replace(good, tenant_id="tenant-b"),))
    with pytest.raises(CaseMetricsRejected, match="unknown, duplicate"):
        _report(done, clocks=(replace(good, case_id=_uuid("absent")),))
    with pytest.raises(CaseMetricsRejected, match="unknown, duplicate"):
        _report(done, clocks=(replace(good, source_event_id=_uuid("wrong-source")),))
    with pytest.raises(CaseMetricsRejected, match="unknown, duplicate"):
        _report(done, clocks=(good, good))


def test_synthetic_alert_temporal_causality_and_missing_is_not_zero() -> None:
    history = _done()
    good = _clock(history)
    with pytest.raises(CaseMetricsRejected, match="alert cannot precede"):
        replace(good, source_event_at=good.alert_emitted_at + timedelta(seconds=1))
    with pytest.raises(CaseMetricsRejected, match="unknown, duplicate"):
        _report(history, clocks=(
            replace(good, alert_emitted_at=history[0].recorded_at + timedelta(seconds=1)),
        ))
    without_clock = _report(history)
    assert without_clock["alert_latency"]["count"] == 0
    assert without_clock["alert_latency"]["mean_seconds"] is None


def test_dst_fold_offsets_use_utc_instants_for_backlog_and_alert_latency() -> None:
    ny = ZoneInfo("America/New_York")
    first = datetime(2026, 11, 1, 1, 45, tzinfo=ny, fold=0)
    later = datetime(2026, 11, 1, 1, 15, tzinfo=ny, fold=1)
    assert first.astimezone(UTC) < later.astimezone(UTC)
    history = _steps("dst", (CREATE, 60, None), (TRIAGE, 55, None))
    history = (
        replace(history[0], recorded_at=first),
        replace(history[1], recorded_at=later),
    )
    clock = SyntheticAlertClock(
        tenant_id="tenant-a", case_id=history[0].case_id,
        source_event_id=history[0].source_event_id,
        source_event_at=first - timedelta(minutes=2),
        alert_emitted_at=first - timedelta(minutes=1),
    )
    report = _report(history, clocks=(clock,), as_of=later.astimezone(UTC) + timedelta(minutes=5))
    assert report["backlog_age"]["mean_seconds"] == 2100.0
    assert report["alert_latency"]["mean_seconds"] == 60.0


def test_reject_malformed_clocks_scope_and_mutable_clock_inputs() -> None:
    history = _done()
    with pytest.raises(CaseMetricsRejected):
        _report(history, clocks=[_clock(history)])  # type: ignore[arg-type]
    with pytest.raises(CaseMetricsRejected):
        summarize_synthetic_case_metrics(
            tenant_id=" tenant-a", histories=(history,), as_of=AS_OF,
        )
    with pytest.raises(CaseMetricsRejected):
        SyntheticAlertClock(
            "tenant-a", history[0].case_id, history[0].source_event_id,
            datetime(2026, 11, 1, 18), AS_OF,
        )


def test_censoring_and_missing_timing_cover_every_synthetic_case() -> None:
    complete = _done("complete-coverage")
    pending = _unresolved("pending-coverage")
    open_case = _open("open-coverage")
    report = _report(complete, pending, open_case)
    for name in ("backlog_age", "investigation_turnaround", "alert_latency"):
        duration = report[name]
        assert (
            duration["count"] + duration["missing_count"]
            + duration["censored_count"] + duration["excluded_count"]
            == duration["denominator"] == 3
        )
        assert duration["count"] + duration["missing_count"] == duration["eligible_count"]
    assert report["investigation_turnaround"]["censored_count"] == 1
    assert report["alert_latency"]["missing_count"] == 3
    assert report["alert_latency"]["coverage_rate"] == 0.0
    assert report["alert_latency"]["eligible_coverage_rate"] == 0.0
    assert report["alert_latency"]["mean_seconds"] is None
    assert "NaN" not in json.dumps(report, allow_nan=False)


def test_reassignment_cannot_reset_first_assignment_clock() -> None:
    # The canonical append-only lifecycle admits exactly one ASSIGN. Neither
    # a second ASSIGN nor an unassigned DISPOSE can enter the aggregate.
    reassignment = _steps(
        "reassigned", (CREATE, 60, None), (TRIAGE, 55, None),
        (ASSIGN, 50, None), (ASSIGN, 40, None),
        (DISPOSE, 20, CaseDisposition.FRAUD),
    )
    with pytest.raises(CaseRejected, match="invalid case lifecycle"):
        _report(_done(), reassignment)
    without_assignment = _steps(
        "missing-assignment", (CREATE, 60, None), (TRIAGE, 55, None),
        (DISPOSE, 20, CaseDisposition.FRAUD),
    )
    with pytest.raises(CaseRejected, match="invalid case lifecycle"):
        _report(_done(), without_assignment)
    valid = _report(_done())
    assert valid["investigation_turnaround"]["count"] == 1
    assert valid["investigation_turnaround"]["mean_seconds"] == 1800.0
    assert valid["investigation_turnaround"]["missing_count"] == 0


@pytest.mark.parametrize("invalid", [
    datetime(2026, 11, 1, 18),
    "2026-11-01T18:00:00Z",
    None,
    0,
])
def test_external_synthetic_clocks_must_be_typed_and_aware(invalid: object) -> None:
    history = _done()
    valid = _clock(history)
    with pytest.raises(CaseMetricsRejected):
        replace(valid, source_event_at=invalid)  # type: ignore[arg-type]
    with pytest.raises(CaseMetricsRejected):
        replace(valid, alert_emitted_at=invalid)  # type: ignore[arg-type]


def test_equivalent_utc_offset_instants_keep_timing_canonical() -> None:
    from datetime import timezone
    hour_ahead = timezone(timedelta(hours=1))
    history = _done()
    clock = _clock(history)
    shifted = replace(
        clock,
        source_event_at=clock.source_event_at.astimezone(hour_ahead),
        alert_emitted_at=clock.alert_emitted_at.astimezone(hour_ahead),
    )
    assert _report(history, clocks=(clock,))["alert_latency"] == (
        _report(history, clocks=(shifted,))["alert_latency"]
    )


@pytest.mark.parametrize(("field", "bad_value"), [
    ("tenant_id", "tenant-b"),
    ("case_id", "not-a-uuid"),
    ("source_event_id", "not-a-uuid"),
    ("source_event_at", AS_OF - timedelta(minutes=70)),
    ("alert_emitted_at", AS_OF - timedelta(minutes=90)),
    ("source_event_at", "2026-11-01T18:00:00Z"),
    ("alert_emitted_at", None),
])
def test_post_construction_mutated_alert_clock_is_rejected(
    field: str, bad_value: object,
) -> None:
    history = _done()
    clock = _clock(history)
    # Frozen/slotted dataclasses still permit low-level mutation.
    object.__setattr__(clock, field, bad_value)
    with pytest.raises(CaseMetricsRejected):
        _report(history, clocks=(clock,))


@pytest.mark.parametrize("field", [
    "tenant_id", "case_id", "source_event_id",
    "source_event_at", "alert_emitted_at",
])
def test_deleted_alert_clock_attribute_is_rejected(field: str) -> None:
    history = _done()
    clock = _clock(history)
    object.__delattr__(clock, field)
    with pytest.raises(CaseMetricsRejected, match="invalid synthetic alert clock"):
        _report(history, clocks=(clock,))


def test_valid_synthetic_clock_still_reports_nonnegative_latency() -> None:
    history = _done()
    report = _report(history, clocks=(_clock(history),))
    assert report["alert_latency"]["count"] == 1
    assert report["alert_latency"]["mean_seconds"] == 120.0
    assert report["alert_latency"]["missing_count"] == 0


class _CallbackTimezone(tzinfo):
    """A valid datetime may carry a callback-capable untrusted tzinfo."""

    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta:
        self.calls += 1
        raise AssertionError("untrusted timezone callback executed")

    def dst(self, dt: datetime | None) -> timedelta | None:
        return None

    def tzname(self, dt: datetime | None) -> str | None:
        return "untrusted"


class _CallbackDatetime(datetime):
    """Datetime subclasses also cannot be trusted as a clock boundary."""

    calls = 0

    def utcoffset(self) -> timedelta:
        type(self).calls += 1
        raise AssertionError("untrusted datetime callback executed")


@pytest.mark.parametrize("field", [
    "as_of",
    "source_event_at",
    "alert_emitted_at",
    "mutated_source_event_at",
    "mutated_alert_emitted_at",
])
def test_synthetic_metric_clock_rejects_untrusted_timezone_before_callback(
    field: str,
) -> None:
    history = _done()
    bad_zone = _CallbackTimezone()
    malicious_clock = datetime(2026, 11, 1, 18, tzinfo=bad_zone)
    if field == "as_of":
        with pytest.raises(CaseMetricsRejected):
            _report(history, as_of=malicious_clock)
    elif field.startswith("mutated_"):
        clock = _clock(history)
        object.__setattr__(clock, field.removeprefix("mutated_"), malicious_clock)
        with pytest.raises(CaseMetricsRejected):
            _report(history, clocks=(clock,))
    else:
        with pytest.raises(CaseMetricsRejected):
            replace(_clock(history), **{field: malicious_clock})
    assert bad_zone.calls == 0


@pytest.mark.parametrize("field", [
    "as_of", "source_event_at", "alert_emitted_at",
])
def test_synthetic_metric_clock_rejects_datetime_subclass_before_callback(
    field: str,
) -> None:
    history = _done()
    _CallbackDatetime.calls = 0
    malicious_clock = _CallbackDatetime(2026, 11, 1, 18, tzinfo=UTC)
    if field == "as_of":
        with pytest.raises(CaseMetricsRejected):
            _report(history, as_of=malicious_clock)
    else:
        with pytest.raises(CaseMetricsRejected):
            replace(_clock(history), **{field: malicious_clock})
    assert _CallbackDatetime.calls == 0
