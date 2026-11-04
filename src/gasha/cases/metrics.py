"""Synthetic-only #45 analyst-operation metrics from validated append-only case histories.

No Bank metrics or provenance are asserted. An installed authorized tenant reader
must provide histories and clocks before this could inform operational reporting.
Nothing here reads/writes storage, authenticates users, or invokes a payment action.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from uuid import UUID

from gasha.cases.timeline import (
    CaseDisposition,
    CaseEvent,
    CaseOperation,
    validate_case_history,
)

_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


class CaseMetricsRejected(ValueError):
    """Invalid synthetic metric scope or ambiguous/corrupt history."""


def _instant(value: datetime) -> datetime:
    if type(value) is not datetime or value.utcoffset() is None:
        raise CaseMetricsRejected("timezone-aware timestamp required")
    return value.astimezone(UTC)


def _seconds(start: datetime, end: datetime) -> float:
    return (_instant(end) - _instant(start)).total_seconds()


@dataclass(frozen=True, slots=True)
class SyntheticAlertClock:
    """Caller-supplied timing assertion, NEVER a verified Bank alert timestamp."""

    tenant_id: str
    case_id: UUID
    source_event_id: UUID
    source_event_at: datetime
    alert_emitted_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.tenant_id) is not str
            or _TENANT.fullmatch(self.tenant_id) is None
            or type(self.case_id) is not UUID
            or type(self.source_event_id) is not UUID
        ):
            raise CaseMetricsRejected("typed tenant-bound alert identity required")
        if _instant(self.alert_emitted_at) < _instant(self.source_event_at):
            raise CaseMetricsRejected("alert cannot precede source event")


def _duration(
    samples: list[float], *, cohort: int, eligible: int,
    censored: int, missing_reason: str,
) -> dict[str, object]:
    """Expose the complete cohort, observed, missing, censored and excluded counts.

    All rates remain provisional synthetic measurements. Missing observations
    cannot silently improve a Bank-facing latency or turnaround denominator.
    """
    observed = len(samples)
    if eligible < observed or cohort < eligible + censored:
        raise CaseMetricsRejected("invalid duration coverage accounting")
    return {
        "count": observed,
        "denominator": cohort,
        "eligible_count": eligible,
        "missing_count": eligible - observed,
        "censored_count": censored,
        "excluded_count": cohort - eligible - censored,
        "coverage_rate": observed / cohort if cohort else None,
        "eligible_coverage_rate": observed / eligible if eligible else None,
        "mean_seconds": sum(samples) / observed if observed else None,
        "max_seconds": max(samples) if observed else None,
        "undefined_reason": None if observed else missing_reason,
    }


def summarize_synthetic_case_metrics(
    *,
    tenant_id: str,
    histories: tuple[tuple[CaseEvent, ...], ...],
    as_of: datetime,
    alert_clocks: tuple[SyntheticAlertClock, ...] = (),
) -> dict[str, object]:
    """Aggregate a complete, immutable *synthetic* tenant sample.

    Backlog = no disposition, or latest unresolved disposition not reconciled.
    Investigation turnaround = first assignment to first disposition.
    Alert latency = source event to alert emission, only when BOTH synthetic
    clocks exist. Corrections change final unresolved status, not first-turnaround.
    Unknown clocks/labels are excluded from denominators, not imputed as zero.
    """
    if type(tenant_id) is not str or _TENANT.fullmatch(tenant_id) is None:
        raise CaseMetricsRejected("canonical tenant identifier required")
    if type(histories) is not tuple or type(alert_clocks) is not tuple:
        raise CaseMetricsRejected("immutable histories and clocks required")
    current = _instant(as_of)
    by_case: dict[UUID, tuple[UUID, datetime]] = {}
    source_ids: set[UUID] = set()
    backlog_ages: list[float] = []
    turnarounds: list[float] = []
    backlog = disposed = unresolved = fraud = legitimate = reconciled = 0
    feedback_pending = 0

    # Validate the WHOLE snapshot before returning even an aggregate result.
    for history in histories:
        if type(history) is not tuple or not history or type(history[0]) is not CaseEvent:
            raise CaseMetricsRejected("nonempty typed case history required")
        first = history[0]
        validate_case_history(history, tenant_id=tenant_id, case_id=first.case_id)
        if first.case_id in by_case or first.source_event_id in source_ids:
            raise CaseMetricsRejected("duplicate case or source evaluation")
        if any(_instant(event.recorded_at) > current for event in history):
            raise CaseMetricsRejected("future-dated case history")
        by_case[first.case_id] = (first.source_event_id, _instant(first.recorded_at))
        source_ids.add(first.source_event_id)
        last_disposition = next(
            (event.disposition for event in reversed(history)
             if event.disposition is not None),
            None,
        )
        is_reconciled = history[-1].operation is CaseOperation.RECONCILE
        if is_reconciled:
            reconciled += 1
        if last_disposition is not None:
            disposed += 1
            if last_disposition is CaseDisposition.UNRESOLVED:
                unresolved += 1
            elif last_disposition is CaseDisposition.FRAUD:
                fraud += 1
            else:
                legitimate += 1
            if not is_reconciled:
                feedback_pending += 1
        if not is_reconciled and (
            last_disposition is None or last_disposition is CaseDisposition.UNRESOLVED
        ):
            backlog += 1
            backlog_ages.append(_seconds(first.recorded_at, current))
        assigned = next(
            (event for event in history if event.operation is CaseOperation.ASSIGN),
            None,
        )
        first_disposition = next(
            (event for event in history if event.operation is CaseOperation.DISPOSE),
            None,
        )
        if assigned is not None and first_disposition is not None:
            turnarounds.append(_seconds(assigned.recorded_at, first_disposition.recorded_at))

    observed_clocks: set[UUID] = set()
    latencies: list[float] = []
    for untrusted_clock in alert_clocks:
        if type(untrusted_clock) is not SyntheticAlertClock:
            raise CaseMetricsRejected("wrong-tenant or untyped alert clock")
        # Reconstruct each caller-supplied clock before using its times or
        # identifiers. A frozen/slotted record can be altered or damaged after
        # construction; a negative latency must never enter a KPI aggregate.
        try:
            clock = replace(untrusted_clock)
        except (AttributeError, TypeError, ValueError) as exc:
            raise CaseMetricsRejected("invalid synthetic alert clock") from exc
        if clock.tenant_id != tenant_id:
            raise CaseMetricsRejected("wrong-tenant or untyped alert clock")
        matching = by_case.get(clock.case_id)
        if (
            matching is None
            or matching[0] != clock.source_event_id
            or clock.case_id in observed_clocks
            or _instant(clock.alert_emitted_at) > matching[1]
            or _instant(clock.alert_emitted_at) > current
        ):
            raise CaseMetricsRejected("unknown, duplicate or impossible alert timing")
        observed_clocks.add(clock.case_id)
        latencies.append(_seconds(clock.source_event_at, clock.alert_emitted_at))

    total = len(histories)
    return {
        "source": "caller_supplied_synthetic_case_histories_only",
        "tenant_id": tenant_id,
        "as_of": current.isoformat(),
        "bank_data_verified": False,
        "bank_operational_kpi_authorized": False,
        "enforcement_activated": False,
        "counts": {
            "total_cases": total,
            "open_investigations": backlog,
            "dispositioned_cases": disposed,
            "confirmed_fraud": fraud,
            "confirmed_legitimate": legitimate,
            "unresolved": unresolved,
            "feedback_pending": feedback_pending,
            "reconciled": reconciled,
            "alert_timing_unknown": total - len(latencies),
        },
        "backlog_age": _duration(
            backlog_ages, cohort=total, eligible=backlog, censored=0,
            missing_reason="no_open_investigations",
        ),
        "investigation_turnaround": _duration(
            turnarounds, cohort=total, eligible=disposed,
            censored=total - disposed,
            missing_reason="no_completed_investigations",
        ),
        "alert_latency": _duration(
            latencies, cohort=total, eligible=total, censored=0,
            missing_reason="no_synthetic_alert_clocks",
        ),
        "unresolved_rate": {
            "count": unresolved,
            "denominator": disposed,
            "rate": unresolved / disposed if disposed else None,
            "undefined_reason": None if disposed else "no_dispositions",
        },
        "limitations": (
            "Clocks and histories are caller-supplied, not Bank-attested.",
            "Every duration reports the whole synthetic cohort and its missing coverage.",
            "Alert latency excludes cases without both synthetic alert clocks.",
            "Backlog and disposition definitions require Bank KPI agreement.",
            "No protected API, trusted history reader, Bank action or release authority.",
        ),
    }
