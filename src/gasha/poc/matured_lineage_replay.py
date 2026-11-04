"""Opt-in synthetic #41/#48 historical replay with point-in-time preflight.

This does not authenticate bank data, create a trusted cohort, or authorize a
bank replay. In particular, the legacy replay_historical() remains unchanged.
Only events whose *caller-asserted* lineage is complete and in scope can reach
the production decision algorithm via this deliberately separate offline entry.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from uuid import UUID

from gasha.domain.models import DecisionPolicy
from gasha.poc.historical import (
    HistoricalReplayReport,
    HistoricalTransactionEvent,
    replay_historical,
)
from gasha.poc.temporal_lineage import (
    HistoricalFeatureEnvelope,
    HistoricalLineageRejected,
    assert_historical_snapshot_bound,
)

_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPORT_VERSION = "synthetic-matured-lineage-replay-v1"


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise HistoricalLineageRejected("timezone-aware cohort clock required")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class OfflineCohortScope:
    tenant_id: str
    dataset_digest: str
    cohort_version: str
    mapping_version: str
    configuration_version: str
    policy_version: str
    rule_version: str
    signal_policy_version: str
    window_start: datetime
    window_end: datetime
    label_cutoff: datetime

    def __post_init__(self) -> None:
        for name in (
            "tenant_id", "cohort_version", "mapping_version",
            "configuration_version", "policy_version", "rule_version",
            "signal_policy_version",
        ):
            value = getattr(self, name)
            if type(value) is not str or _TAG.fullmatch(value) is None:
                raise HistoricalLineageRejected("invalid offline cohort version or scope")
        if type(self.dataset_digest) is not str or _DIGEST.fullmatch(self.dataset_digest) is None:
            raise HistoricalLineageRejected("invalid offline dataset digest")
        start, end, cutoff = (
            _utc(self.window_start), _utc(self.window_end), _utc(self.label_cutoff),
        )
        if not start <= end <= cutoff:
            raise HistoricalLineageRejected("invalid cohort/label cutoff order")
        object.__setattr__(self, "window_start", start)
        object.__setattr__(self, "window_end", end)
        object.__setattr__(self, "label_cutoff", cutoff)


def _rate(numerator: int, denominator: int, missing_reason: str) -> dict[str, object]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
        "undefined_reason": None if denominator else missing_reason,
    }


@dataclass(frozen=True, slots=True)
class OfflineLineageReplayResult:
    """Raw replay is for local tests only; to_dict exports aggregates only."""

    scope: OfflineCohortScope
    cohort_digest: str
    replay: HistoricalReplayReport
    matured_positive: int
    matured_negative: int
    excluded_future_labels: int
    excluded_unconfirmed_labels: int
    absent_labels: int

    def to_dict(self) -> dict[str, object]:
        metrics = self.replay.metrics
        return {
            "report_version": REPORT_VERSION,
            "source": "synthetic_caller_asserted",
            "scope": {
                "tenant_id": self.scope.tenant_id,
                "dataset_digest": self.scope.dataset_digest,
                "cohort_version": self.scope.cohort_version,
                "mapping_version": self.scope.mapping_version,
                "configuration_version": self.scope.configuration_version,
                "policy_version": self.scope.policy_version,
                "rule_version": self.scope.rule_version,
                "signal_policy_version": self.scope.signal_policy_version,
                "window_start": self.scope.window_start.isoformat(),
                "window_end": self.scope.window_end.isoformat(),
                "label_cutoff": self.scope.label_cutoff.isoformat(),
            },
            "cohort_digest": self.cohort_digest,
            "cases": metrics.cases,
            "maturity": {
                "matured_positive": self.matured_positive,
                "matured_negative": self.matured_negative,
                "excluded_future_labels": self.excluded_future_labels,
                "excluded_unconfirmed_labels": self.excluded_unconfirmed_labels,
                "absent_labels": self.absent_labels,
            },
            "confusion_counts": {
                "true_positive": metrics.true_positives,
                "false_positive": metrics.false_positives,
                "true_negative": metrics.true_negatives,
                "false_negative": metrics.false_negatives,
                "unlabeled": metrics.unlabeled_cases,
            },
            "precision": _rate(
                metrics.true_positives,
                metrics.true_positives + metrics.false_positives, "no_alerted_labeled_cases",
            ),
            "recall": _rate(
                metrics.true_positives,
                metrics.true_positives + metrics.false_negatives, "no_labeled_positives",
            ),
            "false_positive_rate": _rate(
                metrics.false_positives,
                metrics.false_positives + metrics.true_negatives, "no_labeled_negatives",
            ),
            "bank_data_verified": False,
            "bank_kpi_approved": False,
            "readiness_authorized": False,
            "enforcement_activated": False,
            "limitations": [
                "Lineage, labels, dataset and cohort identifiers remain caller assertions.",
                "Absent and non-mature labels do not enter confusion-matrix denominators.",
                "No incumbent comparison, bank-approved alert budget, IdP or trusted evidence registry.",
                "Synthetic replay decisions are not bank payment interventions.",
            ],
        }


def replay_offline_matured_lineage(
    scope: OfflineCohortScope,
    events: tuple[HistoricalTransactionEvent, ...],
    lineages: tuple[HistoricalFeatureEnvelope, ...],
    policy: DecisionPolicy,
    *,
    clock: Callable[[], datetime] | None = None,
) -> OfflineLineageReplayResult:
    """Preflight the *entire* single-tenant cohort before any decision is made.

    An event without explicit complete, point-in-time signal lineage fails closed.
    A future/unconfirmed label is masked to unknown rather than counted as a
    historical positive or negative. Raw IDs stay in memory, never in to_dict.
    """
    if type(scope) is not OfflineCohortScope:
        raise HistoricalLineageRejected("typed offline cohort scope required")
    try:
        scope = OfflineCohortScope(**{
            key: getattr(scope, key) for key in OfflineCohortScope.__dataclass_fields__
        })
    except AttributeError:
        raise HistoricalLineageRejected("missing offline cohort scope field") from None
    if type(events) is not tuple or type(lineages) is not tuple:
        raise HistoricalLineageRejected("immutable event and lineage tuples required")
    if not isinstance(policy, DecisionPolicy) or (
        policy.configuration_version != scope.configuration_version
        or policy.policy_version != scope.policy_version
        or policy.rule_version != scope.rule_version
    ):
        raise HistoricalLineageRejected("cohort policy/config/rule version mismatch")

    lineage_by_event: dict[UUID, HistoricalFeatureEnvelope] = {}
    for lineage in lineages:
        if type(lineage) is not HistoricalFeatureEnvelope:
            raise HistoricalLineageRejected("typed historical lineage required")
        try:
            event_id = lineage.event_id
        except AttributeError:
            raise HistoricalLineageRejected("missing lineage event identity") from None
        if event_id in lineage_by_event:
            raise HistoricalLineageRejected("duplicate lineage event identity")
        lineage_by_event[event_id] = lineage

    seen: set[UUID] = set()
    masked: list[HistoricalTransactionEvent] = []
    digest_entries: list[dict[str, str]] = []
    maturity = {
        "matured_positive": 0, "matured_negative": 0,
        "excluded_future_labels": 0, "excluded_unconfirmed_labels": 0,
        "absent_labels": 0,
    }
    for untrusted in events:
        if type(untrusted) is not HistoricalTransactionEvent:
            raise HistoricalLineageRejected("typed historical event required")
        try:
            event = HistoricalTransactionEvent.model_validate(untrusted.model_dump())
        except (ValueError, TypeError, AttributeError) as exc:
            raise HistoricalLineageRejected("invalid historical event") from exc
        transaction = event.transaction
        if (
            transaction.tenant_id != scope.tenant_id
            or not scope.window_start <= _utc(transaction.occurred_at) <= scope.window_end
            or transaction.event_id in seen
        ):
            raise HistoricalLineageRejected("cohort tenant/window/duplicate event mismatch")
        seen.add(transaction.event_id)
        lineage = lineage_by_event.get(transaction.event_id)
        if lineage is None:
            raise HistoricalLineageRejected("missing complete event lineage")
        if (
            lineage.cohort_version != scope.cohort_version
            or lineage.mapping_version != scope.mapping_version
            or lineage.configuration_version != scope.configuration_version
            or lineage.policy_version != scope.policy_version
            or lineage.signal_policy_version != scope.signal_policy_version
            or event.signal_policy_versions != (scope.signal_policy_version,)
        ):
            raise HistoricalLineageRejected("historical cohort or policy lineage mismatch")
        if (
            event.received_at is None
            or _utc(event.received_at) > _utc(lineage.decision_cutoff)
            or _utc(lineage.decision_cutoff) > scope.label_cutoff
        ):
            raise HistoricalLineageRejected("missing or invalid historical receipt/cutoff")
        assert_historical_snapshot_bound(
            lineage, transaction=transaction, snapshot=event.intelligence,
            expected_tenant=scope.tenant_id, expected_dataset_digest=scope.dataset_digest,
        )

        label = event.label
        label_status = "absent_labels"
        if label is not None:
            if label.confirmed_at is None:
                label_status = "excluded_unconfirmed_labels"
            elif _utc(label.confirmed_at) > scope.label_cutoff:
                label_status = "excluded_future_labels"
            else:
                label_status = "matured_positive" if label.is_fraud else "matured_negative"
        maturity[label_status] += 1
        if label_status not in ("matured_positive", "matured_negative"):
            event = event.model_copy(update={"label": None})
        masked.append(event)
        digest_entries.append({
            "event_id": str(transaction.event_id),
            "lineage_digest": lineage.fingerprint(),
            "label_status": label_status,
            "matured_label": str(label.is_fraud) if label_status.startswith("matured_") else "",
        })
    if set(lineage_by_event) != seen:
        raise HistoricalLineageRejected("orphan lineage outside cohort")

    canonical = dumps(
        {
            "domain": REPORT_VERSION,
            "tenant": scope.tenant_id, "dataset": scope.dataset_digest,
            "cohort": scope.cohort_version,
            "entries": sorted(digest_entries, key=lambda item: item["event_id"]),
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    digest = "sha256:" + sha256(canonical.encode("ascii")).hexdigest()
    result = replay_historical(tuple(masked), {scope.tenant_id: policy}, clock=clock)
    return OfflineLineageReplayResult(
        scope=scope, cohort_digest=digest, replay=result,
        matured_positive=maturity["matured_positive"],
        matured_negative=maturity["matured_negative"],
        excluded_future_labels=maturity["excluded_future_labels"],
        excluded_unconfirmed_labels=maturity["excluded_unconfirmed_labels"],
        absent_labels=maturity["absent_labels"],
    )
