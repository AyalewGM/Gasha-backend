"""Matured-label training dataset builder.

Training rows are built from the same ``HistoricalTransactionEvent``
contract used by offline decision replay, with the same label-maturity
rules as the replay path: a label confirmed after ``label_cutoff``, a
label that was never confirmed, and an absent label are all excluded from
the training population rather than treated as legitimate. The cohort
digest binds the exact feature rows and labels that produced a model so a
manifest can always be traced back to its training population.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from uuid import UUID

from gasha.ml.features import ModelFeatureVector, build_feature_vector, feature_row
from gasha.poc.historical import HistoricalTransactionEvent

_DATASET_DIGEST_DOMAIN = "gasha-ml-training-cohort-v1"


class DatasetRejected(ValueError):
    """Malformed, inconsistent or unmatured training cohort input."""


@dataclass(frozen=True, slots=True)
class TrainingRow:
    """One matured, labeled, feature-bound training example."""

    event_id: UUID
    tenant_id: str
    occurred_at: datetime
    is_fraud: bool
    features: ModelFeatureVector


@dataclass(frozen=True, slots=True)
class TrainingDataset:
    """Time-ordered matured rows plus the exclusion counters that shaped them."""

    rows: tuple[TrainingRow, ...]
    label_cutoff: datetime
    matured_positive: int
    matured_negative: int
    excluded_future_labels: int
    excluded_unconfirmed_labels: int
    absent_labels: int
    cohort_digest: str


def _utc(name: str, value: datetime) -> datetime:
    if type(value) is not datetime or value.utcoffset() is None:
        raise DatasetRejected(f"{name} must be a timezone-aware datetime")
    return value.astimezone(UTC)


def build_training_dataset(
    events: Sequence[HistoricalTransactionEvent],
    *,
    label_cutoff: datetime,
    tenant_id: str | None = None,
) -> TrainingDataset:
    """Builds a time-ordered matured-label training population.

    Events are validated and labeled exactly like the matured-lineage
    replay path: duplicates and tenant mismatches fail closed, and
    future/unconfirmed/absent labels are counted and excluded. The
    returned rows are sorted by ``occurred_at`` so callers can split
    chronologically without leaking future labels into training.
    """
    if not isinstance(events, (list, tuple)):
        raise DatasetRejected("immutable event sequence required")
    cutoff = _utc("label_cutoff", label_cutoff)
    if tenant_id is not None and (type(tenant_id) is not str or not tenant_id):
        raise DatasetRejected("tenant_id must be a non-empty tag")

    rows: list[TrainingRow] = []
    digest_entries: list[dict[str, object]] = []
    counters = {
        "matured_positive": 0,
        "matured_negative": 0,
        "excluded_future_labels": 0,
        "excluded_unconfirmed_labels": 0,
        "absent_labels": 0,
    }
    seen: set[UUID] = set()
    for untrusted in events:
        if type(untrusted) is not HistoricalTransactionEvent:
            raise DatasetRejected("typed historical event required")
        event = untrusted
        transaction = event.transaction
        occurred = _utc("occurred_at", transaction.occurred_at)
        if transaction.event_id in seen:
            raise DatasetRejected("duplicate training event identity")
        if tenant_id is not None and transaction.tenant_id != tenant_id:
            raise DatasetRejected("cohort tenant mismatch")
        seen.add(transaction.event_id)

        label = event.label
        status = "absent_labels"
        matured: bool | None = None
        if label is not None:
            if label.confirmed_at is None:
                status = "excluded_unconfirmed_labels"
            elif _utc("label.confirmed_at", label.confirmed_at) > cutoff:
                status = "excluded_future_labels"
            else:
                status = "matured_positive" if label.is_fraud else "matured_negative"
                matured = label.is_fraud
        counters[status] += 1
        if matured is None:
            continue
        vector = build_feature_vector(transaction, event.intelligence)
        row = feature_row(vector)
        rows.append(
            TrainingRow(
                event_id=transaction.event_id,
                tenant_id=transaction.tenant_id,
                occurred_at=occurred,
                is_fraud=matured,
                features=vector,
            )
        )
        digest_entries.append(
            {
                "event_id": str(transaction.event_id),
                "tenant_id": transaction.tenant_id,
                "occurred_at": occurred.isoformat(timespec="microseconds"),
                "is_fraud": matured,
                "feature_row": list(row),
                "label_source": label.label_source if label is not None else "",
            }
        )

    rows.sort(key=lambda item: (item.occurred_at, str(item.event_id)))
    canonical = dumps(
        {
            "domain": _DATASET_DIGEST_DOMAIN,
            "label_cutoff": cutoff.isoformat(timespec="microseconds"),
            "tenant_id": tenant_id,
            "entries": sorted(digest_entries, key=lambda item: item["event_id"]),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = "sha256:" + sha256(canonical.encode("ascii")).hexdigest()
    return TrainingDataset(
        rows=tuple(rows),
        label_cutoff=cutoff,
        matured_positive=counters["matured_positive"],
        matured_negative=counters["matured_negative"],
        excluded_future_labels=counters["excluded_future_labels"],
        excluded_unconfirmed_labels=counters["excluded_unconfirmed_labels"],
        absent_labels=counters["absent_labels"],
        cohort_digest=digest,
    )
