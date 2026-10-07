from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, Field

from gasha.poc.outcomes import IncumbentControlOutcome, OutcomeRecord


class SubmissionStatus(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"


class IncumbentOutcomeRecord(BaseModel):
    """What the bank's existing control stack did on an event.

    Vendor-neutral by contract: adapter-layer integrations map
    provider-specific outcomes into ``IncumbentControlOutcome``; the core
    never names an incumbent vendor.
    """

    tenant_id: str = Field(min_length=1)
    event_id: UUID
    outcome: IncumbentControlOutcome
    source_system: str = Field(min_length=1)
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )


class OutcomeSubmission(BaseModel):
    status: SubmissionStatus
    history: tuple[OutcomeRecord, ...] = ()
    incumbent_history: tuple[IncumbentOutcomeRecord, ...] = ()


class OutcomeStore(Protocol):
    """Append-only, tenant-scoped outcome history.

    Outcomes arrive after the original decision; appending preserves the
    full transition (e.g. UNRESOLVED -> CONFIRMED_FRAUD) and never mutates
    the stored T0 decision.
    """

    def outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[OutcomeRecord, ...]: ...

    def incumbent_outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[IncumbentOutcomeRecord, ...]: ...

    def append(self, record: OutcomeRecord) -> None: ...

    def append_incumbent(self, record: IncumbentOutcomeRecord) -> None: ...


class InMemoryOutcomeStore:
    """Reference store; production storage implements the same contract."""

    def __init__(self) -> None:
        self._outcomes: dict[tuple[str, UUID], list[OutcomeRecord]] = {}
        self._incumbent: dict[
            tuple[str, UUID], list[IncumbentOutcomeRecord]
        ] = {}

    def outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[OutcomeRecord, ...]:
        return tuple(self._outcomes.get((tenant_id, event_id), ()))

    def incumbent_outcomes(
        self, tenant_id: str, event_id: UUID
    ) -> tuple[IncumbentOutcomeRecord, ...]:
        return tuple(self._incumbent.get((tenant_id, event_id), ()))

    def append(self, record: OutcomeRecord) -> None:
        self._outcomes.setdefault(
            (record.tenant_id, record.event_id), []
        ).append(record)

    def append_incumbent(self, record: IncumbentOutcomeRecord) -> None:
        self._incumbent.setdefault(
            (record.tenant_id, record.event_id), []
        ).append(record)


class OutcomeIngestionService:
    """Tenant-safe, idempotent outcome and incumbent-control ingestion.

    An identical resubmission is a no-op duplicate; a changed outcome is a
    new entry in the append-only history so transitions remain auditable.
    """

    def __init__(self, store: OutcomeStore | None = None) -> None:
        self._store = store or InMemoryOutcomeStore()

    @property
    def store(self) -> OutcomeStore:
        return self._store

    def submit(self, record: OutcomeRecord) -> OutcomeSubmission:
        history = list(
            self._store.outcomes(record.tenant_id, record.event_id)
        )
        if record in history:
            return OutcomeSubmission(
                status=SubmissionStatus.DUPLICATE, history=tuple(history)
            )
        self._store.append(record)
        history.append(record)
        return OutcomeSubmission(
            status=SubmissionStatus.ACCEPTED, history=tuple(history)
        )

    def submit_incumbent(
        self, record: IncumbentOutcomeRecord
    ) -> OutcomeSubmission:
        history = list(
            self._store.incumbent_outcomes(
                record.tenant_id, record.event_id
            )
        )
        if record in history:
            return OutcomeSubmission(
                status=SubmissionStatus.DUPLICATE,
                incumbent_history=tuple(history),
            )
        self._store.append_incumbent(record)
        history.append(record)
        return OutcomeSubmission(
            status=SubmissionStatus.ACCEPTED,
            incumbent_history=tuple(history),
        )
