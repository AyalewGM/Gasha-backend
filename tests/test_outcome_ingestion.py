from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from gasha.api.main import app
from gasha.ingestion.outcome_ingestion import (
    IncumbentOutcomeRecord,
    OutcomeIngestionService,
    SubmissionStatus,
)
from gasha.poc.outcomes import (
    IncumbentControlOutcome,
    OutcomeRecord,
    OutcomeType,
)

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


def record(
    tenant_id: str = "tenant-a",
    outcome: OutcomeType = OutcomeType.UNRESOLVED,
    **kwargs,
) -> OutcomeRecord:
    return OutcomeRecord(
        tenant_id=tenant_id,
        event_id=kwargs.pop("event_id", uuid4()),
        outcome=outcome,
        outcome_source=kwargs.pop("outcome_source", "case-review"),
        outcome_version=kwargs.pop("outcome_version", "outcomes-1"),
        confirmed_at=kwargs.pop("confirmed_at", T0),
        **kwargs,
    )


def test_submit_accepts_and_deduplicates() -> None:
    service = OutcomeIngestionService()
    outcome = record()

    first = service.submit(outcome)
    second = service.submit(outcome)

    assert first.status == SubmissionStatus.ACCEPTED
    assert second.status == SubmissionStatus.DUPLICATE
    assert len(second.history) == 1


def test_outcome_transition_preserves_history() -> None:
    service = OutcomeIngestionService()
    event_id = uuid4()

    service.submit(record(event_id=event_id, outcome=OutcomeType.UNRESOLVED))
    service.submit(
        record(
            event_id=event_id,
            outcome=OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD,
            confirmed_at=T0 + timedelta(days=4),
        )
    )

    history = service.store.outcomes("tenant-a", event_id)
    assert [o.outcome for o in history] == [
        OutcomeType.UNRESOLVED,
        OutcomeType.INVESTIGATOR_CONFIRMED_FRAUD,
    ]
    assert history[-1].is_fraud is True


def test_outcomes_are_tenant_scoped() -> None:
    service = OutcomeIngestionService()
    event_id = uuid4()
    service.submit(
        record(
            tenant_id="tenant-a",
            event_id=event_id,
            outcome=OutcomeType.CONFIRMED_FRAUD,
        )
    )

    # Same event_id under another tenant sees nothing of tenant-a's.
    assert service.store.outcomes("tenant-b", event_id) == ()
    assert service.store.outcomes("tenant-a", event_id) != ()


def test_incumbent_outcome_ingestion() -> None:
    service = OutcomeIngestionService()
    outcome = IncumbentOutcomeRecord(
        tenant_id="tenant-a",
        event_id=uuid4(),
        outcome=IncumbentControlOutcome.ALERT,
        source_system="synthetic-existing-controls",
    )

    first = service.submit_incumbent(outcome)
    second = service.submit_incumbent(outcome)

    assert first.status == SubmissionStatus.ACCEPTED
    assert second.status == SubmissionStatus.DUPLICATE
    assert len(second.incumbent_history) == 1


def test_incumbent_outcomes_are_tenant_scoped() -> None:
    service = OutcomeIngestionService()
    event_id = uuid4()
    service.submit_incumbent(
        IncumbentOutcomeRecord(
            tenant_id="tenant-a",
            event_id=event_id,
            outcome=IncumbentControlOutcome.HOLD,
            source_system="synthetic-existing-controls",
        )
    )
    assert service.store.incumbent_outcomes("tenant-b", event_id) == ()


def test_outcome_api_roundtrip() -> None:
    app.state.outcome_ingestion = OutcomeIngestionService()
    client = TestClient(app)
    event_id = str(uuid4())

    response = client.post(
        "/v1/outcomes",
        json={
            "tenant_id": "tenant-a",
            "event_id": event_id,
            "outcome": "customer_reported_scam",
            "outcome_source": "customer-dispute-channel",
            "outcome_version": "outcomes-1",
            "confirmed_at": T0.isoformat(),
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"

    duplicate = client.post(
        "/v1/outcomes",
        json={
            "tenant_id": "tenant-a",
            "event_id": event_id,
            "outcome": "customer_reported_scam",
            "outcome_source": "customer-dispute-channel",
            "outcome_version": "outcomes-1",
            "confirmed_at": T0.isoformat(),
        },
    )
    assert duplicate.json()["status"] == "duplicate"


def test_incumbent_api_roundtrip() -> None:
    app.state.outcome_ingestion = OutcomeIngestionService()
    client = TestClient(app)

    response = client.post(
        "/v1/incumbent-outcomes",
        json={
            "tenant_id": "tenant-a",
            "event_id": str(uuid4()),
            "outcome": "review",
            "source_system": "synthetic-existing-controls",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert len(body["incumbent_history"]) == 1


def test_outcome_api_validates_payload() -> None:
    app.state.outcome_ingestion = OutcomeIngestionService()
    client = TestClient(app)
    response = client.post(
        "/v1/outcomes",
        json={
            "tenant_id": "tenant-a",
            "event_id": "not-a-uuid",
            "outcome": "confirmed_fraud",
            "outcome_source": "case-review",
            "outcome_version": "outcomes-1",
        },
    )
    assert response.status_code == 422
