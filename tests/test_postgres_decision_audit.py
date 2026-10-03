from datetime import UTC, datetime
from uuid import uuid4

from gasha.decision.audit import DecisionAuditRecord
from gasha.decision.postgres_audit import PostgresDecisionAuditRepository
from gasha.domain.models import DecisionAction, FraudDecision
from gasha.intelligence.provenance import (
    IntelligenceEvidence,
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)


class FakeCursor:
    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection
        self.row: dict[str, object] | None = None

    def execute(self, query: str, params: tuple[object, ...]) -> None:
        normalized = " ".join(query.split())
        if normalized.startswith("INSERT INTO fraud_decision_audit"):
            tenant_id, event_id, decision_json, versions_json, evidence_json, _ = params
            key = (str(tenant_id), str(event_id))
            self.connection.rows.setdefault(
                key,
                {
                    "decision_json": decision_json,
                    "signal_policy_versions_json": versions_json,
                    "evidence_json": evidence_json,
                },
            )
        elif normalized.startswith("SELECT decision_json"):
            tenant_id, event_id = params
            self.row = self.connection.rows.get((str(tenant_id), str(event_id)))
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self) -> dict[str, object] | None:
        return self.row

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.commits = 0

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.commits += 1


def record(tenant_id: str = "tenant-a", event_id=None) -> DecisionAuditRecord:
    event_id = event_id or uuid4()
    now = datetime.now(UTC)
    decision = FraudDecision(
        tenant_id=tenant_id,
        event_id=event_id,
        action=DecisionAction.REVIEW,
        risk_score=0.77,
        reason_codes=["NEW_BENEFICIARY_HIGH_VALUE"],
        configuration_version="config-3",
        policy_version="policy-5",
        rule_version="rules-7",
        model_version="model-2",
        decided_at=now,
        correlation_id="corr-postgres",
    )
    evidence = IntelligenceEvidence(
        reason_code="NEW_BENEFICIARY_HIGH_VALUE",
        provenance=SignalProvenance(
            source=IntelligenceSource.TENANT_RELATIONSHIP,
            scope=IntelligenceScope.TENANT_OBSERVED,
            observed_at=now,
            source_version="relationship-features-2",
            confidence=0.91,
        ),
    )
    return DecisionAuditRecord(
        decision=decision,
        signal_policy_versions=("relationship-policy-2",),
        evidence=(evidence,),
    )


def test_save_round_trips_versions_and_evidence() -> None:
    connection = FakeConnection()
    repository = PostgresDecisionAuditRepository(connection)
    expected = record()

    persisted = repository.save(expected)

    assert persisted == expected
    assert connection.commits == 1


def test_duplicate_tenant_event_preserves_first_decision() -> None:
    connection = FakeConnection()
    repository = PostgresDecisionAuditRepository(connection)
    first = record()
    duplicate = record(first.decision.tenant_id, first.decision.event_id)
    duplicate = DecisionAuditRecord(
        decision=duplicate.decision.model_copy(
            update={"action": DecisionAction.ALLOW, "risk_score": 0.0}
        ),
        signal_policy_versions=("different-policy",),
    )

    repository.save(first)
    persisted = repository.save(duplicate)

    assert persisted == first


def test_same_event_id_remains_tenant_isolated() -> None:
    connection = FakeConnection()
    repository = PostgresDecisionAuditRepository(connection)
    event_id = uuid4()
    tenant_a = record("tenant-a", event_id)
    tenant_b = record("tenant-b", event_id)

    repository.save(tenant_a)
    repository.save(tenant_b)

    assert repository.get("tenant-a", event_id) == tenant_a
    assert repository.get("tenant-b", event_id) == tenant_b
