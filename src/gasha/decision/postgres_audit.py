from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Protocol, Self
from uuid import UUID

from gasha.decision.audit import DecisionAuditRecord
from gasha.domain.models import FraudDecision
from gasha.intelligence.provenance import IntelligenceEvidence
from gasha.tenant_scope import require_tenant


class Cursor(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> None: ...
    def fetchone(self) -> Mapping[str, object] | None: ...
    def __enter__(self) -> Self: ...
    def __exit__(self, exc_type: object, exc: object, tb: object) -> None: ...


class Connection(Protocol):
    def cursor(self) -> Cursor: ...
    def commit(self) -> None: ...


class PostgresDecisionAuditRepository:
    """PostgreSQL adapter for tenant/event idempotent decision audit records."""

    def __init__(
        self, connection: Connection, *, tenant_ids: tuple[str, ...] | None = None
    ) -> None:
        self._tenant_ids = tenant_ids
        self.connection = connection

    def get(self, tenant_id: str, event_id: UUID) -> DecisionAuditRecord | None:
        require_tenant(tenant_id, self._tenant_ids)
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_json, signal_policy_versions_json, evidence_json
                FROM fraud_decision_audit
                WHERE tenant_id = %s AND event_id = %s
                """,
                (tenant_id, str(event_id)),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return self._decode(row)

    def save(self, record: DecisionAuditRecord) -> DecisionAuditRecord:
        decision = record.decision
        require_tenant(decision.tenant_id, self._tenant_ids)
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO fraud_decision_audit (
                    tenant_id, event_id, decision_json,
                    signal_policy_versions_json, evidence_json, decided_at
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, event_id) DO NOTHING
                """,
                (
                    decision.tenant_id,
                    str(decision.event_id),
                    decision.model_dump_json(),
                    json.dumps(record.signal_policy_versions),
                    json.dumps([item.model_dump(mode="json") for item in record.evidence]),
                    decision.decided_at,
                ),
            )
        self.connection.commit()

        persisted = self.get(decision.tenant_id, decision.event_id)
        if persisted is None:
            raise RuntimeError("decision audit insert completed without a persisted record")
        return persisted

    @staticmethod
    def _decode(row: Mapping[str, object]) -> DecisionAuditRecord:
        decision_raw = row["decision_json"]
        versions_raw = row["signal_policy_versions_json"]
        evidence_raw = row["evidence_json"]
        if not isinstance(decision_raw, str):
            raise TypeError("decision_json must be returned as text")
        if not isinstance(versions_raw, str):
            raise TypeError("signal_policy_versions_json must be returned as text")
        if not isinstance(evidence_raw, str):
            raise TypeError("evidence_json must be returned as text")

        versions = json.loads(versions_raw)
        evidence_items = json.loads(evidence_raw)
        if not isinstance(versions, list) or not isinstance(evidence_items, list):
            raise TypeError("invalid decision audit JSON payload")

        return DecisionAuditRecord(
            decision=FraudDecision.model_validate_json(decision_raw),
            signal_policy_versions=tuple(str(item) for item in versions),
            evidence=tuple(
                IntelligenceEvidence.model_validate(item) for item in evidence_items
            ),
        )

