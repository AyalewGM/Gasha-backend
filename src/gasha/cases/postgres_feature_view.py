"""Opt-in, unmounted #45 synthetic analyst feature-evidence projection.

A versioned, finite field set derived from durable case and evaluation records;
never from transport data, caller-supplied digests, or a ranking claim.
This adapter does NOT install an HTTP endpoint, security audit sink, browser
session, Bank source attestation, or any payment/enforcement capability.
An independently approved protected ingress must audit read/denial before
exposing these fields. Case scope means the *creation-source event only*:
other alerts grouped into that case are not represented by this projection.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from gasha.cases.evaluation_alerts import persisted_evaluation_context_matches
from gasha.cases.postgres_history_reader import authorized_case_read
from gasha.cases.postgres_timeline import PostgresCaseTimelineService
from gasha.cases.timeline import CaseRejected, CaseSourceUnavailable
from gasha.domain.models import DecisionAction, OperatingMode
from gasha.orchestration import ShadowEvaluationRecord
from gasha.postgres import Connection
from gasha.security.access import TrustedPrincipal

# Never echo an unconstrained persisted string as a browser-visible signal.
_SYNTHETIC_MISSING = frozenset({
    "beneficiary_ref",
    "device_ref",
    "sender_beneficiary_history_coverage",
    "beneficiary_unique_senders_1h",
})


@dataclass(frozen=True, slots=True)
class SyntheticCaseFeatureView:
    """No tenant, actor, customer, account, device or raw event identifiers."""

    schema: Literal["gasha-synthetic-case-feature-view-v1"]
    scope: Literal["case_creation_source_only"]
    availability: Literal["available", "not_recorded"]
    source_assurance: Literal["synthetic_unattested", "not_established"]
    context_ref: str
    assessment_version: str | None
    feature_set_version: str | None
    decision_as_of: str | None
    lineage_ref: str | None
    source_fingerprint: str | None
    computation_fingerprint: str | None
    eligible_observations: int | None
    late_observations: int | None
    nonprior_observations: int | None
    unavailable_signals: tuple[str, ...] | None


class ExplicitPostgresCaseFeatureReader:
    """Authorized read of an existing synthetic alert's immutable source.

    The caller supplies a separately verified principal, never a raw token.
    A fresh isolated connection and Bank-approved ingress audit/session remain
    installation obligations; this module is deliberately *not* API-wired.
    """

    def __init__(
        self, *, connections: Callable[[], AbstractContextManager[Connection]],
    ) -> None:
        self._connections = connections

    def read(
        self, *, principal: TrustedPrincipal, tenant_id: str,
        case_id: UUID, at: datetime,
    ) -> SyntheticCaseFeatureView:
        if type(case_id) is not UUID:
            raise CaseRejected("typed case ID required")
        accepted = authorized_case_read(
            principal=principal, tenant_id=tenant_id, at=at,
        )
        # No database access before tenant/capability/expiry checks.
        with self._connections() as connection:
            history = PostgresCaseTimelineService(connection).history(
                principal=accepted, tenant_id=tenant_id, case_id=case_id, at=at,
            )
            if not history:
                raise CaseSourceUnavailable("case source unavailable")
            creation = history[0]
            # Prove the case creation is also an actual persisted alert link.
            # A forged case-history reference or unrelated evaluation is not
            # a source of field-level analyst evidence.
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT 1 AS present FROM evaluation_alerts
                       WHERE tenant_id = %s AND case_id = %s
                         AND event_id = %s AND context_ref = %s""",
                    (
                        tenant_id, str(case_id),
                        str(creation.source_event_id), creation.source_context_ref,
                    ),
                )
                alert = cursor.fetchone()
            if alert is None:
                raise CaseSourceUnavailable("case source unavailable")
            # Verify the original serialized source, not a reserialized
            # Pydantic object: historical explicit-null contexts legitimately
            # differ from new canonical writes. Read exactly one durable row.
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT record_json FROM shadow_evaluations
                       WHERE tenant_id = %s AND event_id = %s""",
                    (tenant_id, str(creation.source_event_id)),
                )
                source = cursor.fetchone()
            if source is None:
                raise CaseSourceUnavailable("case source unavailable")
            raw_record_json = str(source["record_json"])
            try:
                record = ShadowEvaluationRecord.model_validate_json(raw_record_json)
            except (TypeError, ValueError) as exc:
                raise CaseSourceUnavailable("case source unavailable") from exc
            if (
                record.event.tenant_id != tenant_id
                or record.event.event_id != creation.source_event_id
                or record.event.canonical_transaction.tenant_id != tenant_id
                or record.event.canonical_transaction.event_id != creation.source_event_id
                or record.event.operating_mode is not OperatingMode.SHADOW
                or record.evaluation.operating_mode is not OperatingMode.SHADOW
                or record.evaluation.effective_action is not DecisionAction.NO_ACTION_SHADOW
                or not persisted_evaluation_context_matches(
                    record,
                    raw_record_json=raw_record_json,
                    stored_context_ref=creation.source_context_ref,
                )
            ):
                raise CaseSourceUnavailable("case source unavailable")
            evidence = record.feature_evidence
            if evidence is None:
                # Legacy/missing telemetry is not a measured zero or an
                # invented receipt cutoff/source fingerprint.
                return SyntheticCaseFeatureView(
                    "gasha-synthetic-case-feature-view-v1",
                    "case_creation_source_only", "not_recorded",
                    "not_established", creation.source_context_ref,
                    None, None, None, None, None, None, None, None, None, None,
                )
            evidence.assert_matches_event(record.event)
            if not set(evidence.unavailable_signals) <= _SYNTHETIC_MISSING:
                raise CaseSourceUnavailable("unrecognized synthetic signal")
            return SyntheticCaseFeatureView(
                "gasha-synthetic-case-feature-view-v1",
                "case_creation_source_only", "available",
                "synthetic_unattested", creation.source_context_ref,
                evidence.version, evidence.feature_set_version,
                evidence.decision_as_of.astimezone(UTC).isoformat(),
                evidence.lineage_ref, evidence.source_fingerprint,
                evidence.computation_fingerprint,
                evidence.eligible_observations, evidence.late_observations,
                evidence.nonprior_observations, evidence.unavailable_signals,
            )
