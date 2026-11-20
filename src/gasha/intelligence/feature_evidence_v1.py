"""Inactive #145/#48 synthetic receipt-time lineage carried in immutable evaluation JSON.

This is a reproducible content binding, NOT Bank source/time attestation. Do not
expose an unverified caller-supplied digest or use it to authorize enforcement.
"""
from __future__ import annotations

from datetime import UTC, datetime, timezone
from hashlib import sha256
from json import dumps
from re import fullmatch
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic_core import TzInfo

from gasha.domain.models import OperatingMode
from gasha.ingestion.contracts import FraudEventEnvelope
from gasha.ingestion.shadow_copy import SHADOW_COPY_SCHEMA
from gasha.intelligence.feature_assessment_v1 import (
    ASSESSMENT_VERSION,
    FeatureAssessmentV1,
)


def _digest(value: object) -> str:
    return sha256(dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def _instant(value: object) -> datetime:
    # Serialized Pydantic JSON dates restore with exact pydantic-core TzInfo.
    # Never execute an arbitrary in-process tzinfo/datetime subclass callback.
    if type(value) is not datetime or type(value.tzinfo) not in (timezone, TzInfo):
        raise ValueError("invalid synthetic lineage cutoff")
    return value.astimezone(UTC)


def _lineage_ref(payload: dict[str, object]) -> str:
    normalized = dict(payload)
    normalized["decision_as_of"] = _instant(payload["decision_as_of"]).isoformat()
    normalized["event_id"] = str(payload["event_id"])
    return _digest(["gasha-synthetic-feature-evidence-content-v1", normalized])


class SyntheticFeatureEvidenceV1(BaseModel):
    """Opaque source/decision binding; no raw observation or customer payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["gasha-synthetic-feature-assessment-v1"]
    tenant_id: str
    event_id: UUID
    decision_as_of: datetime
    source_fingerprint: str
    computation_fingerprint: str
    feature_set_version: str
    canonical_transaction_fingerprint: str
    assessed_event_fingerprint: str
    lineage_ref: str
    eligible_observations: int
    late_observations: int
    nonprior_observations: int
    unavailable_signals: tuple[str, ...]

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        self._require_valid()
        return self

    def _require_valid(self) -> None:
        if (
            self.version != ASSESSMENT_VERSION
            or type(self.tenant_id) is not str
            or not self.tenant_id
            or self.tenant_id != self.tenant_id.strip()
            or type(self.event_id) is not UUID
            or type(self.feature_set_version) is not str
            or not self.feature_set_version
            or len(self.feature_set_version) > 128
            or type(self.unavailable_signals) is not tuple
            or self.unavailable_signals != tuple(sorted(set(self.unavailable_signals)))
            or any(
                type(value) is not str
                or fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is None
                for value in self.unavailable_signals
            )
            or any(
                type(getattr(self, name)) is not int
                or getattr(self, name) < 0
                for name in (
                    "eligible_observations", "late_observations",
                    "nonprior_observations",
                )
            )
            or any(
                type(getattr(self, name)) is not str
                or fullmatch(r"[0-9a-f]{64}", getattr(self, name)) is None
                for name in (
                    "source_fingerprint", "computation_fingerprint",
                    "canonical_transaction_fingerprint",
                    "assessed_event_fingerprint", "lineage_ref",
                )
            )
        ):
            raise ValueError("invalid synthetic feature evidence")
        _instant(self.decision_as_of)
        if self.lineage_ref != _lineage_ref(
            self.model_dump(mode="python", exclude={"lineage_ref"})
        ):
            raise ValueError("synthetic feature evidence digest mismatch")

    @classmethod
    def from_assessment(cls, assessment: FeatureAssessmentV1) -> Self:
        if type(assessment) is not FeatureAssessmentV1:
            raise ValueError("trusted synthetic feature assessment required")
        event = assessment.assessed_envelope
        fields: dict[str, object] = {
            "version": ASSESSMENT_VERSION,
            "tenant_id": assessment.tenant_id,
            "event_id": assessment.event_id,
            "decision_as_of": assessment.decision_as_of,
            "source_fingerprint": assessment.source_fingerprint,
            "computation_fingerprint": assessment.computation_fingerprint,
            "feature_set_version": assessment.feature_set.version,
            "canonical_transaction_fingerprint": _digest([
                "gasha-synthetic-canonical-transaction-v1",
                event.canonical_transaction.model_dump(mode="json"),
            ]),
            "assessed_event_fingerprint": _digest([
                "gasha-synthetic-assessed-envelope-v1", event.model_dump(mode="json"),
            ]),
            "eligible_observations": assessment.eligible_observations,
            "late_observations": assessment.late_observations,
            "nonprior_observations": assessment.nonprior_observations,
            "unavailable_signals": assessment.unavailable_signals,
        }
        evidence = cls.model_validate({**fields, "lineage_ref": _lineage_ref(fields)})
        evidence.assert_matches_event(event)
        return evidence

    def assert_matches_event(self, event: FraudEventEnvelope) -> None:
        self._require_valid()
        if type(event) is not FraudEventEnvelope:
            raise ValueError("invalid synthetic evidence event")
        transaction = event.canonical_transaction
        received = event.received_at
        if (
            event.operating_mode is not OperatingMode.SHADOW
            or event.adapter.adapter_type != "synthetic-shadow-copy"
            or event.adapter.schema_version != SHADOW_COPY_SCHEMA
            or (self.tenant_id, self.event_id) != (event.tenant_id, event.event_id)
            or (transaction.tenant_id, transaction.event_id)
            != (event.tenant_id, event.event_id)
            or received is None
            or _instant(self.decision_as_of) != _instant(received)
            or self.canonical_transaction_fingerprint != _digest([
                "gasha-synthetic-canonical-transaction-v1",
                transaction.model_dump(mode="json"),
            ])
            or self.assessed_event_fingerprint != _digest([
                "gasha-synthetic-assessed-envelope-v1",
                event.model_dump(mode="json"),
            ])
        ):
            raise ValueError("synthetic feature evidence event/cutoff mismatch")
