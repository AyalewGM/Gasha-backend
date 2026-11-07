"""Standalone #49 evidence proposal ledger clock preflight regressions.

All actors, bindings and clocks here are synthetic. No Bank registry, identity,
deployment or enforcement authority is installed by this test.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import ClassVar
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.evidence_identity import EvidenceBinding, EvidencePacket, EvidenceRecord
from gasha.poc.evidence_lifecycle import EvidenceAction
from gasha.poc.postgres_evidence_proposals import (
    EvidenceLedgerRejected,
    PostgresEvidenceProposalLedger,
)
from gasha.poc.readiness import EvidenceArea, Stage
from gasha.security.access import Capability, TrustedPrincipal

NOW = datetime(2026, 11, 1, 1, tzinfo=UTC)
CAPABILITIES = {
    EvidenceAction.SUBMIT: Capability.EVIDENCE_SUBMIT,
    EvidenceAction.VERIFY: Capability.EVIDENCE_VERIFY,
    EvidenceAction.APPROVE: Capability.STAGE_APPROVE,
    EvidenceAction.REVOKE_EVIDENCE: Capability.EVIDENCE_REVOKE,
    EvidenceAction.REVOKE_APPROVAL: Capability.APPROVAL_REVOKE,
}


class DatabaseReached(Exception):
    """The valid clock passed all pre-DB guards."""


class ConnectionGuard:
    autocommit = False

    def __init__(self) -> None:
        self.cursor_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    def cursor(self) -> None:
        self.cursor_calls += 1
        raise DatabaseReached()

    def commit(self) -> None:
        self.commit_calls += 1

    def rollback(self) -> None:
        self.rollback_calls += 1


class ArtifactReader:
    def __init__(self) -> None:
        self.calls = 0

    def sha256_digest(self, record: EvidenceRecord) -> str:
        self.calls += 1
        return record.artifact_digest


class ForgedClassClock:
    def __init__(self, callbacks: list[str]) -> None:
        self.callbacks = callbacks

    @property
    def __class__(self) -> type[datetime]:
        self.callbacks.append("class")
        return datetime

    def utcoffset(self) -> timedelta:
        self.callbacks.append("offset")
        return timedelta(0)


class HostileZone(tzinfo):
    def __init__(self, callbacks: list[str]) -> None:
        self.callbacks = callbacks

    def utcoffset(self, dt: datetime | None) -> timedelta:
        self.callbacks.append("offset")
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta:
        self.callbacks.append("dst")
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str:
        self.callbacks.append("name")
        return "hostile"


class HostileDatetime(datetime):
    callbacks: ClassVar[list[str]] = []

    def utcoffset(self) -> timedelta:
        self.callbacks.append("offset")
        return timedelta(0)


def packet() -> EvidencePacket:
    binding = EvidenceBinding(
        tenant_id="bank-a", installation_id="synthetic-installation",
        stage=Stage.SHADOW, use_case="uc-01", commit_sha="a" * 40,
        image_digest="sha256:" + "b" * 64,
        dataset_digest="sha256:" + "c" * 64,
        config_version="cfg-1", policy_version="policy-1", rule_version="rule-1",
        signal_version="signal-1", adapter_version="adapter-1",
        window_start=NOW - timedelta(hours=2),
        window_end=NOW - timedelta(hours=1),
    )
    record = EvidenceRecord(
        evidence_id=UUID(int=1), binding=binding, area=EvidenceArea.SECURITY,
        artifact_ref="synthetic-artifact",
        artifact_digest="sha256:" + "d" * 64,
        source_system="synthetic-ci",
        collector_actor_ref="a" * 64,
        collected_at=NOW - timedelta(minutes=30),
        expires_at=NOW + timedelta(days=1),
    )
    return EvidencePacket(binding, "evaluator-1", (record,))


def principal(action: EvidenceAction) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject="synthetic-actor", issuer="synthetic-issuer",
        credential_ref="synthetic-credential", tenant_ids=frozenset({"bank-a"}),
        capabilities=frozenset({CAPABILITIES[action]}),
        expires_at=NOW + timedelta(days=2),
    )


def hostile_clock(variant: str, callbacks: list[str]) -> object:
    if variant == "forged_class":
        return ForgedClassClock(callbacks)
    if variant == "datetime_subclass":
        HostileDatetime.callbacks = callbacks
        return HostileDatetime(2026, 11, 1, 1, tzinfo=UTC)
    if variant == "custom_tz":
        return datetime(2026, 11, 1, 1, tzinfo=HostileZone(callbacks))
    raise AssertionError("unknown clock variant")


def ledger(connection: ConnectionGuard) -> PostgresEvidenceProposalLedger:
    return PostgresEvidenceProposalLedger(
        connection, installation_schema="synthetic_installation",
        tenant_id="bank-a", installation_id="synthetic-installation",
    )


@pytest.mark.parametrize("action", tuple(EvidenceAction))
@pytest.mark.parametrize("variant", ("forged_class", "datetime_subclass", "custom_tz"))
def test_all_actions_reject_untrusted_now_before_callbacks_or_db(
    action: EvidenceAction, variant: str,
) -> None:
    callbacks: list[str] = []
    connection = ConnectionGuard()
    reader = ArtifactReader()
    with pytest.raises(EvidenceLedgerRejected, match="trusted timezone-aware clock"):
        ledger(connection).apply(
            packet(), principal=principal(action), action=action,
            now=hostile_clock(variant, callbacks), expected_revision=0,
            artifact_reader=reader,
        )
    assert callbacks == []
    assert reader.calls == 0
    assert (connection.cursor_calls, connection.commit_calls, connection.rollback_calls) == (
        0, 0, 0,
    )


@pytest.mark.parametrize("action", tuple(EvidenceAction))
@pytest.mark.parametrize("variant", ("forged_class", "datetime_subclass", "custom_tz"))
def test_all_actions_reject_mutated_principal_expiry_before_callbacks_or_db(
    action: EvidenceAction, variant: str,
) -> None:
    callbacks: list[str] = []
    connection = ConnectionGuard()
    reader = ArtifactReader()
    actor = principal(action)
    object.__setattr__(actor, "expires_at", hostile_clock(variant, callbacks))
    with pytest.raises(EvidenceLedgerRejected, match="invalid credential expiry"):
        ledger(connection).apply(
            packet(), principal=actor, action=action, now=NOW,
            expected_revision=0, artifact_reader=reader,
        )
    assert callbacks == []
    assert reader.calls == 0
    assert (connection.cursor_calls, connection.commit_calls, connection.rollback_calls) == (
        0, 0, 0,
    )


@pytest.mark.parametrize("action", tuple(EvidenceAction))
@pytest.mark.parametrize("valid_clock", (
    NOW,
    datetime(2026, 11, 1, 3, tzinfo=timezone(timedelta(hours=2))),
    datetime(2026, 11, 1, 1, 30, fold=0, tzinfo=ZoneInfo("America/New_York")),
    datetime(2026, 11, 1, 1, 30, fold=1, tzinfo=ZoneInfo("America/New_York")),
))
def test_approved_utc_fixed_offset_and_dst_fold_clocks_pass_preflight(
    action: EvidenceAction, valid_clock: datetime,
) -> None:
    connection = ConnectionGuard()
    reader = ArtifactReader()
    # A valid clock proceeds to the intentionally blocked DB boundary,
    # not to an actual PostgreSQL write or readiness decision.
    with pytest.raises(DatabaseReached):
        ledger(connection).apply(
            packet(), principal=principal(action), action=action,
            now=valid_clock, expected_revision=0, artifact_reader=reader,
        )
    assert connection.cursor_calls == 1
    assert connection.commit_calls == 0
    assert connection.rollback_calls == 1
    assert reader.calls == 0
