"""#49 bounded offline proposal-kernel regression tests, not bank evidence."""
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.evidence_identity import EvidenceBinding, EvidencePacket, EvidenceRecord
from gasha.poc.evidence_lifecycle import (
    EvidenceAction,
    EvidenceLifecycle,
    EvidenceTransition,
    LifecycleRejected,
    propose_transition,
)
from gasha.poc.readiness import EvidenceArea, Stage
from gasha.security.access import Capability, TrustedPrincipal

NOW = datetime(2026, 10, 31, 20, tzinfo=UTC)


def actor(subject: str, *caps: Capability, tenant: str = "bank-a", expiry: datetime | None = None
          ) -> TrustedPrincipal:
    return TrustedPrincipal(
        subject=subject, issuer="synthetic-test-issuer", credential_ref="synthetic-credential",
        tenant_ids=frozenset((tenant,)), capabilities=frozenset(caps),
        expires_at=expiry or NOW + timedelta(days=1),
    )


COLLECTOR = actor("collector", Capability.EVIDENCE_SUBMIT)
VERIFIER = actor("verifier", Capability.EVIDENCE_VERIFY)
APPROVER = actor("approver", Capability.STAGE_APPROVE)
REVOKER = actor("revoker", Capability.EVIDENCE_REVOKE, Capability.APPROVAL_REVOKE)


class ArtifactReader:
    def __init__(self, digest: str | None = None, *, fail: bool = False) -> None:
        self.digest = digest
        self.fail = fail
        self.calls = 0

    def sha256_digest(self, record: EvidenceRecord) -> str:
        self.calls += 1
        if self.fail:
            raise OSError("synthetic-reader-unavailable")
        return record.artifact_digest if self.digest is None else self.digest


def packet() -> EvidencePacket:
    binding = EvidenceBinding(
        tenant_id="bank-a", installation_id="synthetic-test-install",
        stage=Stage.SHADOW, use_case="uc-01", commit_sha="a" * 40,
        image_digest="sha256:" + "b" * 64,
        dataset_digest="sha256:" + "c" * 64,
        config_version="cfg-1", policy_version="policy-1", rule_version="rule-1",
        signal_version="signal-1", adapter_version="adapter-1",
        window_start=NOW - timedelta(hours=2), window_end=NOW - timedelta(hours=1),
    )
    records = tuple(
        EvidenceRecord(
            evidence_id=UUID(int=i), binding=binding, area=area,
            artifact_ref=f"synthetic-{i}", artifact_digest="sha256:" + "d" * 64,
            source_system="synthetic-ci", collector_actor_ref=COLLECTOR.audit_actor,
            collected_at=NOW - timedelta(minutes=30), expires_at=NOW + timedelta(hours=1),
        ) for i, area in ((1, EvidenceArea.SECURITY), (2, EvidenceArea.DATA_QUALITY))
    )
    return EvidencePacket(binding, "evaluator-1", records)


def apply(
    lifecycle: EvidenceLifecycle, action: EvidenceAction, principal: TrustedPrincipal,
    evidence_id: UUID | None = None, *, now: datetime = NOW,
    reader: ArtifactReader | None = None,
) -> EvidenceLifecycle:
    return propose_transition(
        lifecycle, action=action, principal=principal, evidence_id=evidence_id,
        now=now, artifact_reader=reader,
    )


def submitted() -> EvidenceLifecycle:
    lifecycle = EvidenceLifecycle(packet())
    for record in lifecycle.packet.records:
        lifecycle = apply(lifecycle, EvidenceAction.SUBMIT, COLLECTOR, record.evidence_id)
    return lifecycle


def verified() -> EvidenceLifecycle:
    lifecycle = submitted()
    for record in lifecycle.packet.records:
        lifecycle = apply(
            lifecycle, EvidenceAction.VERIFY, VERIFIER, record.evidence_id,
            reader=ArtifactReader(),
        )
    return lifecycle


def approved() -> EvidenceLifecycle:
    return apply(verified(), EvidenceAction.APPROVE, APPROVER)


def test_positive_synthetic_lifecycle_proposals_are_bound_but_not_authority() -> None:
    lifecycle = approved()
    assert tuple(e.action for e in lifecycle.events) == (
        EvidenceAction.SUBMIT, EvidenceAction.SUBMIT, EvidenceAction.VERIFY,
        EvidenceAction.VERIFY, EvidenceAction.APPROVE,
    )
    assert all(e.packet_digest == lifecycle.packet.packet_digest() for e in lifecycle.events)
    assert not hasattr(lifecycle, "ready")
    assert not hasattr(lifecycle, "bank_inline_approved")
    assert not hasattr(lifecycle, "enforcement_activated")


@pytest.mark.parametrize("capability_actor", [
    actor("wrong-cap", Capability.EVIDENCE_VERIFY),
    actor("wrong-tenant", Capability.EVIDENCE_SUBMIT, tenant="bank-b"),
    actor("expired", Capability.EVIDENCE_SUBMIT, expiry=NOW),
])
def test_submission_fails_on_capability_tenant_or_expired_credential(
    capability_actor: TrustedPrincipal,
) -> None:
    lifecycle = EvidenceLifecycle(packet())
    with pytest.raises(LifecycleRejected):
        apply(lifecycle, EvidenceAction.SUBMIT, capability_actor, UUID(int=1))
    assert lifecycle.events == ()


def test_legacy_capabilities_do_not_grant_bank_lifecycle_actions() -> None:
    draft = EvidenceLifecycle(packet())
    with pytest.raises(LifecycleRejected, match="denied"):
        apply(draft, EvidenceAction.SUBMIT,
              actor("collector", Capability.EVIDENCE_CREATE), UUID(int=1))
    with pytest.raises(LifecycleRejected, match="denied"):
        apply(verified(), EvidenceAction.APPROVE,
              actor("approver", Capability.EVIDENCE_APPROVE))
    with pytest.raises(LifecycleRejected, match="denied"):
        apply(approved(), EvidenceAction.REVOKE_APPROVAL,
              actor("revoker", Capability.EVIDENCE_REVOKE))
    with pytest.raises(LifecycleRejected, match="denied"):
        apply(verified(), EvidenceAction.REVOKE_EVIDENCE,
              actor("revoker", Capability.APPROVAL_REVOKE), UUID(int=1))


def test_collector_identity_must_match_immutable_record() -> None:
    lifecycle = EvidenceLifecycle(packet())
    with pytest.raises(LifecycleRejected, match="collector mismatch"):
        apply(lifecycle, EvidenceAction.SUBMIT,
              actor("other-collector", Capability.EVIDENCE_SUBMIT), UUID(int=1))


def test_no_approval_without_every_independent_verification() -> None:
    with pytest.raises(LifecycleRejected, match="independent verified"):
        apply(submitted(), EvidenceAction.APPROVE, APPROVER)
    lifecycle = submitted()
    lifecycle = apply(lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=1),
                      reader=ArtifactReader())
    with pytest.raises(LifecycleRejected, match="independent verified"):
        apply(lifecycle, EvidenceAction.APPROVE, APPROVER)


def test_collector_cannot_verify_even_with_both_capabilities() -> None:
    dual = actor("collector", Capability.EVIDENCE_SUBMIT, Capability.EVIDENCE_VERIFY)
    with pytest.raises(LifecycleRejected, match="independent verification"):
        apply(submitted(), EvidenceAction.VERIFY, dual, UUID(int=1), reader=ArtifactReader())


@pytest.mark.parametrize("identity", ["collector", "verifier"])
def test_approver_must_be_separate_from_collectors_and_verifiers(identity: str) -> None:
    dual = actor(identity, Capability.STAGE_APPROVE)
    with pytest.raises(LifecycleRejected, match="independent verified"):
        apply(verified(), EvidenceAction.APPROVE, dual)


def test_reader_is_mandatory_and_computed_digest_must_match() -> None:
    lifecycle = submitted()
    with pytest.raises(LifecycleRejected, match="reader"):
        apply(lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=1))
    with pytest.raises(LifecycleRejected, match="digest mismatch"):
        apply(lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=1),
              reader=ArtifactReader("sha256:" + "f" * 64))
    with pytest.raises(LifecycleRejected, match="unavailable"):
        apply(lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=1),
              reader=ArtifactReader(fail=True))
    assert len(lifecycle.events) == 2


def test_reject_unauthorized_verifier_and_unknown_evidence() -> None:
    lifecycle = submitted()
    with pytest.raises(LifecycleRejected, match="capability"):
        apply(lifecycle, EvidenceAction.VERIFY,
              actor("wrong", Capability.STAGE_APPROVE), UUID(int=1),
              reader=ArtifactReader())
    with pytest.raises(LifecycleRejected, match="reader and evidence"):
        apply(lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=99),
              reader=ArtifactReader())


def test_reject_duplicate_submission_verification_and_approval() -> None:
    with pytest.raises(LifecycleRejected, match="duplicate submission"):
        apply(submitted(), EvidenceAction.SUBMIT, COLLECTOR, UUID(int=1))
    with pytest.raises(LifecycleRejected, match="invalid independent verification"):
        apply(verified(), EvidenceAction.VERIFY, VERIFIER, UUID(int=1), reader=ArtifactReader())
    with pytest.raises(LifecycleRejected, match="independent verified"):
        apply(approved(), EvidenceAction.APPROVE, APPROVER)


def test_revoke_evidence_invalidates_future_approval_proposal() -> None:
    lifecycle = verified()
    revoked = apply(lifecycle, EvidenceAction.REVOKE_EVIDENCE, REVOKER, UUID(int=1))
    with pytest.raises(LifecycleRejected, match="independent verified"):
        apply(revoked, EvidenceAction.APPROVE, APPROVER)
    with pytest.raises(LifecycleRejected, match="revocation"):
        apply(revoked, EvidenceAction.REVOKE_EVIDENCE, REVOKER, UUID(int=1))
    assert len(lifecycle.events) + 1 == len(revoked.events)


def test_revoke_after_approval_invalidates_packet_approval() -> None:
    lifecycle = approved()
    revoked = apply(lifecycle, EvidenceAction.REVOKE_EVIDENCE, REVOKER, UUID(int=1))
    assert revoked.events[-1].action is EvidenceAction.REVOKE_EVIDENCE
    with pytest.raises(LifecycleRejected, match="no active approval"):
        apply(revoked, EvidenceAction.REVOKE_APPROVAL, REVOKER)
    with pytest.raises(LifecycleRejected, match="independent verified"):
        apply(revoked, EvidenceAction.APPROVE, APPROVER)


def test_approval_revocation_is_append_only_and_irreversible_for_packet() -> None:
    lifecycle = approved()
    revoked = apply(lifecycle, EvidenceAction.REVOKE_APPROVAL, REVOKER)
    assert revoked.events[-1].action is EvidenceAction.REVOKE_APPROVAL
    with pytest.raises(LifecycleRejected, match="no active approval"):
        apply(revoked, EvidenceAction.REVOKE_APPROVAL, REVOKER)
    with pytest.raises(LifecycleRejected, match="independent verified"):
        apply(revoked, EvidenceAction.APPROVE, APPROVER)
    with pytest.raises(LifecycleRejected, match="no active approval"):
        apply(EvidenceLifecycle(packet()), EvidenceAction.REVOKE_APPROVAL, REVOKER)


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "bank-b"), ("installation_id", "different-installation"),
    ("policy_version", "policy-2"), ("dataset_digest", "sha256:" + "f" * 64),
    ("commit_sha", "f" * 40), ("image_digest", "sha256:" + "f" * 64),
])
def test_history_cannot_be_replayed_against_changed_identity(
    field: str, value: Any,
) -> None:
    lifecycle = approved()
    other_binding = replace(lifecycle.packet.binding, **{field: value})
    changed = replace(lifecycle.packet, binding=other_binding, records=tuple(
        replace(r, binding=other_binding) for r in lifecycle.packet.records
    ))
    with pytest.raises(LifecycleRejected, match="packet identity changed"):
        EvidenceLifecycle(changed, lifecycle.events)


def test_tampered_approval_without_verify_is_rejected() -> None:
    lifecycle = EvidenceLifecycle(packet())
    fake = EvidenceTransition(EvidenceAction.APPROVE, APPROVER.audit_actor, NOW,
                              lifecycle.packet.packet_digest())
    with pytest.raises(LifecycleRejected, match="independent verified"):
        EvidenceLifecycle(lifecycle.packet, (fake,))


def test_revocation_requires_authorized_tenant_and_capability() -> None:
    lifecycle = approved()
    for principal in (actor("tenant-else", Capability.APPROVAL_REVOKE, tenant="bank-b"),
                      actor("wrong-cap", Capability.STAGE_APPROVE)):
        with pytest.raises(LifecycleRejected, match="denied"):
            apply(lifecycle, EvidenceAction.REVOKE_APPROVAL, principal)


def test_strict_action_clock_and_monotonic_history() -> None:
    lifecycle = submitted()
    with pytest.raises(LifecycleRejected, match="typed lifecycle and action"):
        propose_transition(lifecycle, principal=VERIFIER, action="verify", now=NOW,  # type: ignore[arg-type]
                           evidence_id=UUID(int=1), artifact_reader=ArtifactReader())
    with pytest.raises(LifecycleRejected, match="timezone-aware trusted clock"):
        apply(lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=1),
              now=datetime(2026, 10, 31), reader=ArtifactReader())
    with pytest.raises(LifecycleRejected, match="clock moved backward"):
        apply(lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=1),
              now=NOW - timedelta(hours=1), reader=ArtifactReader())


def test_dst_fold_event_instants_are_canonical_utc() -> None:
    zone = ZoneInfo("America/New_York")
    early = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    late = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=1)
    event_early = EvidenceTransition(
        EvidenceAction.SUBMIT, COLLECTOR.audit_actor, early, packet().packet_digest(), UUID(int=1)
    )
    event_late = replace(event_early, at=late)
    assert event_early.at != event_late.at
    assert event_early.at.tzinfo is UTC and event_late.at.tzinfo is UTC
    assert event_late.at - event_early.at == timedelta(hours=1)
    assert event_late.at == late.astimezone(UTC)


def test_frozen_history_and_missing_approval_record_reference() -> None:
    lifecycle = approved()
    with pytest.raises(FrozenInstanceError):
        lifecycle.events = ()  # type: ignore[misc]
    with pytest.raises(LifecycleRejected, match="cannot reference"):
        EvidenceLifecycle(lifecycle.packet, lifecycle.events + (
            EvidenceTransition(EvidenceAction.APPROVE, APPROVER.audit_actor, NOW,
                               lifecycle.packet.packet_digest(), UUID(int=1)),
        ))
