"""#49 bounded offline proposal-kernel regression tests, not bank evidence."""
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from gasha.poc.evidence_identity import (
    EvidenceBinding,
    EvidenceIdentityRejected,
    EvidencePacket,
    EvidenceRecord,
)
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


def split_collector_packet() -> EvidencePacket:
    """Two records have different collectors, with both actors verifier-capable."""
    original = packet()
    second_collector = actor("collector-b", Capability.EVIDENCE_SUBMIT)
    return replace(
        original,
        records=(
            original.records[0],
            replace(original.records[1], collector_actor_ref=second_collector.audit_actor),
        ),
    )


def split_submitted() -> EvidenceLifecycle:
    lifecycle = EvidenceLifecycle(split_collector_packet())
    collectors = (
        actor("collector", Capability.EVIDENCE_SUBMIT),
        actor("collector-b", Capability.EVIDENCE_SUBMIT),
    )
    for record, principal in zip(lifecycle.packet.records, collectors, strict=True):
        lifecycle = apply(lifecycle, EvidenceAction.SUBMIT, principal, record.evidence_id)
    return lifecycle


@pytest.mark.parametrize(
    "verifier,evidence_id",
    [
        (actor("collector", Capability.EVIDENCE_VERIFY), UUID(int=2)),
        (actor("collector-b", Capability.EVIDENCE_VERIFY), UUID(int=1)),
    ],
)
def test_packet_collector_cannot_verify_another_collectors_record(
    verifier: TrustedPrincipal, evidence_id: UUID,
) -> None:
    lifecycle = split_submitted()
    reader = ArtifactReader()
    with pytest.raises(LifecycleRejected, match="independent verification"):
        apply(lifecycle, EvidenceAction.VERIFY, verifier, evidence_id, reader=reader)
    assert reader.calls == 0
    assert len(lifecycle.events) == 2


@pytest.mark.parametrize(
    "verifier,evidence_id",
    [
        (actor("collector", Capability.EVIDENCE_VERIFY), UUID(int=2)),
        (actor("collector-b", Capability.EVIDENCE_VERIFY), UUID(int=1)),
    ],
)
def test_replay_rejects_forged_cross_record_collector_verification(
    verifier: TrustedPrincipal, evidence_id: UUID,
) -> None:
    lifecycle = split_submitted()
    forged = EvidenceTransition(
        EvidenceAction.VERIFY, verifier.audit_actor, NOW,
        lifecycle.packet.packet_digest(), evidence_id,
    )
    with pytest.raises(LifecycleRejected, match="independent verification"):
        EvidenceLifecycle(lifecycle.packet, lifecycle.events + (forged,))


def test_disjoint_packet_collectors_verifier_and_approver_pass() -> None:
    lifecycle = split_submitted()
    for record in lifecycle.packet.records:
        lifecycle = apply(
            lifecycle, EvidenceAction.VERIFY, VERIFIER,
            record.evidence_id, reader=ArtifactReader(),
        )
    lifecycle = apply(lifecycle, EvidenceAction.APPROVE, APPROVER)
    assert lifecycle.events[-1].action is EvidenceAction.APPROVE
    assert {r.collector_actor_ref for r in lifecycle.packet.records}.isdisjoint(
        {VERIFIER.audit_actor, APPROVER.audit_actor}
    )


def test_verify_ineligible_state_never_reads_artifact() -> None:
    never_submitted = EvidenceLifecycle(packet())
    waiting = submitted()
    verified_once = apply(
        waiting, EvidenceAction.VERIFY, VERIFIER, UUID(int=1),
        reader=ArtifactReader(),
    )
    revoked_record = apply(
        waiting, EvidenceAction.REVOKE_EVIDENCE, REVOKER, UUID(int=1),
    )
    for lifecycle, evidence_id in (
        (never_submitted, UUID(int=1)),
        (waiting, UUID(int=99)),
        (verified_once, UUID(int=1)),
        (revoked_record, UUID(int=1)),
    ):
        reader = ArtifactReader()
        events_before = lifecycle.events
        with pytest.raises(LifecycleRejected):
            apply(
                lifecycle, EvidenceAction.VERIFY, VERIFIER,
                evidence_id, reader=reader,
            )
        assert reader.calls == 0
        assert lifecycle.events == events_before


def test_verify_auth_denials_precede_reader_and_leave_history_unchanged() -> None:
    lifecycle = submitted()
    denied = (
        actor("other-tenant", Capability.EVIDENCE_VERIFY, tenant="bank-b"),
        actor("expired", Capability.EVIDENCE_VERIFY, expiry=NOW),
        actor("wrong-cap", Capability.STAGE_APPROVE),
        actor("legacy", Capability.EVIDENCE_CREATE, Capability.EVIDENCE_APPROVE),
    )
    for principal in denied:
        reader = ArtifactReader()
        with pytest.raises(LifecycleRejected, match="denied|expired"):
            apply(
                lifecycle, EvidenceAction.VERIFY, principal,
                UUID(int=1), reader=reader,
            )
        assert reader.calls == 0
        assert len(lifecycle.events) == 2


def test_failed_verification_reader_does_not_append_event() -> None:
    lifecycle = submitted()
    for reader in (
        ArtifactReader("sha256:" + "f" * 64),
        ArtifactReader(fail=True),
    ):
        with pytest.raises(LifecycleRejected, match="mismatch|unavailable"):
            apply(
                lifecycle, EvidenceAction.VERIFY, VERIFIER,
                UUID(int=1), reader=reader,
            )
        assert reader.calls == 1
        assert len(lifecycle.events) == 2


def test_replay_rejects_forged_submission_outside_collection_and_expiry() -> None:
    """Durable/untrusted histories must obey the proposal's original clock gate."""
    item = packet()
    record = item.records[0]
    for event_time in (
        record.collected_at - timedelta(microseconds=1),
        record.expires_at,
        record.expires_at + timedelta(microseconds=1),
    ):
        forged = EvidenceTransition(
            action=EvidenceAction.SUBMIT,
            actor_ref=COLLECTOR.audit_actor,
            at=event_time,
            packet_digest=item.packet_digest(),
            evidence_id=record.evidence_id,
        )
        with pytest.raises(EvidenceIdentityRejected, match="future-dated|expired"):
            EvidenceLifecycle(item, (forged,))


def test_replay_submission_must_follow_all_packet_collections() -> None:
    """A signed-looking complete packet cannot preexist a later-collected record."""
    original = packet()
    later = replace(original.records[1], collected_at=NOW - timedelta(minutes=5))
    item = EvidencePacket(original.binding, original.evaluator_version,
                          (original.records[0], later))
    event = EvidenceTransition(
        action=EvidenceAction.SUBMIT,
        actor_ref=COLLECTOR.audit_actor,
        at=NOW - timedelta(minutes=20),
        packet_digest=item.packet_digest(),
        evidence_id=original.records[0].evidence_id,
    )
    with pytest.raises(EvidenceIdentityRejected, match="future-dated"):
        EvidenceLifecycle(item, (event,))
    assert len(EvidenceLifecycle(item, (replace(event, at=later.collected_at),)).events) == 1



def test_replay_submission_accepts_exact_collection_boundary() -> None:
    """Equality at collection is valid; equality at expiry is not."""
    item = packet()
    record = item.records[0]
    submitted_at_collection = EvidenceTransition(
        action=EvidenceAction.SUBMIT,
        actor_ref=COLLECTOR.audit_actor,
        at=record.collected_at,
        packet_digest=item.packet_digest(),
        evidence_id=record.evidence_id,
    )
    assert len(EvidenceLifecycle(item, (submitted_at_collection,)).events) == 1


def test_replay_submission_uses_utc_instants_across_dst_fold() -> None:
    """Wall-clock ordering is not the chronology of a repeated local hour."""
    zone = ZoneInfo("America/New_York")
    original = packet()
    collected_early = datetime(2026, 11, 1, 1, 45, tzinfo=zone, fold=0)
    expires_late = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    valid = replace(
        original,
        records=tuple(
            replace(record, collected_at=collected_early, expires_at=expires_late)
            for record in original.records
        ),
    )
    valid_event = EvidenceTransition(
        action=EvidenceAction.SUBMIT,
        actor_ref=COLLECTOR.audit_actor,
        at=datetime(2026, 11, 1, 1, 10, tzinfo=zone, fold=1),
        packet_digest=valid.packet_digest(),
        evidence_id=valid.records[0].evidence_id,
    )
    assert len(EvidenceLifecycle(valid, (valid_event,)).events) == 1

    collected_late = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    expires_later = datetime(2026, 11, 1, 1, 45, tzinfo=zone, fold=1)
    invalid = replace(
        original,
        records=tuple(
            replace(record, collected_at=collected_late, expires_at=expires_later)
            for record in original.records
        ),
    )
    invalid_event = EvidenceTransition(
        action=EvidenceAction.SUBMIT,
        actor_ref=COLLECTOR.audit_actor,
        at=datetime(2026, 11, 1, 1, 45, tzinfo=zone, fold=0),
        packet_digest=invalid.packet_digest(),
        evidence_id=invalid.records[0].evidence_id,
    )
    with pytest.raises(EvidenceIdentityRejected, match="future-dated"):
        EvidenceLifecycle(invalid, (invalid_event,))


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("action", "verify", "typed action"),
        ("action", 0, "typed action"),
        ("actor_ref", "", "pseudonymous actor"),
        ("actor_ref", 1, "pseudonymous actor"),
        ("at", datetime(2026, 10, 31, 20), "timezone-aware"),
        ("at", None, "timezone-aware"),
        ("packet_digest", 17, "packet digest"),
        ("evidence_id", "1", "typed evidence_id"),
    ],
)
def test_replay_revalidates_runtime_mutated_transition_fields(
    field: str, value: object, reason: str,
) -> None:
    """Typed frozen history may be mutated after construction; never trust it."""
    lifecycle = submitted()
    forged = EvidenceTransition(
        EvidenceAction.VERIFY, VERIFIER.audit_actor, NOW,
        lifecycle.packet.packet_digest(), UUID(int=1),
    )
    object.__setattr__(forged, field, value)
    with pytest.raises(LifecycleRejected, match=reason):
        EvidenceLifecycle(lifecycle.packet, lifecycle.events + (forged,))


@pytest.mark.parametrize(
    "field", ("action", "actor_ref", "at", "packet_digest", "evidence_id"),
)
def test_replay_rejects_deleted_transition_attributes(field: str) -> None:
    lifecycle = submitted()
    forged = EvidenceTransition(
        EvidenceAction.VERIFY, VERIFIER.audit_actor, NOW,
        lifecycle.packet.packet_digest(), UUID(int=1),
    )
    object.__delattr__(forged, field)
    with pytest.raises(LifecycleRejected, match="missing transition attribute"):
        EvidenceLifecycle(lifecycle.packet, lifecycle.events + (forged,))


def test_strenum_value_cannot_replay_as_a_different_lifecycle_action() -> None:
    """A raw string 'verify' formerly compared equal, then fell into REVOKE."""
    lifecycle = submitted()
    forged = EvidenceTransition(
        EvidenceAction.VERIFY, VERIFIER.audit_actor, NOW,
        lifecycle.packet.packet_digest(), UUID(int=1),
    )
    object.__setattr__(forged, "action", "verify")
    with pytest.raises(LifecycleRejected, match="typed action"):
        EvidenceLifecycle(lifecycle.packet, lifecycle.events + (forged,))
    # A forged history must fail before the privileged artifact resolver is read.
    object.__setattr__(lifecycle, "events", lifecycle.events + (forged,))
    reader = ArtifactReader()
    with pytest.raises(LifecycleRejected, match="typed action"):
        apply(
            lifecycle, EvidenceAction.VERIFY, VERIFIER, UUID(int=1),
            reader=reader,
        )
    assert reader.calls == 0



@pytest.mark.parametrize("bad_records", [None, [], ()])
def test_replay_checks_packet_shape_before_nested_record_access(
    bad_records: Any,
) -> None:
    damaged = packet()
    object.__setattr__(damaged, "records", bad_records)
    with pytest.raises(LifecycleRejected, match="invalid evidence packet"):
        EvidenceLifecycle(damaged)


def test_replay_rejects_deleted_record_identifier_with_domain_error() -> None:
    damaged = packet()
    object.__delattr__(damaged.records[0], "evidence_id")
    with pytest.raises(LifecycleRejected, match="invalid evidence packet"):
        EvidenceLifecycle(damaged)


def test_replay_accepts_valid_packet_with_verified_approval_history() -> None:
    existing = approved()
    replayed = EvidenceLifecycle(existing.packet, existing.events)
    assert replayed.events == existing.events
    assert replayed.packet.packet_digest() == existing.packet.packet_digest()

@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("binding", None),
        ("records", None),
        ("records", []),
        ("evaluator_version", ""),
    ],
)
def test_transition_rejects_mutated_packet_before_tenant_lookup_or_reader(
    field: str, replacement: Any,
) -> None:
    lifecycle = submitted()
    reader = ArtifactReader()
    original_events = lifecycle.events
    object.__setattr__(lifecycle.packet, field, replacement)
    with pytest.raises(LifecycleRejected, match="invalid evidence packet"):
        apply(
            lifecycle, EvidenceAction.VERIFY, VERIFIER,
            UUID(int=1), reader=reader,
        )
    assert reader.calls == 0
    assert lifecycle.events == original_events


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("capabilities", frozenset({"evidence.verify"})),
        ("tenant_ids", frozenset({123})),
        ("expires_at", None),
        ("subject", ""),
    ],
)
def test_transition_rejects_mutated_principal_before_authorization_or_reader(
    field: str, replacement: Any,
) -> None:
    lifecycle = submitted()
    reader = ArtifactReader()
    principal = actor("verifier", Capability.EVIDENCE_VERIFY)
    object.__setattr__(principal, field, replacement)
    with pytest.raises(LifecycleRejected, match="invalid trusted principal"):
        apply(
            lifecycle, EvidenceAction.VERIFY, principal,
            UUID(int=1), reader=reader,
        )
    assert reader.calls == 0
    assert len(lifecycle.events) == 2


@pytest.mark.parametrize("missing", ["subject", "capabilities", "expires_at"])
def test_transition_rejects_deleted_principal_field(missing: str) -> None:
    principal = actor("verifier", Capability.EVIDENCE_VERIFY)
    object.__delattr__(principal, missing)
    reader = ArtifactReader()
    with pytest.raises(LifecycleRejected, match="invalid trusted principal"):
        apply(
            submitted(), EvidenceAction.VERIFY, principal,
            UUID(int=1), reader=reader,
        )
    assert reader.calls == 0

@pytest.mark.parametrize("missing", ("packet", "events"))
def test_proposal_rejects_deleted_lifecycle_field_before_artifact_read(missing: str) -> None:
    lifecycle = submitted()
    reader = ArtifactReader()
    original_events = lifecycle.events
    object.__delattr__(lifecycle, missing)
    with pytest.raises(LifecycleRejected, match="missing lifecycle attribute"):
        apply(
            lifecycle, EvidenceAction.VERIFY, VERIFIER,
            UUID(int=1), reader=reader,
        )
    assert reader.calls == 0
    if missing != "events":
        assert lifecycle.events is original_events


class _ProposalHookZone(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        self.calls += 1
        return timedelta(0)

    def dst(self, dt: datetime | None) -> timedelta | None:
        return timedelta(0)

    def tzname(self, dt: datetime | None) -> str | None:
        return "hostile-proposal-zone"


class _ProposalHookDateTime(datetime):
    calls = 0

    def utcoffset(self) -> timedelta | None:
        type(self).calls += 1
        return timedelta(0)

    def astimezone(self, tz: tzinfo | None = None) -> datetime:
        type(self).calls += 1
        return super().astimezone(tz)


@pytest.mark.parametrize("surface", [
    "new_event", "replayed_event", "proposal_now", "mutated_principal_expiry",
])
@pytest.mark.parametrize("kind", ["custom_zone", "datetime_subclass"])
def test_evidence_lifecycle_rejects_clock_hooks_without_side_effects(
    surface: str, kind: str,
) -> None:
    lifecycle = submitted()
    reader = ArtifactReader()
    before = lifecycle.events
    zone = _ProposalHookZone()
    _ProposalHookDateTime.calls = 0
    hostile = (
        datetime(2026, 10, 31, 20, tzinfo=zone)
        if kind == "custom_zone"
        else _ProposalHookDateTime(2026, 10, 31, 20, tzinfo=UTC)
    )
    with pytest.raises(LifecycleRejected, match="timezone-aware|principal"):
        if surface == "new_event":
            EvidenceTransition(
                EvidenceAction.VERIFY, VERIFIER.audit_actor, hostile,
                lifecycle.packet.packet_digest(), UUID(int=1),
            )
        elif surface == "replayed_event":
            forged = EvidenceTransition(
                EvidenceAction.VERIFY, VERIFIER.audit_actor, NOW,
                lifecycle.packet.packet_digest(), UUID(int=1),
            )
            object.__setattr__(forged, "at", hostile)
            EvidenceLifecycle(lifecycle.packet, lifecycle.events + (forged,))
        elif surface == "mutated_principal_expiry":
            principal = actor("verifier-clock", Capability.EVIDENCE_VERIFY)
            object.__setattr__(principal, "expires_at", hostile)
            apply(
                lifecycle, EvidenceAction.VERIFY, principal,
                UUID(int=1), reader=reader,
            )
        else:
            apply(
                lifecycle, EvidenceAction.VERIFY, VERIFIER,
                UUID(int=1), now=hostile, reader=reader,
            )
    assert zone.calls == 0
    assert _ProposalHookDateTime.calls == 0
    assert reader.calls == 0
    assert lifecycle.events == before


class _PretendProposalDateTime:
    """An isinstance(datetime) callback trap; not a valid clock."""

    def __init__(self) -> None:
        self.calls = 0

    @property
    def __class__(self) -> type[datetime]:
        self.calls += 1
        return datetime


@pytest.mark.parametrize("surface", [
    "new_event", "replayed_event", "proposal_now", "mutated_principal_expiry",
])
def test_proposal_forged_class_clock_rejected_without_reader(
    surface: str,
) -> None:
    lifecycle = submitted()
    reader = ArtifactReader()
    before = lifecycle.events
    hostile: Any = _PretendProposalDateTime()
    with pytest.raises(LifecycleRejected, match="timezone-aware|principal"):
        if surface == "new_event":
            EvidenceTransition(
                EvidenceAction.VERIFY, VERIFIER.audit_actor, hostile,
                lifecycle.packet.packet_digest(), UUID(int=1),
            )
        elif surface == "replayed_event":
            event = EvidenceTransition(
                EvidenceAction.VERIFY, VERIFIER.audit_actor, NOW,
                lifecycle.packet.packet_digest(), UUID(int=1),
            )
            object.__setattr__(event, "at", hostile)
            EvidenceLifecycle(lifecycle.packet, lifecycle.events + (event,))
        elif surface == "mutated_principal_expiry":
            principal = actor("verifier-clock-class", Capability.EVIDENCE_VERIFY)
            object.__setattr__(principal, "expires_at", hostile)
            apply(
                lifecycle, EvidenceAction.VERIFY, principal,
                UUID(int=1), reader=reader,
            )
        else:
            apply(
                lifecycle, EvidenceAction.VERIFY, VERIFIER,
                UUID(int=1), now=hostile, reader=reader,
            )
    assert hostile.calls == 0
    assert reader.calls == 0
    assert lifecycle.events == before
