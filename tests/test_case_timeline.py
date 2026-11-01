"""#45 inert transition-kernel tests; no bank case storage or proxy enabled."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest

from gasha.cases.timeline import (
    AuthorizedAssignee,
    BankExecution,
    CaseCommand,
    CaseConflict,
    CaseDisposition,
    CaseOperation,
    CaseReason,
    CaseRejected,
    CaseSourceUnavailable,
    VerifiedEvaluation,
    advance_case,
)
from gasha.security.access import AuthorizationRejected, Capability, TrustedPrincipal

NOW = datetime(2026, 10, 31, 18, 0, tzinfo=UTC)
CASE = uuid4()
SOURCE = uuid4()
CONTEXT = "c" * 64


class Lookup:
    def __init__(self, tenant: str = "tenant-a", context: str = CONTEXT) -> None:
        self.tenant = tenant
        self.context = context
        self.outage = False

    def resolve(self, tenant_id: str, event_id):
        if self.outage:
            raise RuntimeError("synthetic lookup failure")
        return VerifiedEvaluation(self.tenant, event_id, self.context)


def principal(*, tenant: str = "tenant-a", caps: frozenset[Capability] | None = None):
    return TrustedPrincipal(
        subject="synthetic-analyst", issuer="synthetic-test",
        credential_ref="synthetic-credential-v1", tenant_ids=frozenset({tenant}),
        capabilities=(caps if caps is not None else frozenset({
            Capability.CASE_CREATE, Capability.CASE_TRIAGE, Capability.CASE_ASSIGN,
            Capability.CASE_DISPOSITION, Capability.CASE_CORRECT,
            Capability.CASE_FEEDBACK,
        })),
        expires_at=NOW + timedelta(hours=1),
    )


def command(operation: CaseOperation, revision: int, **kwargs):
    reasons = {
        CaseOperation.CREATE: CaseReason.SOURCE_EVALUATION,
        CaseOperation.TRIAGE: CaseReason.ANALYST_TRIAGE,
        CaseOperation.ASSIGN: CaseReason.INVESTIGATION_ASSIGNED,
        CaseOperation.DISPOSE: CaseReason.FRAUD_EVIDENCE,
        CaseOperation.CORRECT: CaseReason.CORRECTED_FINDING,
        CaseOperation.RECONCILE: CaseReason.FEEDBACK_RECONCILED,
    }
    return CaseCommand(
        tenant_id="tenant-a", case_id=CASE, source_event_id=SOURCE,
        operation=operation, expected_revision=revision, idempotency_key=uuid4().hex,
        reason_code=reasons[operation], **kwargs,
    )


def step(history, cmd, *, identity=None, lookup=None, at=NOW):
    return advance_case(
        history, cmd, principal=identity if identity is not None else principal(),
        source=lookup if lookup is not None else Lookup(), at=at,
    )


def lifecycle():
    history = ()
    for op, kwargs in (
        (CaseOperation.CREATE, {}), (CaseOperation.TRIAGE, {}),
        (CaseOperation.ASSIGN, {
            "assignee": AuthorizedAssignee("tenant-a", "a" * 64),
        }),
        (CaseOperation.DISPOSE, {"disposition": CaseDisposition.FRAUD}),
        (CaseOperation.CORRECT, {"disposition": CaseDisposition.LEGITIMATE}),
        (CaseOperation.RECONCILE, {}),
    ):
        history, _ = step(history, command(op, len(history), **kwargs))
    return history


def test_full_synthetic_case_lifecycle_is_immutable_and_never_executes_bank_action():
    history = lifecycle()
    assert [event.operation for event in history] == list(CaseOperation)
    assert [event.revision for event in history] == list(range(1, 7))
    assert all(event.source_event_id == SOURCE and event.source_context_ref == CONTEXT
               for event in history)
    assert [event.previous_revision for event in history] == [None, 1, 2, 3, 4, 5]
    assert [event.bank_execution for event in history] == [BankExecution.UNKNOWN] * 6
    assert history[3].disposition is CaseDisposition.FRAUD
    assert history[4].disposition is CaseDisposition.LEGITIMATE
    assert history[3].disposition is CaseDisposition.FRAUD
    assert len({event.command_ref for event in history}) == 6
    assert all(event.actor_ref == principal().audit_actor for event in history)
    assert "synthetic-analyst" not in repr(history)


def test_same_idempotency_key_returns_original_revision_without_write():
    cmd = command(CaseOperation.CREATE, 0)
    history, event = step((), cmd)
    repeated, same = step(history, cmd, at=NOW + timedelta(seconds=1))
    assert repeated == history and same is event


def test_idempotency_key_payload_conflict_is_rejected():
    cmd = command(CaseOperation.CREATE, 0)
    history, _ = step((), cmd)
    with pytest.raises(CaseConflict):
        step(history, replace(cmd, expected_revision=1))
    assert len(history) == 1


def test_stale_revision_rejected_with_zero_changes():
    history, _ = step((), command(CaseOperation.CREATE, 0))
    with pytest.raises(CaseConflict):
        step(history, command(CaseOperation.TRIAGE, 0))
    assert len(history) == 1


@pytest.mark.parametrize("operation", [
    CaseOperation.TRIAGE, CaseOperation.ASSIGN,
    CaseOperation.DISPOSE, CaseOperation.CORRECT, CaseOperation.RECONCILE,
])
def test_creation_must_be_first(operation):
    kwargs = {}
    if operation is CaseOperation.ASSIGN:
        kwargs["assignee"] = AuthorizedAssignee("tenant-a", "a" * 64)
    if operation in (CaseOperation.DISPOSE, CaseOperation.CORRECT):
        kwargs["disposition"] = CaseDisposition.FRAUD
    with pytest.raises(CaseRejected):
        step((), command(operation, 0, **kwargs))


def test_correction_cannot_preserve_same_disposition():
    history = lifecycle()[:4]
    with pytest.raises(CaseRejected):
        step(history, command(CaseOperation.CORRECT, 4,
                              disposition=CaseDisposition.FRAUD))


def test_final_reconciliation_is_terminal():
    with pytest.raises(CaseRejected):
        step(lifecycle(), command(CaseOperation.CORRECT, 6,
                                  disposition=CaseDisposition.UNRESOLVED))


@pytest.mark.parametrize("operation,cap", [
    (CaseOperation.CREATE, Capability.CASE_CREATE),
    (CaseOperation.TRIAGE, Capability.CASE_TRIAGE),
    (CaseOperation.ASSIGN, Capability.CASE_ASSIGN),
    (CaseOperation.DISPOSE, Capability.CASE_DISPOSITION),
    (CaseOperation.CORRECT, Capability.CASE_CORRECT),
    (CaseOperation.RECONCILE, Capability.CASE_FEEDBACK),
])
def test_each_operation_requires_separate_capability(operation, cap):
    kwargs = {}
    if operation is CaseOperation.ASSIGN:
        kwargs["assignee"] = AuthorizedAssignee("tenant-a", "a" * 64)
    if operation in (CaseOperation.DISPOSE, CaseOperation.CORRECT):
        kwargs["disposition"] = CaseDisposition.FRAUD
    with pytest.raises(AuthorizationRejected):
        step((), command(operation, 0, **kwargs), identity=principal(caps=frozenset()))
    assert cap not in principal(caps=frozenset()).capabilities


def test_cross_tenant_principal_and_source_lookup_fail():
    with pytest.raises(AuthorizationRejected):
        step((), command(CaseOperation.CREATE, 0), identity=principal(tenant="tenant-b"))
    with pytest.raises(CaseSourceUnavailable):
        step((), command(CaseOperation.CREATE, 0), lookup=Lookup(tenant="tenant-b"))


def test_source_outage_fails_closed_even_on_duplicate():
    cmd = command(CaseOperation.CREATE, 0)
    history, _ = step((), cmd)
    lookup = Lookup()
    lookup.outage = True
    with pytest.raises(CaseSourceUnavailable):
        step(history, cmd, lookup=lookup)


def test_source_context_change_does_not_silently_rebind_history():
    history, _ = step((), command(CaseOperation.CREATE, 0))
    with pytest.raises(CaseRejected):
        step(history, command(CaseOperation.TRIAGE, 1), lookup=Lookup(context="d" * 64))


def test_history_case_tenant_or_source_substitution_is_rejected():
    history, _ = step((), command(CaseOperation.CREATE, 0))
    for field, value in (
        ("tenant_id", "tenant-b"),
        ("case_id", uuid4()),
        ("source_event_id", uuid4()),
        ("revision", 8),
        ("source_context_ref", "d" * 64),
    ):
        with pytest.raises(CaseRejected):
            step((replace(history[0], **{field: value}),),
                 command(CaseOperation.TRIAGE, 1))


@pytest.mark.parametrize("field,value", [
    ("tenant_id", " tenant-a"), ("expected_revision", True),
    ("idempotency_key", "raw-client-request"), ("reason_code", "free text"),
    ("reason_code", "token@example.com"), ("reason_code", "bad\nsecret"),
    ("reason_code", CaseReason.ANALYST_TRIAGE),
    ("operation", "create"), ("case_id", "raw-case"),
    ("source_event_id", "raw-event"),
])
def test_malformed_commands_rejected_before_source_or_mutation(field, value):
    with pytest.raises(CaseRejected):
        step((), replace(command(CaseOperation.CREATE, 0), **{field: value}))


def test_wrong_tenant_or_raw_assignee_rejected():
    for assignee in (
        AuthorizedAssignee("tenant-b", "a" * 64),
        AuthorizedAssignee("tenant-a", "raw-subject"),
    ):
        with pytest.raises(CaseRejected):
            step((), command(CaseOperation.ASSIGN, 0, assignee=assignee))


def test_disposition_not_allowed_on_triage_and_missing_on_dispose():
    with pytest.raises(CaseRejected):
        step((), command(CaseOperation.TRIAGE, 0,
                         disposition=CaseDisposition.FRAUD))
    with pytest.raises(CaseRejected):
        step((), command(CaseOperation.DISPOSE, 0))


def test_regressing_or_naive_clock_rejected():
    history, _ = step((), command(CaseOperation.CREATE, 0))
    with pytest.raises(CaseRejected):
        step(history, command(CaseOperation.TRIAGE, 1), at=NOW - timedelta(seconds=1))
    with pytest.raises(CaseRejected):
        step(history, command(CaseOperation.TRIAGE, 1), at=datetime(2026, 10, 31))
@pytest.mark.parametrize(("disposition", "reason"), [
    (CaseDisposition.FRAUD, CaseReason.FRAUD_EVIDENCE),
    (CaseDisposition.LEGITIMATE, CaseReason.LEGITIMATE_EVIDENCE),
    (CaseDisposition.UNRESOLVED, CaseReason.NEEDS_REVIEW),
])
def test_all_normalized_dispositions_preserve_unknown_bank_execution(disposition, reason):
    history = lifecycle()[:3]
    cmd = replace(command(CaseOperation.DISPOSE, 3, disposition=disposition),
                  reason_code=reason)
    appended, event = step(history, cmd)
    assert appended[-1] == event
    assert len(appended) == 4
    assert event.disposition is disposition
    assert event.bank_execution is BankExecution.UNKNOWN
    assert appended[:3] == history


def test_mismatched_disposition_and_reason_code_is_rejected():
    history = lifecycle()[:3]
    with pytest.raises(CaseRejected):
        step(history, command(CaseOperation.DISPOSE, 3,
                              disposition=CaseDisposition.LEGITIMATE))

def test_case_kernel_rejects_expired_principal_across_dst_fallback():
    zone = ZoneInfo("America/New_York")
    at = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    expired = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    assert expired > at  # Wall time is misleading; the credential has expired.
    assert expired.astimezone(UTC) < at.astimezone(UTC)
    with pytest.raises(AuthorizationRejected, match="expired principal"):
        step((), command(CaseOperation.CREATE, 0),
             identity=replace(principal(), expires_at=expired), at=at)


def test_case_kernel_accepts_valid_principal_across_dst_fallback():
    zone = ZoneInfo("America/New_York")
    at = datetime(2026, 11, 1, 1, 30, tzinfo=zone, fold=0)
    expires = datetime(2026, 11, 1, 1, 15, tzinfo=zone, fold=1)
    assert expires < at  # Wall time is misleading; expiry is later in UTC.
    assert expires.astimezone(UTC) > at.astimezone(UTC)
    history, event = step((), command(CaseOperation.CREATE, 0),
                          identity=replace(principal(), expires_at=expires), at=at)
    assert len(history) == 1
    assert event.recorded_at == at.astimezone(UTC)


def test_case_kernel_rejects_exact_credential_expiry():
    with pytest.raises(AuthorizationRejected, match="expired principal"):
        step((), command(CaseOperation.CREATE, 0),
             identity=replace(principal(), expires_at=NOW), at=NOW)
