"""Bounded #145 synthetic provenance contract tests; no Bank evidence or action."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from gasha.domain.models import IntelligenceSnapshot, OperatingMode
from gasha.ingestion.contracts import InboundBankEvent
from gasha.ingestion.shadow_copy import SHADOW_COPY_SCHEMA, SyntheticShadowCopyAdapter
from gasha.intelligence.feature_assessment_v1 import (
    ASSESSMENT_VERSION,
    assess_synthetic_shadow_features,
)
from gasha.intelligence.feature_set_v1 import ObservedTransfer
from gasha.intelligence.internal_graph import InternalGraphPolicy

T = datetime(2026, 11, 14, 12, tzinfo=UTC)
POLICY = InternalGraphPolicy(policy_version="synthetic-graph-v1")


def normalized(*, tenant="synthetic-a", device="device-x"):
    event_id = str(uuid4())
    raw = {
        "event_id": event_id,
        "occurred_at": T.isoformat(),
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": "100.00",
        "currency": "USD",
        "sender_customer_id": "customer-x",
        "sender_account_id": "account-x",
        "beneficiary_id": "beneficiary-x",
        "beneficiary_type": "external",
        "destination_institution_id": "institution-x",
        "correlation_id": "corr-x",
    }
    if device is not None:
        raw["device_id"] = device
    copy = InboundBankEvent(
        tenant_id=tenant, source_system="synthetic-shadow-copy",
        schema_version=SHADOW_COPY_SCHEMA, payload=raw,
        received_at=T + timedelta(seconds=1),
    )
    return SyntheticShadowCopyAdapter().adapt(copy)


def history(*, tenant="synthetic-a"):
    return tuple(
        ObservedTransfer(
            tenant, f"prior-{index}", f"sender-{index}",
            "beneficiary-x", None,
            T - timedelta(minutes=index), T - timedelta(minutes=index),
        )
        for index in range(1, 6)
    )


def assess(envelope, observations):
    return assess_synthetic_shadow_features(
        envelope, observations, policy=POLICY,
    )


def test_replay_stable_graph_provenance_and_default_off_action():
    event = normalized()
    eligible = history()
    late = ObservedTransfer(
        event.tenant_id, "late", "sender-late", "beneficiary-x",
        None, T - timedelta(minutes=10), T + timedelta(seconds=2),
    )
    result = assess(event, eligible + (late,))
    repeated = assess(event, tuple(reversed(eligible)) + (late,))
    assert result.version == ASSESSMENT_VERSION
    assert result.feature_set.beneficiary_unique_senders_1h == 5
    assert result.eligible_observations == 5
    assert result.late_observations == 1
    assert result.nonprior_observations == 0
    assert result.source_fingerprint == repeated.source_fingerprint
    assert result.computation_fingerprint == repeated.computation_fingerprint
    assert len(result.source_fingerprint) == len(result.computation_fingerprint) == 64
    assert "INTERNAL_GRAPH_BENEFICIARY_FAN_IN" in result.assessed_envelope.evidence_reason_codes
    assert result.assessed_envelope.intelligence.network_risk == 0.86
    assert result.assessed_envelope.operating_mode is OperatingMode.SHADOW
    assert event.intelligence == IntelligenceSnapshot()
    assert event.evidence_reason_codes == ()


def test_identical_values_but_different_availability_and_source_do_not_collide():
    event = normalized()
    original = history()
    first = assess(event, original)
    changed_availability = ObservedTransfer(
        "synthetic-a", "prior-1", "sender-1", "beneficiary-x",
        None, T - timedelta(minutes=1), T - timedelta(seconds=1),
    )
    changed_set = ObservedTransfer(
        "synthetic-a", "prior-1", "other-sender", "beneficiary-x",
        None, T - timedelta(minutes=1), T - timedelta(minutes=1),
    )
    for candidate in (changed_availability, changed_set):
        other = assess(event, (candidate,) + original[1:])
        assert other.feature_set.beneficiary_unique_senders_1h == 5
        assert other.source_fingerprint != first.source_fingerprint
        assert other.computation_fingerprint != first.computation_fingerprint
    late = ObservedTransfer(
        "synthetic-a", "late", "sender-late", "beneficiary-x",
        None, T - timedelta(minutes=10), T + timedelta(seconds=2),
    )
    after = assess(event, original + (late,))
    assert after.feature_set.beneficiary_unique_senders_1h == 5
    assert after.source_fingerprint != first.source_fingerprint
    assert after.computation_fingerprint != first.computation_fingerprint


def test_other_cutoff_event_policy_and_tenant_produce_separate_identity():
    event = normalized()
    first = assess(event, history())
    later = event.model_copy(update={"received_at": T + timedelta(seconds=5)})
    assert assess(later, history()).computation_fingerprint != first.computation_fingerprint
    other_event = normalized()
    assert assess(other_event, history()).source_fingerprint != first.source_fingerprint
    other_policy = InternalGraphPolicy(policy_version="synthetic-graph-v2")
    updated = assess_synthetic_shadow_features(event, history(), policy=other_policy)
    assert updated.computation_fingerprint != first.computation_fingerprint


def test_missing_optional_device_is_explicit_not_a_measured_zero():
    event = normalized(device=None)
    result = assess(event, history())
    assert "device_ref" in result.unavailable_signals
    assert result.feature_set.distinct_accounts_on_device_1h is None


@pytest.mark.parametrize("corrupt", ["mode", "risk", "event", "tenant", "reason", "clock"])
def test_forged_normalized_identity_mode_risk_or_clock_is_rejected(corrupt):
    event = normalized()
    tx = event.canonical_transaction
    if corrupt == "mode":
        event = event.model_copy(update={"operating_mode": OperatingMode.ENFORCING})
    elif corrupt == "risk":
        event = event.model_copy(update={"intelligence": IntelligenceSnapshot(network_risk=0.9)})
    elif corrupt == "event":
        event = event.model_copy(update={"event_id": uuid4()})
    elif corrupt == "tenant":
        event = event.model_copy(update={"canonical_transaction": tx.model_copy(
            update={"tenant_id": "synthetic-b"},
        )})
    elif corrupt == "reason":
        event = event.model_copy(update={"evidence_reason_codes": ("IMPORTED_RISK",)})
    else:
        event = event.model_copy(update={"received_at": T.replace(tzinfo=None)})
    with pytest.raises(ValueError, match="untrusted"):
        assess(event, history())


def test_cross_tenant_late_history_and_malformed_inputs_fail_closed():
    event = normalized()
    foreign = ObservedTransfer(
        "synthetic-b", "prior-foreign", "sender-b", "beneficiary-x",
        None, T - timedelta(minutes=5), T + timedelta(seconds=2),
    )
    with pytest.raises(ValueError, match="untrusted"):
        assess(event, history() + (foreign,))
    with pytest.raises(ValueError, match="invalid"):
        assess(event, list(history()))
    with pytest.raises(ValueError, match="invalid"):
        assess_synthetic_shadow_features(event, history(), policy="forged")
