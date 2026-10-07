from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from gasha.decision.mode import ModeAwareDecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
    replay_historical,
)
from gasha.poc.incumbent import compare_incumbent
from gasha.poc.outcomes import IncumbentControlOutcome

T0 = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


def _policy(**kwargs) -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-1",
        policy_version="policy-1",
        rule_version="rules-1",
        **kwargs,
    )


def _transaction(tenant_id: str) -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid4(),
        occurred_at=T0,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("1000.00"),
        currency="ETB",
        sender_customer_id="synthetic-sender",
        sender_account_id="synthetic-account",
        beneficiary_id="synthetic-beneficiary",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="synthetic-destination",
        correlation_id="synthetic-corr",
    )


def _event(
    tenant_id: str,
    intelligence: IntelligenceSnapshot,
    incumbent: IncumbentControlOutcome,
) -> HistoricalTransactionEvent:
    return HistoricalTransactionEvent(
        transaction=_transaction(tenant_id),
        intelligence=intelligence,
        label=ConfirmedOutcomeLabel(is_fraud=True, label_source="synthetic"),
        incumbent_outcome=incumbent,
    )


def test_shadow_envelopes_use_each_tenants_own_policy() -> None:
    intelligence = IntelligenceSnapshot(beneficiary_risk=0.80)
    lax = ModeAwareDecisionService(
        _policy(), operating_mode=OperatingMode.SHADOW
    )
    strict = ModeAwareDecisionService(
        _policy(review_threshold=0.95, hold_threshold=0.96,
                block_threshold=0.97),
        operating_mode=OperatingMode.SHADOW,
    )

    envelope_a = lax.decide(_transaction("tenant-a"), intelligence)
    envelope_b = strict.decide(_transaction("tenant-b"), intelligence)

    # Hypothetical actions differ per tenant policy; both stay non-enforcing.
    assert envelope_a.decision.action == DecisionAction.REVIEW
    assert envelope_b.decision.action == DecisionAction.MONITOR
    assert envelope_a.effective_action == DecisionAction.NO_ACTION_SHADOW
    assert envelope_b.effective_action == DecisionAction.NO_ACTION_SHADOW
    assert envelope_a.decision.tenant_id == "tenant-a"
    assert envelope_b.decision.tenant_id == "tenant-b"


def test_shadow_comparison_cannot_cross_tenant_boundaries() -> None:
    policies = {
        "tenant-a": _policy(),
        # Tenant B only alerts at 0.95+: the same signals are a miss there.
        "tenant-b": _policy(
            monitor_threshold=0.95,
            review_threshold=0.96,
            hold_threshold=0.97,
            block_threshold=0.98,
        ),
    }
    events = (
        _event(
            "tenant-a",
            IntelligenceSnapshot(network_risk=0.80),
            IncumbentControlOutcome.NO_ALERT,
        ),
        _event(
            "tenant-b",
            IntelligenceSnapshot(network_risk=0.80),
            IncumbentControlOutcome.NO_ALERT,
        ),
    )
    report = replay_historical(events, policies)

    by_tenant = {
        result.decision.tenant_id: result.decision.action
        for result in report.results
    }
    assert by_tenant["tenant-a"] == DecisionAction.REVIEW
    assert by_tenant["tenant-b"] == DecisionAction.ALLOW

    comparison = compare_incumbent(report.results)
    # Gasha's tenant-a alert counts as incremental detection; tenant-b's
    # identical signals evaluated under tenant-b policy do not.
    assert comparison.gasha_only_detected == 1
    assert comparison.neither_detected == 1
    assert comparison.incremental_confirmed_detection == 1
