from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest

from gasha.domain.models import BeneficiaryType, CanonicalTransaction
from gasha.intelligence.graph_features import (
    TenantGraphFeatureBuilder,
    TenantIsolationViolation,
)
from gasha.intelligence.provenance import IntelligenceScope, IntelligenceSource

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def transfer(
    *,
    tenant_id: str = "tenant-a",
    sender_customer_id: str = "customer-1",
    sender_account_id: str = "account-1",
    beneficiary_id: str = "beneficiary-9",
    beneficiary_type: BeneficiaryType = BeneficiaryType.EXTERNAL,
    destination_institution_id: str | None = "external-bank",
    device_id: str | None = None,
    amount: Decimal = Decimal("500.00"),
    occurred_at: datetime = T0,
) -> CanonicalTransaction:
    return CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid4(),
        occurred_at=occurred_at,
        channel="mobile",
        transaction_type="transfer",
        amount=amount,
        currency="ETB",
        sender_customer_id=sender_customer_id,
        sender_account_id=sender_account_id,
        beneficiary_id=beneficiary_id,
        beneficiary_type=beneficiary_type,
        destination_institution_id=destination_institution_id,
        device_id=device_id,
        correlation_id=f"corr-{sender_account_id}-{beneficiary_id}",
    )


def builder() -> TenantGraphFeatureBuilder:
    return TenantGraphFeatureBuilder(
        "tenant-a", source_version="internal-graph-features-2"
    )


def test_cross_tenant_observe_and_score_are_rejected() -> None:
    graph = builder()
    foreign = transfer(tenant_id="tenant-b")

    with pytest.raises(TenantIsolationViolation):
        graph.observe(foreign)
    with pytest.raises(TenantIsolationViolation):
        graph.signals_for(foreign)


def test_tenant_history_does_not_leak_across_builders() -> None:
    tenant_a = builder()
    tenant_b = TenantGraphFeatureBuilder(
        "tenant-b", source_version="internal-graph-features-2"
    )
    for index in range(3):
        tenant_a.observe(
            transfer(
                sender_customer_id=f"victim-{index}",
                sender_account_id=f"victim-account-{index}",
                occurred_at=T0 - timedelta(minutes=10),
            )
        )

    scored_a = transfer(occurred_at=T0)
    scored_b = transfer(tenant_id="tenant-b", occurred_at=T0)
    assert tenant_a.signals_for(scored_a).unique_senders_to_beneficiary_1h == 3
    assert tenant_b.signals_for(scored_b).unique_senders_to_beneficiary_1h == 0


def test_fan_in_and_velocity_use_trailing_hour_before_event() -> None:
    graph = builder()
    for index in range(4):
        graph.observe(
            transfer(
                sender_customer_id=f"victim-{index}",
                sender_account_id=f"victim-account-{index}",
                occurred_at=T0 - timedelta(minutes=30),
            )
        )
    graph.observe(
        transfer(
            sender_customer_id="victim-old",
            sender_account_id="victim-account-old",
            occurred_at=T0 - timedelta(hours=2),
        )
    )

    signals = graph.signals_for(transfer(occurred_at=T0))

    assert signals.unique_senders_to_beneficiary_1h == 4
    assert signals.incoming_transfers_to_beneficiary_1h == 4


def test_scored_event_never_counts_itself() -> None:
    graph = builder()
    scored = transfer(occurred_at=T0)
    graph.observe(scored)

    signals = graph.signals_for(scored)

    assert signals.incoming_transfers_to_beneficiary_1h == 0
    assert signals.unique_senders_to_beneficiary_1h == 0


def test_shared_device_and_confirmed_fraud_neighbors_are_counted() -> None:
    graph = builder()
    graph.observe(
        transfer(
            sender_account_id="mule-account-1",
            device_id="device-x",
            occurred_at=T0 - timedelta(hours=5),
        )
    )
    graph.observe(
        transfer(
            sender_account_id="mule-account-2",
            beneficiary_id="other-beneficiary",
            device_id="device-x",
            occurred_at=T0 - timedelta(hours=3),
        )
    )
    graph.observe(
        transfer(
            sender_account_id="fraud-account",
            occurred_at=T0 - timedelta(days=10),
        )
    )

    signals = graph.signals_for(
        transfer(device_id="device-x", occurred_at=T0),
        confirmed_fraud_accounts=frozenset({"fraud-account"}),
    )

    assert signals.distinct_accounts_on_device_24h == 2
    assert signals.confirmed_fraud_neighbors_30d == 1


def test_rapid_outbound_movement_only_observable_for_internal_beneficiary() -> None:
    graph = builder()
    graph.observe(
        transfer(
            beneficiary_id="internal-mule",
            beneficiary_type=BeneficiaryType.INTERNAL,
            destination_institution_id=None,
            amount=Decimal("1000.00"),
            occurred_at=T0 - timedelta(minutes=40),
        )
    )
    graph.observe(
        transfer(
            sender_customer_id="mule-owner",
            sender_account_id="internal-mule",
            beneficiary_id="cash-out",
            amount=Decimal("900.00"),
            occurred_at=T0 - timedelta(minutes=20),
        )
    )

    internal = graph.signals_for(
        transfer(
            beneficiary_id="internal-mule",
            beneficiary_type=BeneficiaryType.INTERNAL,
            destination_institution_id=None,
            occurred_at=T0,
        )
    )
    external = graph.signals_for(transfer(occurred_at=T0))

    assert internal.rapid_outbound_ratio_1h == pytest.approx(0.9)
    assert external.rapid_outbound_ratio_1h is None


def test_repeat_victims_and_shared_sender_cluster_are_detected() -> None:
    graph = builder()
    for days_ago in (9, 5):
        graph.observe(
            transfer(
                sender_customer_id="repeat-victim",
                sender_account_id="repeat-account",
                occurred_at=T0 - timedelta(days=days_ago),
            )
        )
    graph.observe(
        transfer(
            sender_customer_id="repeat-victim",
            sender_account_id="repeat-account",
            beneficiary_id="cluster-beneficiary",
            occurred_at=T0 - timedelta(days=4),
        )
    )
    graph.observe(
        transfer(
            sender_customer_id="single-victim",
            sender_account_id="single-account",
            occurred_at=T0 - timedelta(days=2),
        )
    )
    graph.observe(
        transfer(
            sender_customer_id="single-victim",
            sender_account_id="single-account",
            beneficiary_id="other-beneficiary",
            occurred_at=T0 - timedelta(days=1),
        )
    )

    signals = graph.signals_for(transfer(occurred_at=T0))

    assert signals.repeat_senders_to_beneficiary_30d == 1
    assert signals.linked_beneficiaries_via_shared_senders_30d == 2


def test_signals_carry_event_time_tenant_provenance() -> None:
    graph = builder()

    signals = graph.signals_for(transfer(occurred_at=T0))

    assert signals.provenance.source == IntelligenceSource.TENANT_NETWORK
    assert signals.provenance.scope == IntelligenceScope.TENANT_OBSERVED
    assert signals.provenance.observed_at == T0
    assert signals.provenance.source_version == "internal-graph-features-2"
