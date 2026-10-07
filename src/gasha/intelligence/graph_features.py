from __future__ import annotations

from collections.abc import Set as AbstractSet
from datetime import datetime, timedelta
from decimal import Decimal

from gasha.domain.models import BeneficiaryType, CanonicalTransaction
from gasha.intelligence.internal_graph import InternalGraphSignals
from gasha.intelligence.provenance import (
    IntelligenceScope,
    IntelligenceSource,
    SignalProvenance,
)

ONE_HOUR = timedelta(hours=1)
TWENTY_FOUR_HOURS = timedelta(hours=24)
THIRTY_DAYS = timedelta(days=30)


class TenantIsolationViolation(ValueError):
    """Raised when a tenant-scoped feature store receives another tenant's data."""


class TenantGraphFeatureBuilder:
    """Derives tenant-internal graph signals from the tenant's own transactions.

    The builder only ingests transactions for its configured ``tenant_id`` and
    computes point-in-time aggregates at each scored transaction's
    ``occurred_at``, using only strictly earlier events. Real-time callers score
    before observing the current transaction; historical replay therefore
    cannot leak future events into a decision.
    """

    def __init__(self, tenant_id: str, *, source_version: str) -> None:
        self.tenant_id = tenant_id
        self.source_version = source_version
        self._events: list[CanonicalTransaction] = []

    def observe(self, transaction: CanonicalTransaction) -> None:
        if transaction.tenant_id != self.tenant_id:
            raise TenantIsolationViolation(
                "tenant graph feature builder cannot observe cross-tenant events"
            )
        self._events.append(transaction)

    def signals_for(
        self,
        transaction: CanonicalTransaction,
        *,
        confirmed_fraud_accounts: AbstractSet[str] = frozenset(),
    ) -> InternalGraphSignals:
        if transaction.tenant_id != self.tenant_id:
            raise TenantIsolationViolation(
                "tenant graph feature builder cannot score cross-tenant events"
            )

        observed_at = transaction.occurred_at
        prior = [event for event in self._events if event.occurred_at < observed_at]
        beneficiary = transaction.beneficiary_id

        inbound_1h = [
            event
            for event in prior
            if event.beneficiary_id == beneficiary
            and event.occurred_at >= observed_at - ONE_HOUR
        ]
        inbound_30d = [
            event
            for event in prior
            if event.beneficiary_id == beneficiary
            and event.occurred_at >= observed_at - THIRTY_DAYS
        ]

        device_accounts: set[str] = set()
        if transaction.device_id is not None:
            device_accounts = {
                event.sender_account_id
                for event in prior
                if event.device_id == transaction.device_id
                and event.occurred_at >= observed_at - TWENTY_FOUR_HOURS
            }

        neighbor_accounts = {event.sender_account_id for event in inbound_30d}
        if transaction.device_id is not None:
            neighbor_accounts |= {
                event.sender_account_id
                for event in prior
                if event.device_id == transaction.device_id
                and event.occurred_at >= observed_at - THIRTY_DAYS
            }
        fraud_neighbors = len(neighbor_accounts & set(confirmed_fraud_accounts))

        sender_counts: dict[str, int] = {}
        for event in inbound_30d:
            sender_counts[event.sender_customer_id] = (
                sender_counts.get(event.sender_customer_id, 0) + 1
            )
        repeat_senders = sum(1 for count in sender_counts.values() if count >= 2)

        beneficiary_senders = set(sender_counts)
        linked_beneficiaries = {
            event.beneficiary_id
            for event in prior
            if event.sender_customer_id in beneficiary_senders
            and event.beneficiary_id != beneficiary
            and event.occurred_at >= observed_at - THIRTY_DAYS
        }

        return InternalGraphSignals(
            unique_senders_to_beneficiary_1h=len(
                {event.sender_customer_id for event in inbound_1h}
            ),
            incoming_transfers_to_beneficiary_1h=len(inbound_1h),
            distinct_accounts_on_device_24h=len(device_accounts),
            confirmed_fraud_neighbors_30d=fraud_neighbors,
            repeat_senders_to_beneficiary_30d=repeat_senders,
            linked_beneficiaries_via_shared_senders_30d=len(linked_beneficiaries),
            rapid_outbound_ratio_1h=self._rapid_outbound_ratio(
                transaction, prior, observed_at
            ),
            provenance=SignalProvenance(
                source=IntelligenceSource.TENANT_NETWORK,
                scope=IntelligenceScope.TENANT_OBSERVED,
                observed_at=observed_at,
                source_version=self.source_version,
            ),
        )

    @staticmethod
    def _rapid_outbound_ratio(
        transaction: CanonicalTransaction,
        prior: list[CanonicalTransaction],
        observed_at: datetime,
    ) -> float | None:
        """Share of the last hour's inbound value already re-sent onward.

        Only observable when the beneficiary account is internal to the tenant.
        External beneficiaries return None so unavailable onward-movement
        visibility never fabricates risk.
        """
        if transaction.beneficiary_type != BeneficiaryType.INTERNAL:
            return None
        beneficiary = transaction.beneficiary_id
        inbound_total = sum(
            (
                event.amount
                for event in prior
                if event.beneficiary_id == beneficiary
                and event.occurred_at >= observed_at - ONE_HOUR
            ),
            Decimal(0),
        )
        if inbound_total == 0:
            return 0.0
        outbound_total = sum(
            (
                event.amount
                for event in prior
                if event.sender_account_id == beneficiary
                and event.occurred_at >= observed_at - ONE_HOUR
            ),
            Decimal(0),
        )
        return float(min(outbound_total, inbound_total) / inbound_total)
