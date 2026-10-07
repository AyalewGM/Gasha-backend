from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import NAMESPACE_URL, uuid5

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    IntelligenceSnapshot,
)
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
)
from gasha.poc.outcomes import IncumbentControlOutcome

CAMPAIGN_BASE_TIME = datetime(2026, 2, 12, 9, 0, 0, tzinfo=UTC)


def _event(
    campaign: str,
    name: str,
    *,
    tenant_id: str,
    at: datetime,
    sender: str,
    beneficiary: str,
    amount: str,
    intelligence: IntelligenceSnapshot,
    is_fraud: bool,
    incumbent: IncumbentControlOutcome,
    evidence_reason_codes: tuple[str, ...] = (),
    signal_policy_versions: tuple[str, ...] = (),
) -> HistoricalTransactionEvent:
    transaction = CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid5(NAMESPACE_URL, f"gasha://campaign/{campaign}/{name}"),
        occurred_at=at,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal(amount),
        currency="ETB",
        sender_customer_id=f"synthetic-customer-{name}",
        sender_account_id=f"synthetic-account-{sender}",
        beneficiary_id=f"synthetic-beneficiary-{beneficiary}",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="synthetic-destination",
        correlation_id=f"synthetic-corr-{campaign}-{name}",
    )
    return HistoricalTransactionEvent(
        transaction=transaction,
        intelligence=intelligence,
        evidence_reason_codes=evidence_reason_codes,
        signal_policy_versions=signal_policy_versions,
        label=ConfirmedOutcomeLabel(
            is_fraud=is_fraud,
            label_source="synthetic-campaign",
            confirmed_at=at + timedelta(days=7),
        ),
        incumbent_outcome=incumbent,
    )


def social_engineering_campaign(
    *,
    tenant_id: str = "tenant-a",
    base_time: datetime = CAMPAIGN_BASE_TIME,
    campaign_id: str = "epic3-campaign-1",
) -> tuple[HistoricalTransactionEvent, ...]:
    """A deterministic synthetic social-engineering campaign dataset.

    Covers the five Epic 3 campaign scenarios plus legitimate controls with
    deliberately ambiguous mid-range signals — not every fraud case trips an
    alert and not every legitimate case is risk-free, so replay metrics are
    meaningful rather than degenerate. Incumbent outcomes model a plausible
    existing-control mix: catches some mule/ATO patterns, misses coached and
    impersonation payments.
    """

    versions = (
        "social-engineering-4",
        "behavioral-policy-2",
        "graph-policy-5",
    )
    t = base_time

    def step(minutes: int = 20) -> datetime:
        nonlocal t
        t = t + timedelta(minutes=minutes)
        return t

    events = [
        # Scenario 1 — emergency impersonation: new beneficiary, unusual
        # amount, hesitation. Strong variant detects; weak variant misses.
        _event(
            campaign_id,
            "emergency-impersonation-strong",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-e1",
            beneficiary="emergency-new",
            amount="4800.00",
            intelligence=IntelligenceSnapshot(
                relationship_risk=0.84,
                transaction_risk=0.76,
                device_session_risk=0.66,
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            evidence_reason_codes=(
                "NEW_BENEFICIARY",
                "AMOUNT_ABOVE_SENDER_BASELINE",
            ),
            signal_policy_versions=versions,
        ),
        _event(
            campaign_id,
            "emergency-impersonation-weak",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-e2",
            beneficiary="emergency-new-2",
            amount="900.00",
            intelligence=IntelligenceSnapshot(
                relationship_risk=0.58, transaction_risk=0.52
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            signal_policy_versions=versions,
        ),
        # Scenario 2 — fake bank/support call: active coaching vs partial
        # telemetry.
        _event(
            campaign_id,
            "support-call-coached",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-c1",
            beneficiary="refund-mule",
            amount="6200.00",
            intelligence=IntelligenceSnapshot(
                device_session_risk=0.93, relationship_risk=0.72
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            evidence_reason_codes=(
                "ACTIVE_CALL_DURING_PAYMENT",
                "REMOTE_ACCESS_INDICATOR",
                "POSSIBLE_LIVE_COACHING_PATTERN",
            ),
            signal_policy_versions=versions,
        ),
        _event(
            campaign_id,
            "support-call-partial-telemetry",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-c2",
            beneficiary="refund-mule-2",
            amount="3100.00",
            intelligence=IntelligenceSnapshot(device_session_risk=0.55),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            signal_policy_versions=versions,
        ),
        # Scenario 3 — compromised contact: payment request appears to come
        # from a known person but to an unfamiliar beneficiary.
        _event(
            campaign_id,
            "compromised-contact",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-k1",
            beneficiary="contact-lookalike",
            amount="1400.00",
            intelligence=IntelligenceSnapshot(
                relationship_risk=0.78, transaction_risk=0.62
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.ALERT,
            evidence_reason_codes=("NO_PRIOR_SENDER_BENEFICIARY_HISTORY",),
            signal_policy_versions=versions,
        ),
        # Scenario 4 — SIM-swap-like takeover: derived device/session
        # indicators only; no telecom integration.
        _event(
            campaign_id,
            "sim-swap-takeover",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-s1",
            beneficiary="takeover-out",
            amount="5500.00",
            intelligence=IntelligenceSnapshot(
                device_session_risk=0.80, transaction_risk=0.74
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.REVIEW,
            evidence_reason_codes=(
                "NEW_DEVICE_FOR_SENDER",
                "BEHAVIORAL_BIOMETRIC_ANOMALY",
            ),
            signal_policy_versions=versions,
        ),
        # Scenario 5 — mule aggregation: fan-in, repeat victims, cluster,
        # rapid onward movement. Two detected, one marginal miss.
        _event(
            campaign_id,
            "mule-aggregation-core",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-m1",
            beneficiary="mule-hub-1",
            amount="2750.00",
            intelligence=IntelligenceSnapshot(
                beneficiary_risk=0.88, network_risk=0.96
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.HOLD,
            evidence_reason_codes=(
                "INTERNAL_GRAPH_BENEFICIARY_FAN_IN",
                "INTERNAL_GRAPH_REPEAT_VICTIM_SENDERS",
                "INTERNAL_GRAPH_POSSIBLE_MULE_CLUSTER",
            ),
            signal_policy_versions=versions,
        ),
        _event(
            campaign_id,
            "mule-aggregation-weak-network",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-m2",
            beneficiary="mule-hub-2",
            amount="1800.00",
            intelligence=IntelligenceSnapshot(
                beneficiary_risk=0.71, network_risk=0.58
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            signal_policy_versions=versions,
        ),
        _event(
            campaign_id,
            "mule-aggregation-marginal",
            tenant_id=tenant_id,
            at=step(),
            sender="victim-m3",
            beneficiary="mule-hub-3",
            amount="950.00",
            intelligence=IntelligenceSnapshot(
                beneficiary_risk=0.69, velocity_risk=0.55
            ),
            is_fraud=True,
            incumbent=IncumbentControlOutcome.ALERT,
            signal_policy_versions=versions,
        ),
        # Legitimate controls — including deliberately ambiguous cases.
        _event(
            campaign_id,
            "legit-established-beneficiary",
            tenant_id=tenant_id,
            at=step(),
            sender="legit-1",
            beneficiary="landlord",
            amount="1200.00",
            intelligence=IntelligenceSnapshot(
                relationship_risk=0.08, transaction_risk=0.15
            ),
            is_fraud=False,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            signal_policy_versions=versions,
        ),
        _event(
            campaign_id,
            "legit-urgent-large-payment",
            tenant_id=tenant_id,
            at=step(),
            sender="legit-2",
            beneficiary="contractor",
            amount="7200.00",
            intelligence=IntelligenceSnapshot(
                transaction_risk=0.74, device_session_risk=0.55
            ),
            is_fraud=False,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            signal_policy_versions=versions,
        ),
        _event(
            campaign_id,
            "legit-new-device",
            tenant_id=tenant_id,
            at=step(),
            sender="legit-3",
            beneficiary="utilities",
            amount="310.00",
            intelligence=IntelligenceSnapshot(device_session_risk=0.58),
            is_fraud=False,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            signal_policy_versions=versions,
        ),
        _event(
            campaign_id,
            "legit-repeat-payroll",
            tenant_id=tenant_id,
            at=step(),
            sender="legit-4",
            beneficiary="payroll",
            amount="2600.00",
            intelligence=IntelligenceSnapshot(
                relationship_risk=0.12, velocity_risk=0.30
            ),
            is_fraud=False,
            incumbent=IncumbentControlOutcome.NO_ALERT,
            signal_policy_versions=versions,
        ),
    ]
    return tuple(events)
