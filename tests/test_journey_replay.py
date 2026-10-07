from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)
from gasha.journey.events import (
    BeneficiarySubtype,
    JourneyEvent,
    JourneyEventKind,
)
from gasha.journey.policy import JourneyRiskPolicy
from gasha.poc.ablation import (
    IncrementalDetectionReason,
    run_ablation,
)
from gasha.poc.attribution import SignalFamily, attribute_signals
from gasha.poc.historical import (
    ConfirmedOutcomeLabel,
    HistoricalTransactionEvent,
)
from gasha.poc.journey_campaigns import uc3_journey_campaign
from gasha.poc.journey_replay import replay_journey_scenario

TENANT = "tenant-a"


def _journey(
    kind: JourneyEventKind,
    subtype: str,
    *,
    tenant_id: str = TENANT,
    customer_id: str = "cust-1",
    at: datetime,
    **refs: str,
) -> JourneyEvent:
    return JourneyEvent(
        tenant_id=tenant_id,
        event_id=uuid4(),
        kind=kind,
        subtype=subtype,
        occurred_at=at,
        customer_id=customer_id,
        **refs,
    )


def _payment_tx(
    *,
    tenant_id: str = TENANT,
    customer_id: str = "cust-1",
    at: datetime,
    is_fraud: bool,
    intelligence: IntelligenceSnapshot | None = None,
) -> HistoricalTransactionEvent:
    tx = CanonicalTransaction(
        tenant_id=tenant_id,
        event_id=uuid4(),
        occurred_at=at,
        channel="mobile",
        transaction_type="transfer",
        amount=Decimal("900.00"),
        currency="ETB",
        sender_customer_id=customer_id,
        sender_account_id="acct-1",
        beneficiary_id="ben-1",
        beneficiary_type=BeneficiaryType.EXTERNAL,
        destination_institution_id="sim-destination",
        correlation_id="corr-1",
    )
    return HistoricalTransactionEvent(
        transaction=tx,
        intelligence=intelligence or IntelligenceSnapshot(),
        label=ConfirmedOutcomeLabel(
            is_fraud=is_fraud, label_source="test"
        ),
    )


def _policy() -> DecisionPolicy:
    return DecisionPolicy(
        configuration_version="tenant-config-1",
        policy_version="policy-1",
        rule_version="rules-1",
    )


def _journey_policy() -> JourneyRiskPolicy:
    return JourneyRiskPolicy(
        configuration_version="journey-config-1",
        policy_version="journey-v1",
    )


class TestUc3JourneyCampaign:
    def test_ato_scenarios_alert_on_journey_context(self):
        report = replay_journey_scenario(
            uc3_journey_campaign(),
            {TENANT: _policy()},
            {TENANT: _journey_policy()},
        )
        decisions = {
            r.event.transaction.correlation_id: r.decision
            for r in report.results
        }
        # Full ATO chain (fails->login->device->cred->ben->pay) blocks.
        assert (
            decisions["uc3-ato-full"].action == DecisionAction.BLOCK
        )
        # Profile change -> beneficiary -> transfer holds.
        assert (
            decisions["uc3-ato-profile"].action == DecisionAction.HOLD
        )

    def test_legit_lookalikes_stay_below_review(self):
        report = replay_journey_scenario(
            uc3_journey_campaign(),
            {TENANT: _policy()},
            {TENANT: _journey_policy()},
        )
        for cid in [
            "uc3-legit-newphone",
            "uc3-legit-reset",
            "uc3-legit-family",
            "uc3-legit-typo",
            "uc3-legit-profile",
        ]:
            decision = next(
                r.decision
                for r in report.results
                if r.event.transaction.correlation_id == cid
            )
            assert decision.action in {
                DecisionAction.ALLOW,
                DecisionAction.MONITOR,
            }, cid


class TestJourneyTemporalCorrectness:
    def test_future_events_never_leak_into_earlier_decisions(self):
        base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
        payment = _payment_tx(
            at=base, is_fraud=False
        )
        # Suspicious events all occur AFTER the payment — identical
        # payment without them must produce the same decision.
        late = [
            _journey(
                JourneyEventKind.ACCOUNT_SECURITY,
                "credential_changed",
                at=base + timedelta(minutes=5),
            ),
            _journey(
                JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                at=base + timedelta(minutes=6),
                beneficiary_id="ben-late",
            ),
        ]
        policies = {TENANT: _policy()}
        journeys = {TENANT: _journey_policy()}
        before = replay_journey_scenario(
            [payment], policies, journeys
        )
        after = replay_journey_scenario(
            [payment, *late], policies, journeys
        )
        assert (
            before.results[0].decision.action
            == after.results[0].decision.action
        )

    def test_out_of_order_input_is_sorted_by_occurred_at(self):
        base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
        events = [
            _journey(
                JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                at=base - timedelta(minutes=30),
                beneficiary_id="ben-x",
            ),
            _journey(
                JourneyEventKind.ACCOUNT_SECURITY,
                "credential_changed",
                at=base - timedelta(hours=2),
            ),
        ]
        payment = _payment_tx(at=base, is_fraud=True)
        # Deliberately reversed ordering in the input stream.
        shuffled = [*reversed(events), payment]
        ordered = [*events, payment]
        policies = {TENANT: _policy()}
        journeys = {TENANT: _journey_policy()}
        a = replay_journey_scenario(shuffled, policies, journeys)
        b = replay_journey_scenario(ordered, policies, journeys)
        assert (
            a.results[0].decision.action == b.results[0].decision.action
        )
        assert (
            a.results[0].decision.risk_score
            == b.results[0].decision.risk_score
        )

    def test_journey_events_do_not_leak_across_tenants(self):
        base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
        other_tenant_events = [
            _journey(
                JourneyEventKind.ACCOUNT_SECURITY,
                "credential_changed",
                tenant_id="tenant-b",
                at=base - timedelta(hours=1),
            ),
            _journey(
                JourneyEventKind.BENEFICIARY,
                BeneficiarySubtype.CREATED.value,
                tenant_id="tenant-b",
                at=base - timedelta(minutes=30),
                beneficiary_id="ben-b",
            ),
        ]
        payment = _payment_tx(at=base, is_fraud=False)
        policies = {
            TENANT: _policy(),
            "tenant-b": DecisionPolicy(
                configuration_version="tenant-b-config-1",
                policy_version="policy-b",
                rule_version="rules-b",
            ),
        }
        journeys = {
            TENANT: _journey_policy(),
            "tenant-b": JourneyRiskPolicy(
                configuration_version="journey-b-config-1",
                policy_version="journey-b",
            ),
        }
        report = replay_journey_scenario(
            [*other_tenant_events, payment], policies, journeys
        )
        assert (
            report.results[0].decision.action == DecisionAction.ALLOW
        )
        assert (
            "HIGH_JOURNEY_RISK"
            not in report.results[0].decision.reason_codes
        )


class TestJourneyAttributionAndAblation:
    def _campaign_report(self):
        return replay_journey_scenario(
            uc3_journey_campaign(),
            {TENANT: _policy()},
            {TENANT: _journey_policy()},
        )

    def test_journey_family_appears_in_attribution(self):
        report = self._campaign_report()
        attribution = attribute_signals(
            report.results, {TENANT: _policy()}
        )
        assert SignalFamily.JOURNEY in attribution.families
        journey = attribution.families[SignalFamily.JOURNEY]
        assert journey.alerts_influenced > 0
        assert journey.true_positives_influenced > 0

    def test_journey_is_incrementally_necessary_for_ato_detections(self):
        report = self._campaign_report()
        events = [result.event for result in report.results]
        ablation = run_ablation(events, {TENANT: _policy()})
        without_journey = next(
            comparison
            for comparison in ablation.comparisons
            if comparison.configuration_name == "without_journey"
        )
        assert without_journey.detections_lost > 0
        assert without_journey.recall_delta < 0
        reasons = {
            detection.reason
            for detection in ablation.unique_detections
        }
        assert (
            IncrementalDetectionReason.JOURNEY_INCREMENTAL_DETECTION
            in reasons
        )


class TestJourneyReplayDeterminism:
    def test_same_campaign_replayed_twice_is_identical(self):
        policies = {TENANT: _policy()}
        journeys = {TENANT: _journey_policy()}
        first = replay_journey_scenario(
            uc3_journey_campaign(), policies, journeys
        )
        second = replay_journey_scenario(
            uc3_journey_campaign(), policies, journeys
        )
        # decided_at/decision_latency are wall-clock; the decision
        # content itself must be bit-for-bit identical.
        def signature(result):
            decision = result.decision.model_copy(
                update={"decided_at": None}
            )
            return (decision, result.classification)

        assert [signature(r) for r in first.results] == [
            signature(r) for r in second.results
        ]
