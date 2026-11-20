"""Versioned rule authoring and rules-aware decision tests."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID
from typing import Any

import pytest

from gasha.decision.rules import (
    PolicyRule,
    RuleEffect,
    RulePredicate,
    RulesAwareDecisionService,
    RuleSet,
    RuleValidationError,
    rule_set_digest,
)
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    IntelligenceSnapshot,
)

POLICY = DecisionPolicy(
    configuration_version="cfg-v1",
    policy_version="rules-v1",
    rule_version="tenant-rules-v1",
)


def tx(**overrides: object) -> CanonicalTransaction:
    base = {
        "tenant_id": "tenant-a",
        "event_id": UUID(int=1),
        "occurred_at": datetime(2026, 1, 5, 3, tzinfo=UTC),  # Monday 03:00 UTC
        "channel": "mobile",
        "transaction_type": "transfer",
        "amount": Decimal(500),
        "currency": "ETB",
        "sender_customer_id": "customer-1",
        "sender_account_id": "account-1",
        "beneficiary_id": "beneficiary-1",
        "beneficiary_type": BeneficiaryType.EXTERNAL,
        "destination_institution_id": "external-bank",
        "correlation_id": "corr-1",
    }
    return CanonicalTransaction(**{**base, **overrides})


def rule(
    rule_id: str,
    predicates: list[dict[str, object]],
    *,
    min_score: float | None = None,
    force_action: DecisionAction | None = None,
    enabled: bool = True,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        description=f"rule {rule_id}",
        enabled=enabled,
        predicates=tuple(RulePredicate(**p) for p in predicates),  # type: ignore[arg-type]
        effect=RuleEffect(min_score=min_score, force_action=force_action),
    )


def ruleset(*rules: PolicyRule, version: str = "tenant-rules-v1") -> RuleSet:
    return RuleSet(tenant_id="tenant-a", rule_set_version=version, rules=rules)


def service(
    policy: DecisionPolicy, authored: RuleSet, backend: Any = None
) -> RulesAwareDecisionService:
    return RulesAwareDecisionService(
        policy, authored, backend=backend, tenant_id="tenant-a",
        expected_ruleset_digest=rule_set_digest(authored),
    )


# ---------------- validation ----------------


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValueError, match="unknown predicate field"):
        RulePredicate(field="sender_age", op="eq", value=3)


def test_ordered_ops_reject_string_fields() -> None:
    with pytest.raises(ValueError, match="numeric-only"):
        RulePredicate(field="channel", op="gt", value="mobile")


def test_in_requires_list() -> None:
    with pytest.raises(ValueError, match="list"):
        RulePredicate(field="channel", op="in", value="mobile")


def test_scalar_ops_reject_list() -> None:
    with pytest.raises(ValueError, match="scalar"):
        RulePredicate(field="channel", op="eq", value=["mobile"])


def test_type_mismatch_rejected() -> None:
    with pytest.raises(ValueError, match="finite number"):
        RulePredicate(field="amount", op="gt", value="five hundred")


def test_effect_requires_something() -> None:
    with pytest.raises(ValueError, match="min_score or force_action"):
        RuleEffect()


def test_effect_rejects_shadow_action() -> None:
    with pytest.raises(ValueError, match="shadow"):
        RuleEffect(force_action=DecisionAction.NO_ACTION_SHADOW)


def test_duplicate_rule_ids_rejected() -> None:
    r = rule("dup", [{"field": "amount", "op": "gt", "value": 1}], min_score=0.5)
    with pytest.raises(ValueError, match="duplicate"):
        ruleset(r, r)


def test_untaggable_ids_rejected() -> None:
    with pytest.raises(ValueError):
        rule("bad id!", [{"field": "amount", "op": "gt", "value": 1}], min_score=0.5)
    with pytest.raises(ValueError):
        RuleSet(rule_set_version="bad version!", rules=())


# ---------------- evaluation ----------------


def test_min_score_floors_the_decision() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "high_amount",
                [{"field": "amount", "op": "gt", "value": 100}],
                min_score=0.80,
            )
        ),
    )
    decision = service.decide(tx(), IntelligenceSnapshot())
    assert decision.action == DecisionAction.REVIEW
    assert decision.risk_score == pytest.approx(0.80)
    assert "RULE_high_amount" in decision.reason_codes


def test_force_action_escalates_beyond_mapped() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "deny_channel",
                [{"field": "channel", "op": "eq", "value": "mobile"}],
                force_action=DecisionAction.BLOCK,
            )
        ),
    )
    decision = service.decide(tx(), IntelligenceSnapshot())
    assert decision.action == DecisionAction.BLOCK
    assert decision.risk_score == pytest.approx(0.0)  # score untouched by force
    assert "RULE_deny_channel" in decision.reason_codes


def test_rules_never_downgrade() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "would_be_allow",
                [{"field": "amount", "op": "gt", "value": 1}],
                force_action=DecisionAction.ALLOW,
            )
        ),
    )
    decision = service.decide(tx(), IntelligenceSnapshot(transaction_risk=0.97))
    assert decision.action == DecisionAction.BLOCK


def test_strongest_force_wins() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "rev",
                [{"field": "amount", "op": "gt", "value": 1}],
                force_action=DecisionAction.REVIEW,
            ),
            rule(
                "blk",
                [{"field": "currency", "op": "eq", "value": "ETB"}],
                force_action=DecisionAction.BLOCK,
            ),
        ),
    )
    decision = service.decide(tx(), IntelligenceSnapshot())
    assert decision.action == DecisionAction.BLOCK
    assert {"RULE_rev", "RULE_blk"} <= set(decision.reason_codes)


def test_and_predicates_all_required() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "night_mobile",
                [
                    {"field": "channel", "op": "eq", "value": "mobile"},
                    {"field": "hour_of_day", "op": "lt", "value": 6},
                ],
                min_score=0.9,
            )
        ),
    )
    # 03:00 UTC Monday — matches.
    assert service.decide(tx(), IntelligenceSnapshot()).risk_score == 0.9
    # 09:00 — does not match.
    day_tx = tx(occurred_at=datetime(2026, 1, 5, 9, tzinfo=UTC))
    assert service.decide(day_tx, IntelligenceSnapshot()).action == DecisionAction.ALLOW


def test_in_operator_and_signal_field() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "watchlist_channel",
                [
                    {"field": "channel", "op": "in", "value": ["mobile", "ussd"]},
                    {"field": "velocity_risk", "op": "ge", "value": 0.5},
                ],
                force_action=DecisionAction.REVIEW,
            )
        ),
    )
    assert service.decide(
        tx(), IntelligenceSnapshot(velocity_risk=0.6)
    ).action == DecisionAction.REVIEW
    assert service.decide(
        tx(), IntelligenceSnapshot(velocity_risk=0.2)
    ).action == DecisionAction.ALLOW


def test_missing_optional_field_never_matches() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "institution_rule",
                [
                    {
                        "field": "destination_institution_id",
                        "op": "eq",
                        "value": "other-bank",
                    }
                ],
                force_action=DecisionAction.BLOCK,
            )
        ),
    )
    decision = service.decide(tx(), IntelligenceSnapshot())
    assert decision.action == DecisionAction.ALLOW


def test_disabled_rules_do_not_fire() -> None:
    service = service(
        POLICY,
        ruleset(
            rule(
                "off",
                [{"field": "amount", "op": "gt", "value": 1}],
                force_action=DecisionAction.BLOCK,
                enabled=False,
            )
        ),
    )
    assert service.decide(tx(), IntelligenceSnapshot()).action == DecisionAction.ALLOW


def test_version_binding_enforced() -> None:
    with pytest.raises(RuleValidationError, match="rule_version"):
        service(
            POLICY, ruleset(version="other-rules-v9")
        )


def test_injected_backend_is_respected() -> None:
    class DenyBackend:
        def decide(self, transaction, intelligence, evidence_reason_codes=()):
            base = service(
                POLICY, ruleset()
            ).decide(transaction, intelligence, evidence_reason_codes)
            return base.model_copy(update={"action": DecisionAction.BLOCK, "risk_score": 1.0})

    service = service(
        POLICY,
        ruleset(
            rule(
                "r1",
                [{"field": "amount", "op": "gt", "value": 1}],
                min_score=0.6,
            )
        ),
        backend=DenyBackend(),
    )
    decision = service.decide(tx(), IntelligenceSnapshot())
    assert decision.action == DecisionAction.BLOCK  # backend wins; floor can't downgrade


@pytest.mark.parametrize("bad", [True, False, [True, 1], [0, False]])
def test_predicate_rejects_bool_before_coercion(bad: object) -> None:
    with pytest.raises(ValueError, match="boolean"):
        RulePredicate(
            field="amount", op="in" if isinstance(bad, list) else "gt", value=bad
        )


@pytest.mark.parametrize("original", [DecisionAction.BLOCK, DecisionAction.HOLD])
def test_rule_floor_preserves_stronger_upstream_action(original: DecisionAction) -> None:
    class StrongBackend:
        def decide(self, transaction, intelligence, evidence_reason_codes=()):
            base = service(POLICY, ruleset()).decide(
                transaction, intelligence, evidence_reason_codes
            )
            return base.model_copy(update={"action": original, "risk_score": 0.1})

    authored = ruleset(rule(
        "low_floor", [{"field": "amount", "op": "gt", "value": 1}], min_score=0.2
    ))
    result = service(POLICY, authored, backend=StrongBackend()).decide(
        tx(), IntelligenceSnapshot()
    )
    assert result.action is original
    assert result.risk_score == pytest.approx(0.2)


@pytest.mark.parametrize("changed", [
    {"configuration_version": "foreign-cfg"},
    {"policy_version": "foreign-policy"},
    {"rule_version": "foreign-rules"},
    {"model_version": "foreign-model"},
    {"tenant_id": "tenant-b"},
    {"correlation_id": "other-correlation"},
    {"event_id": UUID(int=2)},
    {"action": DecisionAction.NO_ACTION_SHADOW},
])
def test_rejects_foreign_backend_provenance_or_shadow(
    changed: dict[str, object]
) -> None:
    class ForeignBackend:
        def decide(self, transaction, intelligence, evidence_reason_codes=()):
            base = service(POLICY, ruleset()).decide(
                transaction, intelligence, evidence_reason_codes
            )
            return base.model_copy(update=changed)

    with pytest.raises(RuleValidationError):
        service(POLICY, ruleset(), backend=ForeignBackend()).decide(
            tx(), IntelligenceSnapshot()
        )


def test_tenant_and_digest_binding_rejects_substitution() -> None:
    foreign = RuleSet(
        tenant_id="tenant-b", rule_set_version=POLICY.rule_version,
        rules=(rule(
            "other", [{"field": "amount", "op": "gt", "value": 1}],
            force_action=DecisionAction.BLOCK,
        ),),
    )
    with pytest.raises(RuleValidationError, match="tenant"):
        service(POLICY, foreign)
    correct = ruleset()
    with pytest.raises(RuleValidationError, match="digest"):
        RulesAwareDecisionService(
            POLICY, correct, tenant_id="tenant-a",
            expected_ruleset_digest=rule_set_digest(foreign),
        )
    with pytest.raises(RuleValidationError, match="tenant"):
        service(POLICY, correct).decide(
            tx(tenant_id="tenant-b"), IntelligenceSnapshot()
        )


def test_rule_snapshot_resists_mutation_of_authored_object() -> None:
    authored = ruleset(rule(
        "only_low", [{"field": "amount", "op": "gt", "value": 1}], min_score=0.6
    ))
    guarded = service(POLICY, authored)
    authored.rules[0].effect.min_score = 1.0
    result = guarded.decide(tx(), IntelligenceSnapshot())
    assert result.risk_score == pytest.approx(0.6)


def test_challenge_force_rejects_missing_channel_policy() -> None:
    authored = ruleset(rule(
        "stepup", [{"field": "amount", "op": "gt", "value": 1}],
        force_action=DecisionAction.CHALLENGE,
    ))
    with pytest.raises(RuleValidationError, match="CHALLENGE"):
        service(POLICY, authored).decide(tx(), IntelligenceSnapshot())
