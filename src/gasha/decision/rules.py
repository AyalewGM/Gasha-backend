"""Versioned per-tenant rule authoring and evaluation.

A ``RuleSet`` is an auditable, versioned collection of ``PolicyRule``s. Each
rule is an AND-ed set of predicates over a whitelist of canonical transaction
fields and intelligence signals; rules are OR-ed — any match applies. Effects
can *floor* the fused score (``min_score``) or *force* an escalation action
(``force_action``). v1 rules can only escalate risk — they never downgrade a
decision; suppression belongs to the governed risk-list surface.

A bound ``RuleSet`` *is* the policy's rules: ``RulesAwareDecisionService``
requires ``rule_set.rule_version == policy.rule_version`` so a decision can
never carry rule provenance for a different authored version.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from math import isfinite
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    BeneficiaryType,
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
    RiskScore,
)

RULESET_SCHEMA_VERSION = "gasha-ruleset-1"
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class RuleValidationError(ValueError):
    """A rule set, rule, predicate or effect is malformed or untrustworthy."""


class RuleOperator(StrEnum):
    EQ = "eq"
    NEQ = "neq"
    IN = "in"
    GT = "gt"
    GE = "ge"
    LT = "lt"
    LE = "le"


# Fields a predicate may reference, with their comparison domain.
# Intelligence signals share the namespace; transaction fields are explicit.
_FIELD_TYPES: dict[str, str] = {
    "amount": "number",
    "hour_of_day": "number",
    "day_of_week": "number",
    "channel": "string",
    "transaction_type": "string",
    "currency": "string",
    "beneficiary_type": "string",
    "destination_institution_id": "string",
    "has_device_id": "number",
    "is_external_beneficiary": "number",
    **{name: "number" for name in IntelligenceSnapshot.model_fields},
}

_ORDERED_OPS = frozenset(
    {RuleOperator.GT, RuleOperator.GE, RuleOperator.LT, RuleOperator.LE}
)


class RulePredicate(BaseModel):
    """One comparison over a whitelisted field.

    ``in`` requires a list value; all other operators require a scalar.
    Ordered comparisons (gt/ge/lt/le) are numeric-only. The field's declared
    type must match the value's type — a string value against a numeric
    field is a validation error, not a quiet non-match.
    """

    field: str
    op: RuleOperator
    value: str | float | int | list[str] | list[float] | list[int]

    model_config = ConfigDict(extra="forbid")

    @field_validator("value", mode="before")
    @classmethod
    def reject_raw_booleans(cls, value: object) -> object:
        if type(value) is bool or (
            isinstance(value, (list, tuple))
            and any(type(item) is bool for item in value)
        ):
            raise ValueError("rule predicate rejects boolean values")
        return value

    @model_validator(mode="after")
    def validate_predicate(self) -> RulePredicate:
        field_type = _FIELD_TYPES.get(self.field)
        if field_type is None:
            raise ValueError(f"unknown predicate field {self.field!r}")
        if field_type == "string" and self.op in _ORDERED_OPS:
            raise ValueError(
                f"operator {self.op} is numeric-only (field {self.field!r})"
            )
        if self.op is RuleOperator.IN:
            if not isinstance(self.value, list) or not self.value:
                raise ValueError("'in' operator requires a non-empty list value")
            for item in self.value:
                _check_scalar_type(field_type, item, self.field)
            return self
        if isinstance(self.value, list):
            raise ValueError(  # noqa: TRY004 — ValueError feeds pydantic validation
                f"operator {self.op} requires a scalar value"
            )
        _check_scalar_type(field_type, self.value, self.field)
        return self


def _check_scalar_type(field_type: str, value: object, field: str) -> None:
    if isinstance(value, bool):
        raise ValueError(  # noqa: TRY004 — ValueError feeds pydantic validation
            f"predicate on {field!r} rejects boolean values"
        )
    if field_type == "number":
        if not isinstance(value, (int, float)) or not isfinite(float(value)):
            raise ValueError(f"predicate on {field!r} requires a finite number")
    elif not isinstance(value, str) or not value.strip():
        raise ValueError(f"predicate on {field!r} requires a non-empty string")


class RuleEffect(BaseModel):
    """What a matched rule contributes to the decision.

    ``min_score`` floors the fused risk score; ``force_action`` escalates to
    at least that action. At least one must be set. ``force_action`` cannot
    be ``NO_ACTION_SHADOW`` — shadow semantics are governed by operating
    mode, never by an authored rule.
    """

    model_config = ConfigDict(extra="forbid")

    min_score: RiskScore | None = None
    force_action: DecisionAction | None = None

    @model_validator(mode="after")
    def validate_effect(self) -> RuleEffect:
        if self.min_score is None and self.force_action is None:
            raise ValueError("rule effect requires min_score or force_action")
        if self.force_action is DecisionAction.NO_ACTION_SHADOW:
            raise ValueError("rules cannot force a shadow action")
        return self


class PolicyRule(BaseModel):
    """One authored rule: AND-ed predicates, one effect, audit identity."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    description: str = Field(min_length=1)
    enabled: bool = True
    predicates: tuple[RulePredicate, ...] = Field(min_length=1)
    effect: RuleEffect

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, value: str) -> str:
        if _TAG.fullmatch(value) is None:
            raise ValueError("rule_id must be a tag-safe identifier")
        return value


class RuleSet(BaseModel):
    """Versioned, tenant-bindable collection of authored rules."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=RULESET_SCHEMA_VERSION, min_length=1)
    tenant_id: str
    rule_set_version: str
    rules: tuple[PolicyRule, ...] = ()

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("tenant_id must be nonblank and canonical")
        return value

    @field_validator("schema_version")
    @classmethod
    def validate_schema(cls, value: str) -> str:
        if value != RULESET_SCHEMA_VERSION:
            raise ValueError("unsupported rule set schema")
        return value

    @field_validator("rule_set_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if _TAG.fullmatch(value) is None:
            raise ValueError("rule_set_version must be a tag-safe identifier")
        return value

    @model_validator(mode="after")
    def validate_rules(self) -> RuleSet:
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule_id in rule set")
        return self


def rule_set_digest(rule_set: RuleSet) -> str:
    """Canonical identity; a trusted installation must supply the expected digest."""
    if type(rule_set) is not RuleSet:
        raise RuleValidationError("typed rule set required")
    content = json.dumps(
        rule_set.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RuleVerdict:
    """Aggregate effect of all matched rules on one event."""

    matched_rule_ids: tuple[str, ...]
    min_score: float
    forced_action: DecisionAction | None


_SIGNAL_FIELDS = frozenset(IntelligenceSnapshot.model_fields)


def _field_value(
    transaction: CanonicalTransaction,
    intelligence: IntelligenceSnapshot,
    field: str,
) -> str | float | None:
    """Extracts a whitelisted field value; absent optional data is ``None``."""
    if field in _SIGNAL_FIELDS:
        return float(getattr(intelligence, field))
    if field == "amount":
        return float(transaction.amount)
    if field == "hour_of_day":
        return float(transaction.occurred_at.astimezone(UTC).hour)
    if field == "day_of_week":
        return float(transaction.occurred_at.astimezone(UTC).weekday())
    if field == "channel":
        return transaction.channel
    if field == "transaction_type":
        return transaction.transaction_type
    if field == "currency":
        return transaction.currency
    if field == "beneficiary_type":
        return transaction.beneficiary_type.value
    if field == "destination_institution_id":
        return transaction.destination_institution_id
    if field == "has_device_id":
        return 1.0 if transaction.device_id else 0.0
    if field == "is_external_beneficiary":
        return (
            1.0
            if transaction.beneficiary_type is BeneficiaryType.EXTERNAL
            else 0.0
        )
    raise RuleValidationError(f"unknown predicate field {field!r}")


def _match(
    op: RuleOperator, actual: str | float | None, expected: object
) -> bool:
    if actual is None:
        return False
    if op is RuleOperator.EQ:
        return actual == expected
    if op is RuleOperator.NEQ:
        return actual != expected
    if op is RuleOperator.IN:
        return isinstance(expected, list) and actual in expected
    if isinstance(actual, str) or not isinstance(expected, (int, float)):
        # Ordered comparisons on strings are unreachable after validation.
        raise RuleValidationError(f"operator {op} requires numeric operands")
    actual_num = float(actual)
    expected_num = float(expected)
    if op is RuleOperator.GT:
        return actual_num > expected_num
    if op is RuleOperator.GE:
        return actual_num >= expected_num
    if op is RuleOperator.LT:
        return actual_num < expected_num
    if op is RuleOperator.LE:
        return actual_num <= expected_num
    raise RuleValidationError(f"unknown rule operator {op!r}")


# Escalation severity — a forced action wins only if it outranks the
# threshold-mapped action; rules never downgrade a decision.
_SEVERITY = {
    DecisionAction.ALLOW: 0,
    DecisionAction.MONITOR: 1,
    DecisionAction.CHALLENGE: 2,
    DecisionAction.REVIEW: 3,
    DecisionAction.HOLD: 4,
    DecisionAction.BLOCK: 5,
}


class RuleEvaluator:
    """Evaluates a validated ``RuleSet`` against one event."""

    def __init__(self, rule_set: RuleSet) -> None:
        if type(rule_set) is not RuleSet:
            raise RuleValidationError("typed rule set required")
        self._rules = tuple(
            rule for rule in rule_set.model_copy(deep=True).rules if rule.enabled
        )

    def evaluate(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
    ) -> RuleVerdict:
        matched: list[str] = []
        min_score = 0.0
        forced: DecisionAction | None = None
        for rule in self._rules:
            if not all(
                _match(
                    predicate.op,
                    _field_value(transaction, intelligence, predicate.field),
                    predicate.value,
                )
                for predicate in rule.predicates
            ):
                continue
            matched.append(rule.rule_id)
            effect = rule.effect
            if effect.min_score is not None:
                min_score = max(min_score, effect.min_score)
            if effect.force_action is not None and (
                forced is None
                or _SEVERITY[effect.force_action] > _SEVERITY[forced]
            ):
                forced = effect.force_action
        return RuleVerdict(
            matched_rule_ids=tuple(matched),
            min_score=min_score,
            forced_action=forced,
        )


class _DecisionBackend(Protocol):
    """Anything with the ``DecisionService.decide`` contract can be wrapped."""

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        evidence_reason_codes: Sequence[str] = (),
    ) -> FraudDecision: ...


def _rule_score_action(
    policy: DecisionPolicy, score: float, channel: str
) -> DecisionAction:
    """Match the active server policy ladder; no Bank execution is issued."""
    if score >= policy.block_threshold:
        return DecisionAction.BLOCK
    if score >= policy.hold_threshold:
        return DecisionAction.HOLD
    if score >= policy.review_threshold:
        return DecisionAction.REVIEW
    if (
        policy.challenge_threshold is not None
        and policy.challenge_policy_ref is not None
        and channel in policy.challenge_supported_channels
        and score >= policy.challenge_threshold
    ):
        return DecisionAction.CHALLENGE
    if score >= policy.monitor_threshold:
        return DecisionAction.MONITOR
    return DecisionAction.ALLOW


class RulesAwareDecisionService:
    """Offline escalation-only rules bound to tenant and installed content identity.

    The expected digest must be supplied by a *trusted* tenant installation,
    never taken from an event. This does not implement a Bank-trusted registry,
    installation or enforcement authorization under #42/#49.
    """

    def __init__(
        self,
        policy: DecisionPolicy,
        rule_set: RuleSet,
        backend: _DecisionBackend | None = None,
        *,
        tenant_id: str,
        expected_ruleset_digest: str,
    ) -> None:
        if type(policy) is not DecisionPolicy:
            raise RuleValidationError("typed decision policy required")
        if type(rule_set) is not RuleSet:
            raise RuleValidationError("typed rule set required")
        if (
            type(tenant_id) is not str
            or not tenant_id.strip()
            or tenant_id != tenant_id.strip()
        ):
            raise RuleValidationError("canonical installed tenant_id required")
        if rule_set.tenant_id != tenant_id:
            raise RuleValidationError("rule set tenant does not match installation")
        if rule_set.rule_set_version != policy.rule_version:
            raise RuleValidationError(
                "rule set version does not match policy rule_version"
            )
        if (
            type(expected_ruleset_digest) is not str
            or expected_ruleset_digest != rule_set_digest(rule_set)
        ):
            raise RuleValidationError("rule set digest does not match installation")
        self._tenant_id = tenant_id
        self._policy = policy.model_copy(deep=True)
        self._service = backend if backend is not None else DecisionService(self._policy)
        self._evaluator = RuleEvaluator(rule_set)

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        evidence_reason_codes: Sequence[str] = (),
    ) -> FraudDecision:
        if (
            type(transaction) is not CanonicalTransaction
            or transaction.tenant_id != self._tenant_id
        ):
            raise RuleValidationError("transaction does not match installed rules tenant")
        base = self._service.decide(
            transaction, intelligence, evidence_reason_codes
        )
        if type(base) is not FraudDecision or type(base.action) is not DecisionAction:
            raise RuleValidationError("invalid upstream decision")
        if base.action is DecisionAction.NO_ACTION_SHADOW:
            raise RuleValidationError("shadow effective action cannot be remapped by rules")
        if (
            base.tenant_id != transaction.tenant_id
            or base.event_id != transaction.event_id
            or base.correlation_id != transaction.correlation_id
            or base.configuration_version != self._policy.configuration_version
            or base.policy_version != self._policy.policy_version
            or base.rule_version != self._policy.rule_version
            or base.model_version != self._policy.model_version
        ):
            raise RuleValidationError("upstream decision provenance mismatch")
        verdict = self._evaluator.evaluate(transaction, intelligence)
        if not verdict.matched_rule_ids:
            return base
        score = max(base.risk_score, verdict.min_score)
        mapped = _rule_score_action(self._policy, score, transaction.channel)
        action = (
            base.action if _SEVERITY[base.action] >= _SEVERITY[mapped] else mapped
        )
        if verdict.forced_action is not None:
            if verdict.forced_action is DecisionAction.CHALLENGE and (
                self._policy.challenge_threshold is None
                or self._policy.challenge_policy_ref is None
                or transaction.channel not in self._policy.challenge_supported_channels
            ):
                raise RuleValidationError("CHALLENGE rule lacks channel-scoped policy")
            if _SEVERITY[verdict.forced_action] > _SEVERITY[action]:
                action = verdict.forced_action
        reasons = list(dict.fromkeys([
            *base.reason_codes,
            *[f"RULE_{rid}" for rid in verdict.matched_rule_ids],
        ]))
        if (
            action is DecisionAction.CHALLENGE
            and "STEP_UP_RECOMMENDATION_ONLY" not in reasons
        ):
            reasons.append("STEP_UP_RECOMMENDATION_ONLY")
        return base.model_copy(update={
            "action": action,
            "risk_score": score,
            "reason_codes": reasons,
        })
