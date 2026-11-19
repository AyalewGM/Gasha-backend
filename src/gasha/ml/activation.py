"""Model activation path: manifest-driven tenant policy drafts.

A trained artifact reaches production only through the tenant configuration
lifecycle: ``manifest → candidate DecisionPolicy → DRAFT config entry →
review → plan_activation``. Producing a draft never authorizes serving —
protected-route containment is lifted only when a bank approves and
activates the produced entry.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from gasha.configuration.kernel import (
    ConfigKind,
    TenantConfigEntry,
    new_draft,
)
from gasha.domain.models import DecisionPolicy
from gasha.ml.manifest import ModelManifest
from gasha.ml.replay import PromotionEvaluation

ACTIVATION_EVIDENCE_SCHEMA = "gasha-activation-evidence-1"


class ActivationRejected(ValueError):
    """A manifest, evaluation, or draft request cannot produce an activation."""


def candidate_policy(
    manifest: ModelManifest,
    *,
    configuration_version: str,
    policy_version: str,
    rule_version: str,
    enable_challenge: bool = False,
) -> DecisionPolicy:
    """Builds the candidate ``DecisionPolicy`` a manifest suggests.

    Thresholds come from the artifact's validated operating points and the
    policy is bound to ``manifest.model_version`` — a candidate can never
    carry thresholds for a different model. The suggested challenge point is
    applied only when the operator explicitly opts in; a tenant without
    channel step-up support must not emit CHALLENGE just because the
    validation cohort happened to realize the rung.
    """
    if type(manifest) is not ModelManifest:
        raise ActivationRejected("typed model manifest required")
    thresholds = manifest.thresholds
    return DecisionPolicy(
        configuration_version=configuration_version,
        policy_version=policy_version,
        rule_version=rule_version,
        model_version=manifest.model_version,
        monitor_threshold=thresholds.monitor_threshold,
        challenge_threshold=(
            thresholds.challenge_threshold if enable_challenge else None
        ),
        review_threshold=thresholds.review_threshold,
        hold_threshold=thresholds.hold_threshold,
        block_threshold=thresholds.block_threshold,
    )


def draft_policy_entry(
    policy: DecisionPolicy,
    *,
    tenant_id: str,
    version: int,
    created_at: datetime,
    created_by_ref: str,
) -> TenantConfigEntry:
    """Wraps a candidate policy in a validated DRAFT config entry.

    The kernel validates the serialized payload exactly — a malformed or
    untagged policy cannot become a draft. Nothing is activated here;
    promotion to active goes through ``plan_activation`` and the bank's
    approval of the activation evidence.
    """
    if type(policy) is not DecisionPolicy:
        raise ActivationRejected("typed decision policy required")
    return new_draft(
        tenant_id=tenant_id,
        config_kind=ConfigKind.DECISION_POLICY,
        version=version,
        payload=policy.model_dump(),
        created_at=created_at,
        created_by_ref=created_by_ref,
    )


@dataclass(frozen=True, slots=True)
class ActivationEvidence:
    """Review bundle bound to one manifest, one evaluation, one policy.

    Constructed only for candidates the promotion gate approved — a rejected
    challenger has no activation path to document. The digest pins the exact
    evidence an approver saw so later audits can reproduce it.
    """

    schema_version: str
    model_version: str
    cohort_digest: str
    label_cutoff: datetime
    promotes: bool
    non_promotion_reason: str | None
    rules_fpr: float | None
    model_fpr: float | None
    rules_recall: float | None
    model_recall: float | None
    rules_precision: float | None
    model_precision: float | None
    evaluation_digest: str
    policy: DecisionPolicy
    evidence_digest: str


def activation_evidence(
    manifest: ModelManifest,
    evaluation: PromotionEvaluation,
    policy: DecisionPolicy,
) -> ActivationEvidence:
    """Binds manifest + promotion evaluation + candidate policy for review.

    ``promotes`` must be true — evidence exists to approve an activation,
    never to justify one the gate rejected. The policy's model version must
    equal the manifest's, and the evaluation's cohort digest must equal the
    manifest's training cohort so the evidence cannot be quietly swapped.
    """
    if type(manifest) is not ModelManifest:
        raise ActivationRejected("typed model manifest required")
    if type(evaluation) is not PromotionEvaluation:
        raise ActivationRejected("typed promotion evaluation required")
    if type(policy) is not DecisionPolicy:
        raise ActivationRejected("typed decision policy required")
    if policy.model_version != manifest.model_version:
        raise ActivationRejected("policy model_version does not match manifest")
    if not evaluation.promotes:
        raise ActivationRejected(
            "non-promoting candidate cannot produce activation evidence"
            + (
                f" ({evaluation.non_promotion_reason})"
                if evaluation.non_promotion_reason
                else ""
            )
        )
    canonical = {
        "schema": ACTIVATION_EVIDENCE_SCHEMA,
        "model_version": manifest.model_version,
        "cohort_digest": manifest.cohort_digest,
        "label_cutoff": manifest.label_cutoff.isoformat(),
        "evaluation_digest": evaluation.evidence_digest,
        "policy": policy.model_dump(mode="json"),
        "rates": {
            "rules_fpr": evaluation.rules_fpr,
            "model_fpr": evaluation.model_fpr,
            "rules_recall": evaluation.rules_recall,
            "model_recall": evaluation.model_recall,
            "rules_precision": evaluation.rules_precision,
            "model_precision": evaluation.model_precision,
        },
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ActivationEvidence(
        schema_version=ACTIVATION_EVIDENCE_SCHEMA,
        model_version=manifest.model_version,
        cohort_digest=manifest.cohort_digest,
        label_cutoff=manifest.label_cutoff,
        promotes=evaluation.promotes,
        non_promotion_reason=evaluation.non_promotion_reason,
        rules_fpr=evaluation.rules_fpr,
        model_fpr=evaluation.model_fpr,
        rules_recall=evaluation.rules_recall,
        model_recall=evaluation.model_recall,
        rules_precision=evaluation.rules_precision,
        model_precision=evaluation.model_precision,
        evaluation_digest=evaluation.evidence_digest,
        policy=policy,
        evidence_digest=digest,
    )
