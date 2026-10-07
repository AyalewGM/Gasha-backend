from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from pydantic import BaseModel

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionAction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
    OperatingMode,
)


class DecisionEnvelope(BaseModel):
    """Separates Gasha's hypothetical decision from the bank-facing action.

    In SHADOW mode ``decision`` preserves exactly what Gasha would have done
    (including BLOCK/HOLD) while ``effective_action`` remains non-enforcing.
    In ENFORCING mode ``effective_action`` equals ``decision.action``.
    """

    operating_mode: OperatingMode
    decision: FraudDecision
    effective_action: DecisionAction
    evaluated_at: datetime
    evaluation_latency_ms: float


class ModeAwareDecisionService:
    """Wraps the deterministic DecisionService with an explicit operating mode.

    The hypothetical decision is always computed through the same fusion path;
    the mode only governs the effective action exposed to the bank, never the
    recorded risk score or reason codes.
    """

    def __init__(
        self,
        policy: DecisionPolicy,
        *,
        operating_mode: OperatingMode = OperatingMode.ENFORCING,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.service = DecisionService(policy)
        self.operating_mode = operating_mode
        self._clock = clock or (lambda: datetime.now(UTC))

    def decide(
        self,
        transaction: CanonicalTransaction,
        intelligence: IntelligenceSnapshot,
        evidence_reason_codes: Sequence[str] = (),
    ) -> DecisionEnvelope:
        started = self._clock()
        decision = self.service.decide(
            transaction, intelligence, evidence_reason_codes
        )
        finished = self._clock()
        effective = (
            decision.action
            if self.operating_mode == OperatingMode.ENFORCING
            else DecisionAction.NO_ACTION_SHADOW
        )
        return DecisionEnvelope(
            operating_mode=self.operating_mode,
            decision=decision,
            effective_action=effective,
            evaluated_at=finished,
            evaluation_latency_ms=(finished - started).total_seconds() * 1000.0,
        )
