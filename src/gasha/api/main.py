from fastapi import FastAPI

from gasha.decision.mode import DecisionEnvelope, ModeAwareDecisionService
from gasha.decision.service import DecisionService
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
    OperatingMode,
)

app = FastAPI(title="Gasha Fraud Decision API", version="0.2.0")


class DecisionRequest(IntelligenceSnapshot):
    """Temporary M1 request shape until intelligence assembly is server-side."""

    transaction: CanonicalTransaction
    policy: DecisionPolicy


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/v1/decisions", response_model=FraudDecision)
def create_decision(request: DecisionRequest) -> FraudDecision:
    intelligence = IntelligenceSnapshot(
        **request.model_dump(include=set(IntelligenceSnapshot.model_fields))
    )
    return DecisionService(request.policy).decide(request.transaction, intelligence)


class EvaluationRequest(DecisionRequest):
    """M1 evaluation request carrying an explicit operating mode."""

    operating_mode: OperatingMode = OperatingMode.ENFORCING


@app.post("/v1/evaluations", response_model=DecisionEnvelope)
def create_evaluation(request: EvaluationRequest) -> DecisionEnvelope:
    """Evaluates a transaction while preserving hypothetical vs effective action.

    In SHADOW mode the response never carries an enforcing effective action;
    the hypothetical decision is preserved for later comparison and outcome
    reconciliation.
    """

    intelligence = IntelligenceSnapshot(
        **request.model_dump(include=set(IntelligenceSnapshot.model_fields))
    )
    return ModeAwareDecisionService(
        request.policy, operating_mode=request.operating_mode
    ).decide(request.transaction, intelligence)
