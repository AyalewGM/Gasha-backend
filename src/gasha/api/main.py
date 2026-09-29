from fastapi import FastAPI

from gasha.decision.service import DecisionService
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
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
        customer_risk=request.customer_risk,
        transaction_risk=request.transaction_risk,
        beneficiary_risk=request.beneficiary_risk,
        relationship_risk=request.relationship_risk,
        network_risk=request.network_risk,
    )
    return DecisionService(request.policy).decide(request.transaction, intelligence)
