from fastapi import FastAPI

from gasha.decision.service import DecisionService
from gasha.domain.models import CanonicalTransaction, FraudDecision, IntelligenceSnapshot

app = FastAPI(title="Gasha Fraud Decision API", version="0.1.0")
decision_service = DecisionService()


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness() -> dict[str, str]:
    return {"status": "ready"}


@app.post("/v1/decisions", response_model=FraudDecision)
def create_decision(
    transaction: CanonicalTransaction,
    intelligence: IntelligenceSnapshot,
) -> FraudDecision:
    return decision_service.decide(transaction, intelligence)
