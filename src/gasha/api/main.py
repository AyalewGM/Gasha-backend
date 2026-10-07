from typing import Annotated

from fastapi import Depends, FastAPI, Request

from gasha.decision.mode import DecisionEnvelope, ModeAwareDecisionService
from gasha.decision.service import DecisionService
from gasha.domain.models import (
    CanonicalTransaction,
    DecisionPolicy,
    FraudDecision,
    IntelligenceSnapshot,
    OperatingMode,
)
from gasha.ingestion.outcome_ingestion import (
    IncumbentOutcomeRecord,
    OutcomeIngestionService,
    OutcomeSubmission,
)
from gasha.poc.outcomes import OutcomeRecord

app = FastAPI(title="Gasha Fraud Decision API", version="0.2.0")
app.state.outcome_ingestion = OutcomeIngestionService()


def get_outcome_ingestion(request: Request) -> OutcomeIngestionService:
    service: OutcomeIngestionService = request.app.state.outcome_ingestion
    return service


class DecisionRequest(IntelligenceSnapshot):
    """Temporary M1 request shape until intelligence assembly is server-side."""

    transaction: CanonicalTransaction
    policy: DecisionPolicy


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness(request: Request) -> dict[str, object]:
    """Ready only when the dependencies required to serve traffic exist.

    Checks are dependency-presence checks, not deep probes — no secrets
    or connection details are ever reported.
    """

    checks = {
        "outcome_ingestion": isinstance(
            getattr(request.app.state, "outcome_ingestion", None),
            OutcomeIngestionService,
        ),
    }
    ready = all(checks.values())
    return {"status": "ready" if ready else "not_ready", "checks": checks}


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


@app.post("/v1/outcomes", response_model=OutcomeSubmission)
def submit_outcome(
    record: OutcomeRecord,
    service: Annotated[
        OutcomeIngestionService, Depends(get_outcome_ingestion)
    ],
) -> OutcomeSubmission:
    """Attaches a late confirmed outcome to a prior decision.

    Append-only history keyed by (tenant_id, event_id): resubmissions are
    idempotent duplicates; changed outcomes preserve the transition. The
    original decision is never mutated.
    """

    return service.submit(record)


@app.post("/v1/incumbent-outcomes", response_model=OutcomeSubmission)
def submit_incumbent_outcome(
    record: IncumbentOutcomeRecord,
    service: Annotated[
        OutcomeIngestionService, Depends(get_outcome_ingestion)
    ],
) -> OutcomeSubmission:
    """Records what the bank's existing controls did — vendor-neutral."""

    return service.submit_incumbent(record)
