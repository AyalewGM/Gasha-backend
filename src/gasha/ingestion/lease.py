from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from uuid import UUID


class LeaseLostError(RuntimeError):
    """The evaluation's claim is no longer authorized to persist evidence."""


@dataclass(frozen=True)
class EvaluationLease:
    tenant_id: str
    event_id: UUID
    token: str


# Context-local, never shared between concurrent worker threads/tasks.
current_evaluation_lease: ContextVar[EvaluationLease | None] = ContextVar(
    "gasha_evaluation_lease", default=None
)
