"""NetGuardians export normalization — adapter-layer vendor mapping.

``IncumbentControlOutcome`` is provider-neutral by design; this module is the
adapter layer that maps NetGuardians vocabulary into it. The normalized export
contract (``event_id``, ``risk_score``, ``verdict``) is what Gasha requires —
the extraction job that produces these rows from the bank's actual NG export
(API, report, or message feed) is deployment-specific work pending a real
export sample.

The verdict mapping is draft: NG deployments configure their own dispositions,
so unknown values fail closed rather than defaulting to a non-alert — an
unmapped vendor status silently counted as "no alert" would overstate the
challenger in every comparison.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import isfinite
from uuid import UUID

from gasha.poc.outcomes import IncumbentControlOutcome

NETGUARDIANS_EXPORT_SCHEMA = "netguardians-export-1"
OUTCOME_MAP_VERSION = "netguardians-outcome-map-v1-draft"


class NetGuardiansExportRejected(ValueError):
    """A NetGuardians export row is malformed or uses unmapped vocabulary."""


_VERDICT_MAP: dict[str, IncumbentControlOutcome] = {
    "allow": IncumbentControlOutcome.NO_ALERT,
    "approve": IncumbentControlOutcome.NO_ALERT,
    "pass": IncumbentControlOutcome.NO_ALERT,
    "no_alert": IncumbentControlOutcome.NO_ALERT,
    "alert": IncumbentControlOutcome.ALERT,
    "flag": IncumbentControlOutcome.ALERT,
    "watch": IncumbentControlOutcome.ALERT,
    "review": IncumbentControlOutcome.REVIEW,
    "recommend_review": IncumbentControlOutcome.REVIEW,
    "manual_review": IncumbentControlOutcome.REVIEW,
    "challenge": IncumbentControlOutcome.CHALLENGE,
    "step_up": IncumbentControlOutcome.CHALLENGE,
    "hold": IncumbentControlOutcome.HOLD,
    "recommend_hold": IncumbentControlOutcome.HOLD,
    "freeze": IncumbentControlOutcome.HOLD,
    "block": IncumbentControlOutcome.BLOCK,
    "recommend_block": IncumbentControlOutcome.BLOCK,
    "reject": IncumbentControlOutcome.BLOCK,
    "deny": IncumbentControlOutcome.BLOCK,
}


def map_netguardians_outcome(raw_verdict: str) -> IncumbentControlOutcome:
    """Maps one NetGuardians verdict into the provider-neutral vocabulary."""
    normalized = raw_verdict.strip().lower().replace(" ", "_").replace("-", "_")
    try:
        return _VERDICT_MAP[normalized]
    except KeyError:
        raise NetGuardiansExportRejected(
            f"unmapped NetGuardians verdict {raw_verdict!r}"
        ) from None


@dataclass(frozen=True, slots=True)
class NetGuardiansOutcomeRecord:
    """One normalized incumbent outcome joined to a canonical event."""

    event_id: UUID
    risk_score: float
    outcome: IncumbentControlOutcome
    raw_verdict: str


def normalize_netguardians_export(
    rows: Sequence[Mapping[str, object]],
    *,
    score_max: float = 1.0,
) -> tuple[NetGuardiansOutcomeRecord, ...]:
    """Validates an NG export into normalized outcome records.

    Each row must carry ``event_id`` (UUID or parseable string),
    ``risk_score`` (finite number scaled by ``score_max`` into ``[0, 1]``),
    and ``verdict`` (mapped fail-closed by :func:`map_netguardians_outcome`).
    Duplicate event identifiers and empty input are rejected — a comparison
    against a partial incumbent export would overstate the challenger.
    """
    if not isinstance(score_max, float) or not isfinite(score_max) or score_max <= 0:
        raise NetGuardiansExportRejected("score_max must be a positive finite float")
    if not rows:
        raise NetGuardiansExportRejected("NetGuardians export is empty")

    records: list[NetGuardiansOutcomeRecord] = []
    seen: set[UUID] = set()
    for index, row in enumerate(rows):
        for key in ("event_id", "risk_score", "verdict"):
            if key not in row:
                raise NetGuardiansExportRejected(
                    f"NetGuardians export row {index} missing {key!r}"
                )
        raw_id = row["event_id"]
        try:
            event_id = raw_id if isinstance(raw_id, UUID) else UUID(str(raw_id))
        except (ValueError, AttributeError, TypeError):
            raise NetGuardiansExportRejected(
                f"NetGuardians export row {index} has a malformed event id"
            ) from None
        if event_id in seen:
            raise NetGuardiansExportRejected(
                f"duplicate NetGuardians outcome for event {event_id}"
            )
        raw_score = row["risk_score"]
        if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
            raise NetGuardiansExportRejected(
                f"NetGuardians export row {index} has a non-numeric score"
            )
        score = float(raw_score) / score_max
        if not isfinite(score) or not 0.0 <= score <= 1.0:
            raise NetGuardiansExportRejected(
                f"NetGuardians export row {index} score outside [0, {score_max}]"
            )
        raw_verdict = row["verdict"]
        if not isinstance(raw_verdict, str) or not raw_verdict.strip():
            raise NetGuardiansExportRejected(
                f"NetGuardians export row {index} has a blank verdict"
            )
        seen.add(event_id)
        records.append(
            NetGuardiansOutcomeRecord(
                event_id=event_id,
                risk_score=score,
                outcome=map_netguardians_outcome(raw_verdict),
                raw_verdict=raw_verdict,
            )
        )
    return tuple(records)
