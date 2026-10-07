from __future__ import annotations

from collections.abc import Mapping
from math import ceil
from statistics import fmean, median
from typing import Protocol

# Only low-cardinality, tenant-safe dimensions may ever become labels.
# Customer/account identifiers, device IDs, IPs and payload fields are
# structurally excluded by this whitelist.
ALLOWED_LABEL_KEYS = frozenset(
    {"tenant_id", "action", "outcome", "reason", "source_system"}
)

LabelSet = frozenset[tuple[str, str]]


def _labels(labels: Mapping[str, str] | None) -> LabelSet:
    if not labels:
        return frozenset()
    disallowed = set(labels) - ALLOWED_LABEL_KEYS
    if disallowed:
        raise ValueError(
            f"metric label keys not allowed (cardinality/PII risk): "
            f"{sorted(disallowed)}"
        )
    return frozenset(labels.items())


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile over observed samples."""

    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, ceil(pct / 100 * len(ordered)) - 1))
    return ordered[index]


class MetricsRegistry(Protocol):
    """Operational metrics port — swap for the bank's metrics stack."""

    def increment(
        self, name: str, *, labels: Mapping[str, str] | None = None
    ) -> None: ...

    def observe(
        self,
        name: str,
        value: float,
        *,
        labels: Mapping[str, str] | None = None,
    ) -> None: ...


class InMemoryMetricsRegistry:
    """Deterministic in-memory registry for tests and local runs."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, LabelSet], int] = {}
        self._observations: dict[tuple[str, LabelSet], list[float]] = {}

    def increment(
        self, name: str, *, labels: Mapping[str, str] | None = None
    ) -> None:
        key = (name, _labels(labels))
        self._counters[key] = self._counters.get(key, 0) + 1

    def observe(
        self,
        name: str,
        value: float,
        *,
        labels: Mapping[str, str] | None = None,
    ) -> None:
        key = (name, _labels(labels))
        self._observations.setdefault(key, []).append(value)

    def counter(
        self, name: str, *, labels: Mapping[str, str] | None = None
    ) -> int:
        return self._counters.get((name, _labels(labels)), 0)

    def latency_summary(
        self, name: str, *, labels: Mapping[str, str] | None = None
    ) -> dict[str, float] | None:
        samples = self._observations.get((name, _labels(labels)))
        if not samples:
            return None
        return {
            "count": float(len(samples)),
            "mean": fmean(samples),
            "median": median(samples),
            "p95": percentile(samples, 95),
            "p99": percentile(samples, 99),
            "max": max(samples),
        }
