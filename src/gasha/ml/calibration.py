"""Isotonic probability calibration for raw booster scores.

A gradient-boosted binary classifier outputs scores whose ranking is
meaningful but whose magnitude is not a probability. Decision thresholds,
however, are interpreted as probabilities, so raw scores are calibrated on
a held-out, time-ordered slice with the pool-adjacent-violators algorithm.
The fitted calibrator is a small set of knots that travels inside the model
manifest, keeping serving free of any calibration dependency.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True, slots=True)
class IsotonicCalibrator:
    """Piecewise-linear monotone map from raw score to calibrated risk.

    ``knots`` are ``(score, probability)`` pairs strictly increasing in
    score and non-decreasing in probability. Scores outside the fitted
    range clamp to the nearest knot's probability.
    """

    knots: tuple[tuple[float, float], ...]

    @classmethod
    def fit(
        cls, scores: Sequence[float], labels: Sequence[bool]
    ) -> IsotonicCalibrator:
        """Fits a non-decreasing calibration map via PAVA block merging."""
        if len(scores) != len(labels):
            raise ValueError("score/label length mismatch")
        if not scores:
            raise ValueError("cannot calibrate an empty slice")
        if any(not isfinite(s) for s in scores):
            raise ValueError("scores must be finite")
        ordered = sorted(zip(scores, labels), key=lambda pair: pair[0])
        # Each block: [total_weight, sum_y, x_min, x_max]. Equal weights.
        blocks: list[list[float]] = [
            [1.0, 1.0 if y else 0.0, x, x] for x, y in ordered
        ]
        merged: list[list[float]] = []
        for block in blocks:
            merged.append(block)
            while len(merged) >= 2 and (
                merged[-2][1] / merged[-2][0] > merged[-1][1] / merged[-1][0]
            ):
                right = merged.pop()
                left = merged.pop()
                merged.append(
                    [
                        left[0] + right[0],
                        left[1] + right[1],
                        left[2],
                        right[3],
                    ]
                )
        # Tied scores can survive PAVA as adjacent same-x blocks; merge them
        # into one weighted knot so the serialized map is strictly increasing.
        by_x: list[list[float]] = []  # [x, weight, weighted_y]
        for block in merged:
            x = (block[2] + block[3]) / 2.0
            y = min(1.0, max(0.0, block[1] / block[0]))
            if by_x and by_x[-1][0] == x:
                by_x[-1][1] += block[0]
                by_x[-1][2] += y * block[0]
            else:
                by_x.append([x, block[0], y * block[0]])
        knots = tuple((x, wy / w) for x, w, wy in by_x)
        if len(knots) == 1:
            # A constant map still needs a domain; span the unit interval.
            knots = ((0.0, knots[0][1]), (1.0, knots[0][1]))
        return cls(knots=knots)

    def predict(self, score: float) -> float:
        """Maps one raw score to a calibrated probability in ``[0, 1]``."""
        if not isfinite(score):
            raise ValueError("score must be finite")
        xs = [point[0] for point in self.knots]
        if score <= xs[0]:
            return self.knots[0][1]
        if score >= xs[-1]:
            return self.knots[-1][1]
        index = bisect_right(xs, score) - 1
        x0, y0 = self.knots[index]
        x1, y1 = self.knots[index + 1]
        if x1 == x0:
            return y1
        fraction = (score - x0) / (x1 - x0)
        return min(1.0, max(0.0, y0 + fraction * (y1 - y0)))

    def predict_many(self, scores: Sequence[float]) -> tuple[float, ...]:
        return tuple(self.predict(score) for score in scores)
