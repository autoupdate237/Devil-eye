"""Risk Scoring engine.

Model (documented in docs/SCORING_MODEL.md):

    contribution_i = severity_i        (0..10)
                   × confidence_i      (0..1)
                   × category_weight   (policy)
                   × corroboration     (1.0 + 0.15×(independent_sources−1), ≤1.6)
                   × allowlist_factor  (1.0 unless dampened; 0 if suppressed)
                   × sensitivity       (conservative .8 / balanced 1.0 / aggressive 1.25)

    subject_score    = Σ contributions for the subject        (capped 100)
    global_score     = max(subject_scores)
                     + 0.15 × Σ(other subject scores)         (capped 100)

No single indicator can reach HIGH/CRITICAL on its own unless it is itself
severe AND corroborated — this is the structural false-positive guard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..core.config import Policy
from ..core.models import CorrelationGroup, Indicator

SENSITIVITY_MULT = {"conservative": 0.8, "balanced": 1.0, "aggressive": 1.25}


@dataclass
class ScoringResult:
    global_score: float = 0.0
    subject_scores: Dict[str, float] = field(default_factory=dict)
    top_indicators: List[Indicator] = field(default_factory=list)
    suppressed_count: int = 0


class ScoringEngine:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.weights = policy.category_weights
        self.sensitivity = SENSITIVITY_MULT.get(policy.get("sensitivity", "balanced"), 1.0)

    # ------------------------------------------------------------------
    def score(self, indicators: List[Indicator], groups: Dict[str, CorrelationGroup]) -> ScoringResult:
        result = ScoringResult()
        per_subject: Dict[str, List[float]] = {}
        scored: List[Indicator] = []
        for ind in indicators:
            if ind.suppressed:
                result.suppressed_count += 1
                continue
            group = groups.get(ind.subject_key) or groups.get(ind.process_path.lower())
            corroboration = group.corroboration_factor if group else 1.0
            ind.corroboration = corroboration
            weight = float(self.weights.get(ind.category, 1.0))
            ind.risk_contribution = (
                ind.severity * ind.confidence * weight * corroboration
                * ind.allowlist_dampening * self.sensitivity
            )
            key = ind.subject_key or ind.process_path.lower() or "(host)"
            per_subject.setdefault(key, []).append(ind.risk_contribution)
            if group:
                group.score = sum(per_subject[key])
            scored.append(ind)
        for key, parts in per_subject.items():
            result.subject_scores[key] = round(min(100.0, sum(parts)), 2)
        if result.subject_scores:
            top = max(result.subject_scores.values())
            others = sum(v for k, v in result.subject_scores.items() if v != top)
            result.global_score = round(min(100.0, top + 0.15 * others), 2)
        result.top_indicators = sorted(scored, key=lambda i: i.risk_contribution, reverse=True)[:8]
        return result
