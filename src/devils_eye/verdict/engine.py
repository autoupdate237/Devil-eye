"""Verdict Engine: score + coverage + top evidence → explainable verdict.

Levels: CLEAN / LOW RISK / SUSPICIOUS / HIGH RISK / CRITICAL.

Confidence is the mean confidence of the strongest contributors, scaled by
telemetry coverage: if half the expected sources were missing, a HIGH verdict
is *downgraded* rather than emitted with false certainty ('No single-source
dependency' + graceful degradation).
"""

from __future__ import annotations

from typing import List

from ..core.config import Policy
from ..core.models import TelemetryLimitation, Verdict, VerdictLevel

MIN_COVERAGE_FOR_HIGH = 0.40


class VerdictEngine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def decide(self, score: float, confidence: float, coverage: float,
               top_indicators: List, limitations: List[TelemetryLimitation]) -> Verdict:
        th = self.policy.thresholds
        if score < th["low"]:
            level = VerdictLevel.CLEAN
        elif score < th["suspicious"]:
            level = VerdictLevel.LOW_RISK
        elif score < th["high"]:
            level = VerdictLevel.SUSPICIOUS
        elif score < th["critical"]:
            level = VerdictLevel.HIGH_RISK
        else:
            level = VerdictLevel.CRITICAL

        # Coverage guard: never claim HIGH/CRITICAL on thin telemetry.
        downgraded = False
        if coverage < MIN_COVERAGE_FOR_HIGH and level.rank >= VerdictLevel.HIGH_RISK.rank:
            level = list(VerdictLevel)[level.rank - 1]
            downgraded = True

        rationale = []
        for ind in top_indicators[:5]:
            rationale.append(
                f"[{ind.rule_id}] {ind.title} — {ind.location} "
                f"(confidence {ind.confidence:.2f}, +{ind.risk_contribution:.1f} pts, "
                f"corroboration ×{ind.corroboration:.2f}, evidence: {len(ind.evidence_ids)})"
            )
        if not rationale:
            rationale.append("No indicators fired above allowlist/reputation suppression.")
        if downgraded:
            rationale.append(
                f"Verdict downgraded one level: telemetry coverage {coverage:.0%} < "
                f"{MIN_COVERAGE_FOR_HIGH:.0%} — findings are real but partial."
            )
        subject_scores = {}
        return Verdict(
            level=level.value, score=score, confidence=round(confidence, 3),
            telemetry_coverage=round(coverage, 3), rationale=rationale,
            subject_scores=subject_scores,
            top_indicators=[i.id for i in top_indicators[:8]],
            limitations=[l.reason for l in limitations],
        )
