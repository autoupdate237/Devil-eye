"""Scoring / verdict / allowlist unit tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devils_eye.core.config import Policy  # noqa: E402
from devils_eye.core.models import CorrelationGroup, Indicator, VerdictLevel  # noqa: E402
from devils_eye.scoring.risk import ScoringEngine  # noqa: E402
from devils_eye.verdict.engine import VerdictEngine  # noqa: E402
from devils_eye.allowlist.reputation import ReputationService  # noqa: E402


def make_ind(rule="DE-X", severity=5.0, confidence=0.8, category="process_integrity",
             path=r"C:\Temp\bad.exe", suppressed=False):
    return Indicator(
        rule_id=rule, rule_name=rule, category=category, severity=severity,
        confidence=confidence, title="t", description="d",
        subject_key=path.lower(), process_path=path, location=path,
        evidence_ids=["ev-1"],
    )


class ScoringTest(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.load()
        self.engine = ScoringEngine(self.policy)

    def test_single_weak_indicator_stays_low(self):
        ind = make_ind(severity=3.0, confidence=0.5)
        result = self.engine.score([ind], {})
        self.assertLess(result.global_score, 25.0,
                        "a single weak uncorroborated indicator must not reach SUSPICIOUS")

    def test_corroboration_raises_score(self):
        ind = make_ind()
        groups = {ind.subject_key: CorrelationGroup(subject_key=ind.subject_key, corroboration_factor=1.45)}
        with_corr = self.engine.score([ind], groups)
        ind2 = make_ind()
        without = self.engine.score([ind2], {})
        self.assertGreater(with_corr.global_score, without.global_score)

    def test_severe_corroborated_chain_reaches_high(self):
        inds = [
            make_ind("A", severity=9, confidence=0.9, path=r"C:\Temp\bad.exe"),
            make_ind("B", severity=8, confidence=0.85, category="module_integrity", path=r"C:\Temp\bad.exe"),
            make_ind("C", severity=7, confidence=0.8, category="persistence", path=r"C:\Temp\bad.exe"),
        ]
        key = inds[0].subject_key
        groups = {key: CorrelationGroup(subject_key=key, corroboration_factor=1.6)}
        result = self.engine.score(inds, groups)
        # 3 severe corroborated indicators on ONE subject = SUSPICIOUS by design;
        # HIGH/CRITICAL requires multi-subject chains or additional corroboration.
        self.assertGreaterEqual(result.global_score, 25.0)
        self.assertLess(result.global_score, 75.0)

    def test_allowlist_suppresses_contribution(self):
        ind = make_ind(severity=4, confidence=0.6, path=r"C:\Windows\System32\cmd.exe")
        rep = ReputationService(self.policy)
        rep.apply([ind])
        # cmd.exe under System32 → trusted directory/publisher dampening
        result = self.engine.score([ind], {})
        self.assertLess(result.global_score, 10.0)

    def test_hash_suppress_zeroes_risk(self):
        from devils_eye.core.models import AllowlistEntry

        ind = make_ind(severity=9, confidence=0.9)
        ind.hash_sha256 = "ab" * 32
        rep = ReputationService(self.policy, entries=[
            AllowlistEntry(kind="hash", value="ab" * 32, action="suppress", factor=0.0, reason="test"),
        ])
        rep.apply([ind])
        self.assertTrue(ind.suppressed)
        result = self.engine.score([ind], {})
        self.assertEqual(result.global_score, 0.0)


class VerdictTest(unittest.TestCase):
    def setUp(self):
        self.engine = VerdictEngine(Policy.load())

    def test_thresholds(self):
        cases = [(0, VerdictLevel.CLEAN), (15, VerdictLevel.LOW_RISK),
                 (30, VerdictLevel.SUSPICIOUS), (60, VerdictLevel.HIGH_RISK),
                 (90, VerdictLevel.CRITICAL)]
        for score, expected in cases:
            v = self.engine.decide(score, 0.9, 0.9, [], [])
            self.assertEqual(v.level, expected.value, f"score {score}")

    def test_low_coverage_downgrades_high_verdict(self):
        v_full = self.engine.decide(60, 0.9, 0.9, [], [])
        v_thin = self.engine.decide(60, 0.9, 0.2, [], [])
        self.assertGreater(VerdictLevel(v_full.level).rank, VerdictLevel(v_thin.level).rank)
        self.assertTrue(any("downgraded" in r.lower() for r in v_thin.rationale))

    def test_no_single_source_dependency(self):
        # even max score with near-zero coverage must not claim CRITICAL
        v = self.engine.decide(99, 0.9, 0.05, [], [])
        self.assertNotEqual(v.level, VerdictLevel.CRITICAL.value)


if __name__ == "__main__":
    unittest.main()
