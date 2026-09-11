"""Detection rule tests: each rule's 5-part explanation contract."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # test fixtures

from devils_eye.core.config import Policy  # noqa: E402
from devils_eye.detection.engine import DetectionEngine, all_rules  # noqa: E402
from fake_environment import FakeWindowsHostCollector  # noqa: E402
from devils_eye.collectors.base import PipelineContext  # noqa: E402
from devils_eye.normalization.normalizer import Normalizer  # noqa: E402


def build_snapshot():
    policy = Policy.load()
    ctx = PipelineContext(policy=policy)
    evidences = FakeWindowsHostCollector().collect(ctx).evidences
    return Normalizer().build(evidences, policy.protected_names), policy


class RuleDocsTest(unittest.TestCase):
    def test_every_rule_has_explanation_contract(self):
        from devils_eye.detection import rules  # noqa: F401  (register)

        for spec in all_rules():
            for key in ("what", "where", "evidence", "risk"):
                self.assertTrue(spec.doc.get(key), f"{spec.id} missing doc.{key}")
            self.assertGreater(spec.severity, 0)
            self.assertTrue(0 < spec.base_confidence <= 1 or spec.base_confidence == 0)


class RuleFiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot, cls.policy = build_snapshot()
        cls.indicators, cls.limitations = DetectionEngine(cls.policy).run(cls.snapshot)
        cls.by_rule = {}
        for ind in cls.indicators:
            cls.by_rule.setdefault(ind.rule_id, []).append(ind)

    def rule(self, rule_id):
        return self.by_rule.get(rule_id, [])

    def test_masquerade_ntdll(self):
        inds = self.rule("DE-MOD-002")
        self.assertTrue(inds)
        self.assertIn("ntdll", inds[0].title.lower())

    def test_unsigned_module_in_protected(self):
        inds = self.rule("DE-MOD-001")
        self.assertTrue(any("aimcore" in i.title for i in inds))

    def test_ifeo_hijack_on_protected_game_gets_high_confidence(self):
        inds = self.rule("DE-PERS-002")
        game = [i for i in inds if "r5apex" in i.title.lower()]
        self.assertTrue(game)
        self.assertGreaterEqual(game[0].confidence, 0.9)

    def test_remote_thread_into_protected(self):
        inds = self.rule("DE-TEL-001")
        self.assertTrue(inds)
        self.assertTrue(inds[0].evidence_ids)

    def test_memory_rules_only_on_protected(self):
        for rid in ("DE-MEM-001", "DE-MEM-002"):
            for ind in self.rule(rid):
                self.assertIn("r5apex", ind.process_path.lower())

    def test_broken_driver_signature(self):
        inds = self.rule("DE-DRV-001")
        self.assertTrue(any("cheatdrv" in i.title for i in inds))

    def test_no_indicator_without_evidence(self):
        for ind in self.indicators:
            self.assertTrue(ind.evidence_ids, f"{ind.rule_id} has no evidence ids")

    def test_rule_engine_isolates_crashes(self):
        from devils_eye.detection import engine as eng

        def boom(snap, pol):
            raise RuntimeError("intentional")

        eng._REGISTRY.append(eng.RuleSpec("DE-TEST-BOOM", "boom", "telemetry", 1, 0.5, boom,
                                          doc={"what": "x", "where": "x", "evidence": "x", "risk": "x"}))
        try:
            _, limitations = DetectionEngine(self.policy).run(self.snapshot)
            self.assertTrue(any("DE-TEST-BOOM" in l.source for l in limitations))
        finally:
            eng._REGISTRY.pop()


class TelemetryCoverageTest(unittest.TestCase):
    def test_missing_mandatory_source_lowers_coverage_and_reports(self):
        from devils_eye.core.models import TelemetryAvailability
        from devils_eye.telemetry.availability import compute_coverage

        rows = [
            TelemetryAvailability("processes", False, "access denied", 1.0),
            TelemetryAvailability("eventlog", True, "", 0.9),
            TelemetryAvailability("sysmon", False, "not installed", 0.7),
        ]
        coverage, limitations = compute_coverage(rows)
        self.assertLess(coverage, 1.0)
        self.assertTrue(any(l.source == "processes" for l in limitations))

    def test_full_coverage_is_one(self):
        from devils_eye.core.models import TelemetryAvailability
        from devils_eye.telemetry.availability import compute_coverage

        rows = [TelemetryAvailability("x", True, "", 1.0) for _ in range(3)]
        coverage, _ = compute_coverage(rows)
        self.assertAlmostEqual(coverage, 1.0)


if __name__ == "__main__":
    unittest.main()
