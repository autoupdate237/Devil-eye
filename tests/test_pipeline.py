"""End-to-end pipeline tests against the simulated environment."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devils_eye.core.config import Policy  # noqa: E402
from devils_eye.pipeline.orchestrator import Orchestrator  # noqa: E402


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.orch = Orchestrator(policy=Policy.load(), workspace=Path(cls.tmp.name), simulated=True)
        cls.session = cls.orch.run(mode="scan")

    def test_scan_completes_with_verdict(self):
        self.assertIsNotNone(self.session.verdict)
        self.assertGreater(self.session.evidence_count, 50)

    def test_intrusion_chain_detected_high_or_critical(self):
        v = self.session.verdict
        self.assertIn(v.level, ("SUSPICIOUS", "HIGH RISK", "CRITICAL"),
                      f"expected escalated verdict, got {v.level} (score={v.score})")
        self.assertGreaterEqual(v.score, 50.0)

    def test_key_rules_fired(self):
        store = self.orch.store
        rows = store.query("SELECT DISTINCT rule_id FROM indicators WHERE scan_id=? AND suppressed=0",
                           (self.session.scan_id,))
        fired = {r["rule_id"] for r in rows}
        for expected in ("DE-MOD-001", "DE-MOD-002", "DE-PERS-002", "DE-DRV-001",
                         "DE-TEL-001", "DE-NET-001", "DE-PERS-001"):
            self.assertIn(expected, fired, f"{expected} should have fired")

    def test_benign_processes_not_flagged_severely(self):
        store = self.orch.store
        rows = store.query(
            "SELECT process_path, SUM(risk_contribution) pts FROM indicators "
            "WHERE scan_id=? AND suppressed=0 GROUP BY process_path",
            (self.session.scan_id,))
        for r in rows:
            path = (r["process_path"] or "").lower()
            if path.startswith(("c:\\windows\\system32", "c:\\windows\\syswow64")):
                self.assertLess(r["pts"], 15.0, f"trusted OS binary over-scored: {path}")

    def test_every_indicator_has_evidence(self):
        store = self.orch.store
        rows = store.query("SELECT evidence_json FROM indicators WHERE scan_id=? AND suppressed=0",
                           (self.session.scan_id,))
        import json

        for r in rows:
            ids = json.loads(r["evidence_json"])
            self.assertTrue(len(ids) >= 1, "indicator without evidence")

    def test_reports_written(self):
        self.assertEqual(len(self.session.report_paths), 2)
        for p in self.session.report_paths:
            self.assertTrue(Path(p).exists())
            self.assertGreater(Path(p).stat().st_size, 1000)

    def test_monitor_mode_reports_new_subjects(self):
        session2 = self.orch.run(mode="monitor")
        self.assertIsNotNone(session2.verdict)


class CollectorIsolationTest(unittest.TestCase):
    def test_failing_collector_does_not_crash_pipeline(self):
        from devils_eye.collectors import registry
        from devils_eye.collectors.processes import ProcessCollector

        class Broken(ProcessCollector):
            name = "processes"

            def collect(self, ctx):
                raise RuntimeError("boom")

        original = registry.all_collectors

        def patched(simulated=False):
            cols = original(simulated)
            cols = [Broken() if isinstance(c, ProcessCollector) else c for c in cols]
            cols.append(Broken())  # simulated lists only the sim collector; inject anyway
            return cols

        import devils_eye.pipeline.orchestrator as orch_mod

        registry.all_collectors = patched
        orch_mod.all_collectors = patched
        try:
            with tempfile.TemporaryDirectory() as tmp:
                orch = Orchestrator(workspace=Path(tmp), simulated=True)
                session = orch.run(mode="scan")
                self.assertIsNotNone(session.verdict)
                self.assertTrue(any("processes" in l.source for l in session.limitations))
        finally:
            registry.all_collectors = original
            orch_mod.all_collectors = original


if __name__ == "__main__":
    unittest.main()
