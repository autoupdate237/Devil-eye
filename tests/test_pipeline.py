"""End-to-end pipeline tests.

The pipeline is exercised on any OS by injecting the deterministic
``FakeWindowsHostCollector`` (tests/fake_environment.py) as the collector
set. The product code path under test is exactly the real one — only the
collector list is swapped, which is the intended seam for CI.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # test fixtures

import devils_eye.pipeline.orchestrator as orch_mod  # noqa: E402
from devils_eye.collectors import registry  # noqa: E402
from devils_eye.collectors.processes import ProcessCollector  # noqa: E402
from devils_eye.core.config import Policy  # noqa: E402
from devils_eye.pipeline.orchestrator import Orchestrator  # noqa: E402

from fake_environment import FakeWindowsHostCollector  # noqa: E402

ORIGINAL_ALL = registry.all_collectors


def _use_collectors(cols):
    """Point both the registry and the (already imported) orchestrator at a
    custom collector list."""
    registry.all_collectors = lambda: list(cols)
    orch_mod.all_collectors = registry.all_collectors


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _use_collectors([FakeWindowsHostCollector()])
        cls.tmp = tempfile.TemporaryDirectory()
        cls.orch = Orchestrator(policy=Policy.load(), workspace=Path(cls.tmp.name))
        cls.session = cls.orch.run(mode="scan")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.orch.store.close()   # release the SQLite handle (Windows cleanup)
        finally:
            registry.all_collectors = ORIGINAL_ALL
            orch_mod.all_collectors = ORIGINAL_ALL

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

    def test_monitor_mode_second_pass_reports_no_new_subjects(self):
        session2 = self.orch.run(mode="monitor")
        self.assertIsNotNone(session2.verdict)
        self.assertEqual(session2.new_subjects, [])


class CollectorIsolationTest(unittest.TestCase):
    """A crashing collector must never abort the pipeline (requirement 11/20)."""

    def test_failing_collector_does_not_crash_pipeline(self):
        class Broken(ProcessCollector):
            name = "processes"
            requires_windows = False  # allow the crash to happen on any OS

            def collect(self, ctx):
                raise RuntimeError("boom")

        _use_collectors([FakeWindowsHostCollector(), Broken()])
        try:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                orch = Orchestrator(workspace=Path(tmp))
                session = orch.run(mode="scan")
                self.assertIsNotNone(session.verdict)
                self.assertTrue(any("processes" in l.source for l in session.limitations))
                orch.store.close()
        finally:
            registry.all_collectors = ORIGINAL_ALL
            orch_mod.all_collectors = ORIGINAL_ALL


class ThreadedScanTest(unittest.TestCase):
    """The dashboard triggers scans from worker threads; the evidence store
    must be thread-safe (regression test for SQLite same-thread error)."""

    def test_scan_from_worker_thread(self):
        import threading

        _use_collectors([FakeWindowsHostCollector()])
        try:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                orch = Orchestrator(workspace=Path(tmp))
                errors = []

                def worker():
                    try:
                        session = orch.run(mode="scan")
                        assert session.verdict is not None
                    except Exception as exc:  # noqa: BLE001
                        errors.append(exc)

                threads = [threading.Thread(target=worker) for _ in range(2)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=30)
                self.assertEqual(errors, [])
                orch.store.close()
        finally:
            registry.all_collectors = ORIGINAL_ALL
            orch_mod.all_collectors = ORIGINAL_ALL


class NonWindowsDegradationTest(unittest.TestCase):
    """With NO collectors available the pipeline still completes: verdict is
    evidence-poor and every source is listed as a limitation."""

    def test_empty_host_still_reports(self):
        _use_collectors([])
        try:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                orch = Orchestrator(workspace=Path(tmp))
                session = orch.run(mode="scan")
                self.assertIsNotNone(session.verdict)
                self.assertEqual(session.evidence_count, 0)
                self.assertLessEqual(session.verdict.score, 10.0)
                orch.store.close()
        finally:
            registry.all_collectors = ORIGINAL_ALL
            orch_mod.all_collectors = ORIGINAL_ALL


if __name__ == "__main__":
    unittest.main()
