"""One-click pipeline orchestration.

Workflow (requirement 17):
 1. environment check            5. correlation
 2. telemetry availability       6. detection rules
 3. collectors (isolated)        7. allowlist + risk scoring
 4. normalization + evidence     8. verdict + report

Modes:
 * scan       — single full pass (default)
 * monitor    — repeated passes, reporting *new* subjects only
 * forensic   — scan + offline artifact emphasis + archived report
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..allowlist.reputation import ReputationService
from ..collectors import all_collectors, run_collector
from ..collectors.base import PipelineContext
from ..core.config import Policy, default_workspace
from ..core.logging_setup import get_logger
from ..core.models import TelemetryAvailability, TelemetryLimitation, Verdict
from ..correlation.engine import CorrelationEngine
from ..detection.engine import DetectionEngine
from ..evidence.store import EvidenceStore
from ..integrity.self_check import self_check
from ..normalization.normalizer import Normalizer
from ..scoring.risk import ScoringEngine
from ..telemetry.availability import compute_coverage
from ..verdict.engine import VerdictEngine

log = get_logger("pipeline")


@dataclass
class ScanSession:
    scan_id: str
    mode: str
    started: float = field(default_factory=time.time)
    store_path: str = ""
    verdict: Optional[Verdict] = None
    coverage: float = 0.0
    indicators_total: int = 0
    indicators_suppressed: int = 0
    evidence_count: int = 0
    availability: List[TelemetryAvailability] = field(default_factory=list)
    limitations: List[TelemetryLimitation] = field(default_factory=list)
    self_integrity: Dict[str, List[str]] = field(default_factory=dict)
    report_paths: List[str] = field(default_factory=list)
    new_subjects: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id, "mode": self.mode, "started": self.started,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "coverage": self.coverage,
            "indicators_total": self.indicators_total,
            "indicators_suppressed": self.indicators_suppressed,
            "evidence_count": self.evidence_count,
            "availability": [a.to_dict() for a in self.availability],
            "limitations": [l.to_dict() for l in self.limitations],
            "self_integrity": self.self_integrity,
            "report_paths": self.report_paths,
            "new_subjects": self.new_subjects,
        }


class Orchestrator:
    def __init__(self, policy: Optional[Policy] = None, workspace: Optional[Path] = None,
                 etw: bool = False):
        self.policy = policy or Policy.load()
        if etw:
            self.policy.raw["etw_enabled"] = True
        self.workspace = Path(workspace) if workspace else default_workspace()
        self.store = EvidenceStore(self.workspace / "evidence.db")
        self._known_subjects: set = set()

    # ------------------------------------------------------------------
    def run(self, mode: str = "scan") -> ScanSession:
        session = ScanSession(scan_id=uuid.uuid4().hex[:12], mode=mode)
        session.store_path = str(self.store.path)
        self.store.begin_scan(session.scan_id, mode, json.dumps(self.policy.raw, default=str))
        ctx = PipelineContext(policy=self.policy, mode=mode, workspace=self.workspace)

        # 1. environment check
        from ..core.platform_info import is_elevated, is_windows, os_description, username

        session.self_integrity = self_check(self.workspace)
        env_note = (
            f"os={os_description()} user={username()} elevated={is_elevated()} "
            f"windows={is_windows()}"
        )
        log.info("environment: %s", env_note)

        # 2-3. collectors (isolated)
        evidences = []
        for collector in all_collectors():
            result = run_collector(collector, ctx)
            session.availability.extend(result.availability)
            for err in result.errors:
                session.limitations.append(
                    TelemetryLimitation(collector.name, err, "source skipped for this scan")
                )
            evidences.extend(result.evidences)
        session.evidence_count = len(evidences)
        self.store.add_evidence(session.scan_id, evidences)
        self.store.add_availability(session.scan_id, session.availability)

        # 2'. telemetry coverage
        self.coverage, coverage_limitations = compute_coverage(session.availability)
        session.coverage = self.coverage
        session.limitations.extend(coverage_limitations)

        # 4. normalization
        snapshot = Normalizer().build(evidences, self.policy.protected_names)

        # 5. correlation
        # (indicators first, then grouped — grouping needs fired indicators)
        # 6. detection rules
        indicators, rule_limitations = DetectionEngine(self.policy).run(snapshot)
        session.limitations.extend(rule_limitations)

        groups = CorrelationEngine().run(snapshot, indicators)

        # 7. allowlist + scoring
        reputation = ReputationService(self.policy)
        reputation.apply(indicators)
        scoring = ScoringEngine(self.policy).score(indicators, groups)
        session.indicators_total = len(indicators)
        session.indicators_suppressed = scoring.suppressed_count

        # new-subject tracking (monitor mode)
        for ind in indicators:
            key = ind.subject_key or ind.process_path.lower()
            if key and key not in self._known_subjects:
                self._known_subjects.add(key)
                session.new_subjects.append(key)

        # confidence = mean confidence of top contributors × coverage curve
        top = scoring.top_indicators
        base_conf = (sum(i.confidence for i in top) / len(top)) if top else 1.0
        confidence = min(1.0, base_conf * (0.5 + 0.5 * self.coverage))

        # 8. verdict
        verdict_engine = VerdictEngine(self.policy)
        session.verdict = verdict_engine.decide(
            scoring.global_score, confidence, self.coverage, top, session.limitations
        )
        session.verdict.subject_scores = scoring.subject_scores
        self.store.add_indicators(session.scan_id, indicators)
        self.store.add_limitations(session.scan_id, session.limitations)
        self.store.add_verdict(session.scan_id, session.verdict)

        # 9. report
        from ..reporting.report import ReportBuilder

        builder = ReportBuilder(self.workspace, self.policy)
        session.report_paths = builder.build(session, snapshot, indicators, scoring, groups, self.store)
        self.store.finish_scan(session.scan_id, f"verdict={session.verdict.level}")
        log.info(
            "scan %s complete: %s score=%.1f coverage=%.2f indicators=%d (suppressed %d)",
            session.scan_id, session.verdict.level, session.verdict.score,
            self.coverage, session.indicators_total, session.indicators_suppressed,
        )
        return session

    # ------------------------------------------------------------------
    def monitor(self, interval: float = 10.0, iterations: Optional[int] = None):
        """Real-time mode: repeated scans; yields sessions. ``iterations`` is
        for tests/CI (None = forever)."""
        count = 0
        while iterations is None or count < iterations:
            session = self.run(mode="monitor")
            yield session
            count += 1
            if iterations is None or count < iterations:
                time.sleep(interval)
