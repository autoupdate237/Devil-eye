"""SQLite-backed Evidence Store.

Every Evidence, Indicator, Verdict, telemetry-availability row and limitation
lands here so the Evidence Viewer and forensic re-runs can reconstruct the
full chain: detection → indicators → evidence ids → raw payloads.

Thread-safety: the dashboard triggers scans from worker threads, so the
connection is opened with ``check_same_thread=False`` and every access is
serialised through a lock.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.models import Evidence, Indicator, TelemetryAvailability, TelemetryLimitation, Verdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id TEXT PRIMARY KEY, mode TEXT, started REAL, finished REAL,
  policy_json TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, scan_id TEXT, kind TEXT, source TEXT, collector TEXT,
  ts REAL, pid INTEGER, process_path TEXT, hash_sha256 TEXT, username TEXT,
  data_json TEXT
);
CREATE TABLE IF NOT EXISTS indicators(
  id TEXT PRIMARY KEY, scan_id TEXT, rule_id TEXT, rule_name TEXT, category TEXT,
  severity REAL, confidence REAL, title TEXT, description TEXT, subject_key TEXT,
  pid INTEGER, process_path TEXT, hash_sha256 TEXT, location TEXT,
  evidence_json TEXT, extras_json TEXT, suppressed INTEGER, risk_contribution REAL,
  corroboration REAL, dampening REAL, ts REAL
);
CREATE TABLE IF NOT EXISTS telemetry_status(
  scan_id TEXT, name TEXT, available INTEGER, reason TEXT, weight REAL, category TEXT
);
CREATE TABLE IF NOT EXISTS limitations(
  scan_id TEXT, source TEXT, reason TEXT, impact TEXT
);
CREATE TABLE IF NOT EXISTS verdicts(
  scan_id TEXT PRIMARY KEY, level TEXT, score REAL, confidence REAL,
  coverage REAL, rationale_json TEXT, subject_scores_json TEXT, ts REAL
);
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_subject ON evidence(scan_id, process_path);
CREATE INDEX IF NOT EXISTS idx_indicators_scan ON indicators(scan_id);
"""


class EvidenceStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # ------------------------------------------------------------------
    def begin_scan(self, scan_id: str, mode: str, policy_json: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO scans(id, mode, started, policy_json) VALUES (?,?,?,?)",
                (scan_id, mode, time.time(), policy_json),
            )
            self.conn.commit()

    def finish_scan(self, scan_id: str, notes: str = "") -> None:
        with self._lock:
            self.conn.execute("UPDATE scans SET finished=?, notes=? WHERE id=?", (time.time(), notes, scan_id))
            self.conn.commit()

    # ------------------------------------------------------------------
    def add_evidence(self, scan_id: str, evidences: List[Evidence]) -> None:
        rows = [
            (e.id, scan_id, e.kind, e.source, e.collector, e.ts, e.pid, e.process_path,
             e.hash_sha256, e.user, json.dumps(e.data, ensure_ascii=False, default=str))
            for e in evidences
        ]
        with self._lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows
            )
            self.conn.commit()

    def add_indicators(self, scan_id: str, indicators: List[Indicator]) -> None:
        rows = [
            (i.id, scan_id, i.rule_id, i.rule_name, i.category, i.severity, i.confidence,
             i.title, i.description, i.subject_key, i.pid, i.process_path, i.hash_sha256,
             i.location, json.dumps(i.evidence_ids), json.dumps(i.extras, default=str),
             int(i.suppressed), round(i.risk_contribution, 3), round(i.corroboration, 3),
             round(i.allowlist_dampening, 3), i.ts)
            for i in indicators
        ]
        with self._lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO indicators VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
            )
            self.conn.commit()

    def add_availability(self, scan_id: str, rows: List[TelemetryAvailability]) -> None:
        with self._lock:
            self.conn.executemany(
                "INSERT INTO telemetry_status VALUES (?,?,?,?,?,?)",
                [(scan_id, a.name, int(a.available), a.reason, a.weight, a.category) for a in rows],
            )
            self.conn.commit()

    def add_limitations(self, scan_id: str, rows: List[TelemetryLimitation]) -> None:
        with self._lock:
            self.conn.executemany(
                "INSERT INTO limitations VALUES (?,?,?,?)",
                [(scan_id, l.source, l.reason, l.impact) for l in rows],
            )
            self.conn.commit()

    def add_verdict(self, scan_id: str, verdict: Verdict) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, verdict.level, verdict.score, verdict.confidence, verdict.telemetry_coverage,
                 json.dumps(verdict.rationale, ensure_ascii=False),
                 json.dumps(verdict.subject_scores), verdict.ts),
            )
            self.conn.commit()

    # ------------------------------------------------------------------
    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self.conn.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def evidence_for(self, scan_id: str, evidence_ids: List[str]) -> List[Dict[str, Any]]:
        if not evidence_ids:
            return []
        marks = ",".join("?" * len(evidence_ids))
        return self.query(
            f"SELECT * FROM evidence WHERE scan_id=? AND id IN ({marks})",
            (scan_id, *evidence_ids),
        )

    def close(self) -> None:
        self.conn.close()
