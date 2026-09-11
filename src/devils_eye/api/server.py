"""Local dashboard API.

Security: binds to 127.0.0.1 by default (desktop app). It never accepts
uploads, never executes client-supplied commands, and only reads from the
session database. ``--host 0.0.0.0`` exists for sandboxed previews/CI.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from ..core.config import Policy
from ..pipeline.orchestrator import Orchestrator

UI_DIR = Path(__file__).resolve().parents[1] / "ui" / "static"


class DashboardState:
    def __init__(self, orchestrator: Orchestrator):
        self.orchestrator = orchestrator
        self.sessions = []
        self.running = False
        self.lock = threading.Lock()

    @property
    def latest(self):
        return self.sessions[-1] if self.sessions else None

    def run_scan(self, mode: str = "scan"):
        with self.lock:
            if self.running:
                return None
            self.running = True
        try:
            session = self.orchestrator.run(mode=mode)
            self.sessions.append(session)
            return session
        finally:
            self.running = False


def make_handler(state: DashboardState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DevilsEye/0.1"

        # ---------------- helpers ----------------
        def _json(self, obj, code=200):
            body = json.dumps(obj, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _static(self, rel: str):
            path = (UI_DIR / rel).resolve()
            if not str(path).startswith(str(UI_DIR.resolve())) or not path.is_file():
                self.send_error(404)
                return
            ctype = {
                ".html": "text/html; charset=utf-8", ".js": "application/javascript",
                ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png",
            }.get(path.suffix, "application/octet-stream")
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):  # quiet
            pass

        # ---------------- GET ----------------
        def do_GET(self):
            url = urlparse(self.path)
            qs = parse_qs(url.query)
            p = url.path
            store = state.orchestrator.store
            scan_id = (qs.get("scan_id") or ([state.latest.scan_id] if state.latest else [""]))[0]
            try:
                if p == "/api/status":
                    return self._json({
                        "running": state.running,
                        "scan_count": len(state.sessions),
                        "latest": state.latest.to_dict() if state.latest else None,
                    })
                if p == "/api/verdict":
                    return self._json(state.latest.verdict.to_dict() if state.latest and state.latest.verdict else {})
                if p == "/api/indicators":
                    rows = store.query(
                        "SELECT * FROM indicators WHERE scan_id=? AND suppressed=0 ORDER BY risk_contribution DESC",
                        (scan_id,))
                    return self._json(rows)
                if p == "/api/indicators/suppressed":
                    rows = store.query("SELECT * FROM indicators WHERE scan_id=? AND suppressed=1", (scan_id,))
                    return self._json(rows)
                if p == "/api/evidence":
                    subject = (qs.get("subject") or [""])[0].lower()
                    if subject:
                        rows = store.query(
                            "SELECT * FROM evidence WHERE scan_id=? AND lower(process_path)=?",
                            (scan_id, subject))
                    else:
                        rows = store.query("SELECT * FROM evidence WHERE scan_id=?", (scan_id,))
                    for r in rows:
                        try:
                            r["data"] = json.loads(r.get("data_json") or "{}")
                        except json.JSONDecodeError:
                            r["data"] = {}
                    return self._json(rows[:500])
                if p == "/api/telemetry":
                    rows = store.query("SELECT * FROM telemetry_status WHERE scan_id=?", (scan_id,))
                    limits = store.query("SELECT * FROM limitations WHERE scan_id=?", (scan_id,))
                    return self._json({"availability": rows, "limitations": limits})
                if p == "/api/correlation":
                    rows = store.query(
                        "SELECT subject_key, COUNT(*) n, SUM(risk_contribution) pts FROM indicators "
                        "WHERE scan_id=? AND suppressed=0 GROUP BY subject_key ORDER BY pts DESC", (scan_id,))
                    return self._json(rows)
                if p in ("/api/report", "/api/report.json"):
                    want = ".json" if p.endswith(".json") else ".html"
                    if state.latest and state.latest.report_paths:
                        for cand in state.latest.report_paths:
                            if cand.endswith(want):
                                data = Path(cand).read_bytes()
                                self.send_response(200)
                                self.send_header(
                                    "Content-Type",
                                    "application/json" if want == ".json" else "text/html; charset=utf-8",
                                )
                                self.send_header("Content-Length", str(len(data)))
                                self.end_headers()
                                self.wfile.write(data)
                                return
                    return self._json({"error": "no report yet"}, 404)
                if p == "/api/allowlist":
                    from ..allowlist.reputation import ReputationService
                    rep = ReputationService(state.orchestrator.policy)
                    return self._json([e.to_dict() for e in rep.entries])
                if p == "/api/policy":
                    return self._json(state.orchestrator.policy.raw)
                if p.startswith("/api/"):
                    return self._json({"error": "unknown endpoint"}, 404)
                rel = p.lstrip("/") or "index.html"
                return self._static(rel)
            except BrokenPipeError:
                return
            except Exception as exc:  # noqa: BLE001 — API must not kill the server
                return self._json({"error": str(exc)}, 500)

        # ---------------- POST ----------------
        def do_POST(self):
            url = urlparse(self.path)
            if url.path == "/api/scan":
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b"{}"
                try:
                    mode = json.loads(body or b"{}").get("mode", "scan")
                except json.JSONDecodeError:
                    mode = "scan"
                if state.running:
                    return self._json({"error": "scan already running"}, 409)
                thread = threading.Thread(target=state.run_scan, args=(mode,), daemon=True)
                thread.start()
                return self._json({"started": True, "mode": mode})
            return self._json({"error": "unknown endpoint"}, 404)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080, policy: Optional[Policy] = None,
          initial_scan: bool = True) -> None:
    orchestrator = Orchestrator(policy=policy)
    state = DashboardState(orchestrator)
    if initial_scan:
        state.run_scan(mode="scan")
    server = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"Devil's Eye dashboard: http://{host}:{port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
