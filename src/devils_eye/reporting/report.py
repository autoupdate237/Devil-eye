"""Report builder: JSON (machine) + self-contained HTML (human) reports.

Both reports contain every section demanded by requirement 15: system
overview, protected application info, process tree, loaded modules, signature
results, file hashes, drivers, persistence findings, network correlation,
telemetry availability, suspicious indicators, risk/confidence scores and the
final verdict — each indicator rendered in the mandatory 5-part format.
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Dict, List

from ..core.config import Policy
from ..core.models import Indicator


class ReportBuilder:
    def __init__(self, workspace: Path, policy: Policy):
        self.workspace = Path(workspace)
        self.policy = policy

    # ------------------------------------------------------------------
    def build(self, session, snapshot, indicators: List[Indicator], scoring, groups, store) -> List[str]:
        out_dir = self.workspace / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = self._payload(session, snapshot, indicators, scoring, groups, store)
        json_path = out_dir / f"report-{session.scan_id}.json"
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        html_path = out_dir / f"report-{session.scan_id}.html"
        html_path.write_text(self._html(payload), encoding="utf-8")
        return [str(json_path), str(html_path)]

    # ------------------------------------------------------------------
    def _payload(self, session, snapshot, indicators, scoring, groups, store) -> Dict:
        processes = sorted(snapshot.processes.values(), key=lambda p: p.pid)
        tree_lines = []
        for p in processes:
            depth = 0
            cur = p
            seen = set()
            while cur.ppid and cur.ppid in snapshot.processes and cur.pid not in seen:
                seen.add(cur.pid)
                cur = snapshot.processes[cur.ppid]
                depth += 1
                if depth > 12:
                    break
            tree_lines.append("  " * min(depth, 8) + f"[{p.pid}] {p.name or p.path} ({p.signature_status or 'sig?'})")
        active = [i for i in indicators if not i.suppressed]
        return {
            "scan": session.to_dict(),
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "policy": {
                "protected_processes": self.policy.get("protected_processes"),
                "sensitivity": self.policy.get("sensitivity"),
                "trusted_publishers_count": len(self.policy.trusted_publishers),
                "trusted_directories_count": len(self.policy.trusted_directories),
            },
            "system_overview": {
                "hostname": (snapshot.system[0].data.get("hostname") if snapshot.system else "n/a"),
                "os": (snapshot.system[0].data.get("os") if snapshot.system else "n/a"),
                "process_count": len(processes),
                "module_count": sum(len(p.modules) for p in processes),
            },
            "process_tree": tree_lines,
            "modules": [
                {
                    "process": f"[{m.pid}] {m.name}",
                    "items": [
                        {
                            "module": md.data.get("name"),
                            "path": md.data.get("module_path"),
                            "signature": md.data.get("signature_status") or ("Valid" if md.data.get("signed") else "NotSigned" if md.data.get("signed") is False else "unknown"),
                            "publisher": md.data.get("publisher") or "",
                            "sha256": md.data.get("sha256") or "",
                        }
                        for md in m.modules
                    ],
                }
                for m in processes if m.modules
            ],
            "signatures": [
                {"path": ev.data.get("path"), "status": ev.data.get("status"),
                 "publisher": ev.data.get("publisher"), "chain_valid": ev.data.get("chain_valid")}
                for ev in snapshot.signatures.values()
            ],
            "drivers": [
                {"name": ev.data.get("name"), "path": ev.data.get("image_path"),
                 "state": ev.data.get("state"), "start": ev.data.get("start"),
                 "signature": ev.data.get("signature_status") or ("Valid" if ev.data.get("signed") else "NotSigned")}
                for ev in snapshot.drivers
            ],
            "persistence": [
                {"category": ev.data.get("category"), "key": f"{ev.data.get('hive')}\\{ev.data.get('key')}",
                 "value": ev.data.get("value"), "data": ev.data.get("data")}
                for ev in snapshot.persistence
            ],
            "network": [
                {"pid": n.pid, "process": n.process_path, "remote": n.data.get("remote"),
                 "state": n.data.get("state")}
                for p in processes for n in p.network
            ],
            "telemetry_availability": [a.to_dict() for a in session.availability],
            "telemetry_limitations": [l.to_dict() for l in session.limitations],
            "indicators": [i.to_dict() for i in active],
            "suppressed_indicators": [
                {"id": i.id, "rule": i.rule_id, "title": i.title, "reason": i.suppressed_reason}
                for i in indicators if i.suppressed
            ],
            "correlation_groups": [g.to_dict() for g in groups.values() if g.indicator_ids],
            "verdict": session.verdict.to_dict() if session.verdict else None,
        }

    # ------------------------------------------------------------------
    def _html(self, p: Dict) -> str:
        esc = html.escape
        v = p.get("verdict") or {"level": "UNKNOWN", "score": 0, "confidence": 0,
                                 "telemetry_coverage": 0, "rationale": []}
        color = {"CLEAN": "#2ecc71", "LOW RISK": "#a3d977", "SUSPICIOUS": "#f1c40f",
                 "HIGH RISK": "#e67e22", "CRITICAL": "#e74c3c"}.get(v["level"], "#95a5a6")
        rows_ind = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.2f}</td>"
            "<td>{:.1f}</td><td>\u00d7{:.2f}</td></tr>".format(
                esc(i["rule_id"]), esc(i["category"]), esc(i["title"]),
                esc(i["location"]), len(i["evidence_ids"]), i["confidence"],
                i["risk_contribution"], i["corroboration"],
            )
            for i in p["indicators"]
        )
        rows_tel = "".join(
            f"<tr><td>{esc(a['name'])}</td><td>{'✅' if a['available'] else '❌'}</td><td>{esc(a['reason'])}</td></tr>"
            for a in p["telemetry_availability"]
        )
        rows_pers = "".join(
            f"<tr><td>{esc(str(x['category']))}</td><td>{esc(str(x['key']))}</td>"
            f"<td>{esc(str(x['value']))}</td><td>{esc(str(x['data'])[:120])}</td></tr>"
            for x in p["persistence"]
        )
        rows_drv = "".join(
            f"<tr><td>{esc(str(d['name']))}</td><td>{esc(str(d['path']))}</td>"
            f"<td>{esc(str(d['state']))}</td><td>{esc(str(d['signature']))}</td></tr>"
            for d in p["drivers"]
        )
        rows_net = "".join(
            f"<tr><td>{n['pid']}</td><td>{esc(str(n['process']))}</td>"
            f"<td>{esc(str(n['remote']))}</td><td>{esc(str(n['state']))}</td></tr>"
            for n in p["network"]
        )
        rationale = "".join(f"<li>{esc(r)}</li>" for r in v.get("rationale", []))
        tree = "<br>".join(esc(t) for t in p["process_tree"])
        limits = "".join(
            f"<li><b>{esc(l['source'])}</b> — {esc(l['reason'])} <i>({esc(l['impact'])})</i></li>"
            for l in p["telemetry_limitations"]
        )
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Devil's Eye — report {esc(p['scan']['scan_id'])}</title>
<style>
body{{background:#0e1116;color:#d7dae0;font:14px/1.5 'Segoe UI',system-ui,sans-serif;margin:24px}}
h1{{font-size:22px}} h2{{border-bottom:1px solid #2c313a;padding-bottom:6px;margin-top:32px;font-size:16px;color:#9fb3c8;text-transform:uppercase;letter-spacing:.08em}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}
td,th{{border:1px solid #2c313a;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#161b22;color:#9fb3c8}}
.verdict{{display:inline-block;padding:8px 18px;border-radius:8px;background:{color};color:#0e1116;font-weight:700;font-size:18px}}
pre{{background:#161b22;padding:12px;border-radius:8px;overflow:auto}}
.kpi{{display:inline-block;background:#161b22;border:1px solid #2c313a;border-radius:8px;padding:10px 16px;margin-right:10px}}
.kpi b{{display:block;font-size:20px}}
</style></head><body>
<h1>😈 Devil's Eye — Integrity Report</h1>
<p>Scan <b>{esc(p['scan']['scan_id'])}</b> · mode <b>{esc(p['scan']['mode'])}</b> · {esc(p['generated'])} ·
host <b>{esc(str(p['system_overview']['hostname']))}</b> ({esc(str(p['system_overview']['os']))})</p>
<h2>Final verdict</h2>
<span class="verdict">{esc(v['level'])}</span>
<div style="margin-top:12px">
<span class="kpi">Risk score<b>{v['score']:.1f} / 100</b></span>
<span class="kpi">Confidence<b>{v['confidence']:.0%}</b></span>
<span class="kpi">Telemetry coverage<b>{v['telemetry_coverage']:.0%}</b></span>
<span class="kpi">Indicators<b>{len(p['indicators'])} (+{len(p['suppressed_indicators'])} suppressed)</b></span>
</div>
<h3>Rationale</h3><ul>{rationale}</ul>
<h2>Process tree</h2><pre>{tree}</pre>
<h2>Suspicious indicators (What → Where → Evidence → Confidence → Risk)</h2>
<table><tr><th>Rule</th><th>Category</th><th>What</th><th>Where</th><th>Evidence#</th>
<th>Confidence</th><th>Risk pts</th><th>Corroboration</th></tr>{rows_ind}</table>
<h2>Persistence findings</h2><table><tr><th>Category</th><th>Key</th><th>Value</th><th>Data</th></tr>{rows_pers}</table>
<h2>Drivers</h2><table><tr><th>Name</th><th>Path</th><th>State</th><th>Signature</th></tr>{rows_drv}</table>
<h2>Network correlation</h2><table><tr><th>PID</th><th>Process</th><th>Remote</th><th>State</th></tr>{rows_net}</table>
<h2>Telemetry availability</h2><table><tr><th>Source</th><th>Available</th><th>Note</th></tr>{rows_tel}</table>
<h2>Telemetry limitations</h2><ul>{limits or '<li>none</li>'}</ul>
<p style="color:#5c6370">Devil's Eye is a defensive, read-only integrity monitor.
No verdict here is automatic enforcement — it is explainable evidence for an operator.</p>
</body></html>"""
