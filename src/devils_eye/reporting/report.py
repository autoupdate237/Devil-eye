"""Report builder: JSON (machine) + self-contained HTML (human) reports.

Both reports contain every section demanded by requirement 15: system
overview, protected application info, process tree, loaded modules, signature
results, file hashes, drivers, persistence findings, network correlation,
telemetry availability, suspicious indicators, risk/confidence scores and the
final verdict — each indicator rendered in the mandatory 5-part format
(What → Where → Evidence → Confidence → Risk contribution).
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Dict, List

from ..core.config import Policy
from ..core.models import Indicator

VERDICT_COLOR = {
    "CLEAN": ("#22c55e", "rgba(34,197,94,.25)"),
    "LOW RISK": ("#a3e635", "rgba(163,230,53,.22)"),
    "SUSPICIOUS": ("#facc15", "rgba(250,204,21,.22)"),
    "HIGH RISK": ("#fb923c", "rgba(251,146,60,.25)"),
    "CRITICAL": ("#ef4444", "rgba(239,68,68,.3)"),
}
CATEGORY_COLOR = {
    "memory_integrity": "#f472b6", "module_integrity": "#c084fc",
    "driver": "#ef4444", "signature": "#fb923c", "persistence": "#facc15",
    "process_integrity": "#60a5fa", "ancestry": "#38bdf8", "command_line": "#22d3ee",
    "network": "#34d399", "telemetry": "#a78bfa", "wmi": "#fbbf24",
    "service": "#f97316", "scheduled_task": "#fde047", "file_integrity": "#4ade80",
}


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
            sig = p.signature_status or ("Valid" if p.signed else "NotSigned")
            tree_lines.append("  " * min(depth, 8) + f"[{p.pid}] {p.name or p.path}  ·  {sig}")
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
        color, glow = VERDICT_COLOR.get(v["level"], ("#95a5a6", "rgba(149,165,166,.2)"))
        score = max(0.0, min(100.0, float(v.get("score") or 0)))
        circ = 2 * 3.141592653589793 * 54
        dash = circ * (1 - score / 100.0)

        # --- verdict hero -------------------------------------------------
        rationale = "".join(
            f'<li><span class="dot"></span>{esc(r)}</li>' for r in v.get("rationale", [])
        ) or '<li class="muted">No indicators fired above allowlist/reputation suppression.</li>'

        kpis = (
            ("Evidence items", p["scan"]["evidence_count"]),
            ("Indicators", len(p["indicators"])),
            ("Suppressed", len(p["suppressed_indicators"])),
            ("Telemetry coverage", f"{100 * float(v.get('telemetry_coverage') or 0):.0f}%"),
            ("Confidence", f"{100 * float(v.get('confidence') or 0):.0f}%"),
            ("Host processes", p["system_overview"]["process_count"]),
        )
        kpi_html = "".join(
            f'<div class="kpi"><span>{esc(str(k))}</span><b>{esc(str(val))}</b></div>'
            for k, val in kpis
        )

        # --- indicator cards ----------------------------------------------
        def sev_color(s: float) -> str:
            return "#ef4444" if s >= 8 else "#fb923c" if s >= 6 else "#facc15" if s >= 4 else "#a3e635"

        cards = []
        for i in p["indicators"]:
            c = CATEGORY_COLOR.get(i["category"], "#94a3b8")
            cards.append(f'''
            <div class="card ind">
              <div class="ind-top">
                <span class="badge" style="--c:{c}">{esc(i["category"])}</span>
                <span class="rid">{esc(i["rule_id"])}</span>
                <span class="spacer"></span>
                <span class="chip">conf {100 * float(i["confidence"]):.0f}%</span>
                <span class="chip">+{float(i["risk_contribution"]):.1f} pts</span>
                <span class="chip">\u00d7{float(i["corroboration"]):.2f}</span>
              </div>
              <div class="sevbar"><i style="width:{10 * float(i["severity"])}%;background:{sev_color(float(i["severity"]))}"></i></div>
              <h3>{esc(i["title"])}</h3>
              <p class="muted">{esc(i["description"])}</p>
              <div class="ind-meta">
                <span title="Where">📍 {esc(i["location"] or i["process_path"] or "host-wide")}</span>
                <span title="Evidence">🔗 {len(i["evidence_ids"])} evidence item{"" if len(i["evidence_ids"]) == 1 else "s"}</span>
                <span title="Severity">⚡ severity {float(i["severity"]):.1f}/10</span>
              </div>
            </div>''')
        indicators_html = "".join(cards) or '<div class="card"><p class="muted">No suspicious indicators — everything inspected checked out. 😇</p></div>'

        # --- tables ---------------------------------------------------------
        def table(headers: List[str], rows: List[List[str]], empty: str = "none") -> str:
            body = "".join(
                "<tr>" + "".join(f"<td>{esc(str(c))}</td>" for c in r) + "</tr>" for r in rows
            ) or f'<tr><td colspan="{len(headers)}" class="muted">{esc(empty)}</td></tr>'
            return ("<table><thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) +
                    "</tr></thead><tbody>" + body + "</tbody></table>")

        sig_rows = [
            [s["path"], s["status"], s["publisher"] or "—", "✅" if s["chain_valid"] else "❌"]
            for s in p["signatures"]
        ]
        drv_rows = [
            [d["name"], d["path"], d["state"], d["signature"]] for d in p["drivers"]
        ]
        pers_rows = [
            [x["category"], x["key"], x["value"], str(x["data"])[:120]] for x in p["persistence"]
        ]
        net_rows = [
            [n["pid"], n["process"], n["remote"], n["state"]] for n in p["network"]
        ]
        tel_rows = [
            [a["name"], ("✅ available" if a["available"] else "❌ unavailable"), a["reason"]]
            for a in p["telemetry_availability"]
        ]
        sup_rows = [
            [s["rule"], s["title"], s["reason"]] for s in p["suppressed_indicators"]
        ]
        corr_rows = [
            [g["subject_key"], len(g["indicator_ids"]), f"{float(g['score']):.1f}", f"\u00d7{float(g['corroboration_factor']):.2f}"]
            for g in p["correlation_groups"]
        ]

        limits = "".join(
            f'<li><b>{esc(l["source"])}</b> — {esc(l["reason"])} <span class="muted">({esc(l["impact"])})</span></li>'
            for l in p["telemetry_limitations"]
        ) or '<li class="muted">none</li>'
        tree = "\n".join(p["process_tree"]) or "(no processes captured)"

        protected = ", ".join(
            (pr.get("name") or "?") for pr in (p["policy"].get("protected_processes") or [])
        ) or "—"
        cov = float(v.get("telemetry_coverage") or 0)

        return f'''<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Devil's Eye — Integrity Report {esc(p["scan"]["scan_id"])}</title>
<style>
:root {{
  --bg:#07090f; --panel:rgba(255,255,255,.035); --panel2:rgba(255,255,255,.06);
  --border:rgba(255,255,255,.08); --text:#e8eaf0; --muted:#8b93a7;
  --accent:{color}; --glow:{glow};
}}
* {{ box-sizing:border-box; }}
body {{
  margin:0; background:var(--bg); color:var(--text);
  font:14px/1.6 "Segoe UI",system-ui,-apple-system,sans-serif;
}}
body::before {{
  content:""; position:fixed; inset:0; z-index:-1;
  background:
    radial-gradient(900px 500px at 85% -10%, rgba(231,76,60,.14), transparent 60%),
    radial-gradient(700px 420px at -10% 30%, rgba(124,58,237,.12), transparent 60%),
    radial-gradient(800px 500px at 50% 115%, rgba(37,99,235,.10), transparent 60%);
}}
.wrap {{ max-width:1080px; margin:0 auto; padding:34px 26px 80px; }}
header.hero {{
  display:flex; align-items:center; gap:16px; padding:8px 0 26px;
  border-bottom:1px solid var(--border); margin-bottom:26px;
}}
.logo {{
  width:52px; height:52px; border-radius:14px; display:grid; place-items:center;
  font-size:27px; background:linear-gradient(145deg,#1a1030,#0c0f1d);
  border:1px solid var(--border); box-shadow:0 0 34px rgba(231,76,60,.35);
}}
.hero h1 {{ margin:0; font-size:21px; letter-spacing:.02em; }}
.hero h1 b {{ background:linear-gradient(90deg,#ff5c4d,#c084fc); -webkit-background-clip:text; background-clip:text; color:transparent; }}
.hero .sub {{ color:var(--muted); font-size:12.5px; letter-spacing:.06em; }}
.verdict-hero {{
  display:grid; grid-template-columns:1fr 240px; gap:22px; margin-bottom:26px;
}}
.card {{
  background:var(--panel); border:1px solid var(--border); border-radius:18px;
  padding:20px 22px; backdrop-filter:blur(8px);
}}
.verdict-card {{ position:relative; overflow:hidden; }}
.verdict-card::after {{
  content:""; position:absolute; inset:auto -30% -70% -30%; height:160px;
  background:var(--glow); filter:blur(50px); pointer-events:none;
}}
.verdict-label {{ font-size:12px; letter-spacing:.22em; text-transform:uppercase; color:var(--muted); }}
.verdict-level {{
  font-size:44px; font-weight:800; line-height:1.15; color:var(--accent);
  text-shadow:0 0 42px var(--glow); margin:4px 0 14px;
}}
.verdict-pill {{
  display:inline-block; padding:5px 14px; border-radius:999px; font-size:12.5px;
  font-weight:700; letter-spacing:.06em; color:#07090f; background:var(--accent);
  box-shadow:0 0 26px var(--glow);
}}
.rationale {{ margin:18px 0 0; padding:0; list-style:none; }}
.rationale li {{ padding:7px 0; border-top:1px dashed var(--border); font-size:13.5px; }}
.rationale .dot {{
  display:inline-block; width:7px; height:7px; border-radius:50%;
  background:var(--accent); margin-right:10px; box-shadow:0 0 10px var(--glow);
}}
.ring-box {{ display:grid; place-items:center; }}
.ring {{ position:relative; width:180px; height:180px; }}
.ring svg {{ transform:rotate(-90deg); }}
.ring .track {{ stroke:rgba(255,255,255,.07); }}
.ring .val {{
  stroke:var(--accent); stroke-linecap:round;
  filter:drop-shadow(0 0 10px var(--glow));
  transition:stroke-dashoffset .8s ease;
}}
.ring .center {{
  position:absolute; inset:0; display:grid; place-items:center; text-align:center;
}}
.ring .center b {{ font-size:34px; }}
.ring .center span {{ color:var(--muted); font-size:11.5px; letter-spacing:.14em; text-transform:uppercase; }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:30px; }}
.kpi {{
  background:var(--panel); border:1px solid var(--border); border-radius:14px;
  padding:13px 16px;
}}
.kpi span {{ color:var(--muted); font-size:11px; letter-spacing:.12em; text-transform:uppercase; }}
.kpi b {{ display:block; font-size:21px; margin-top:2px; }}
h2 {{
  font-size:13px; letter-spacing:.18em; text-transform:uppercase; color:var(--muted);
  margin:38px 0 14px; display:flex; align-items:center; gap:10px;
}}
h2::before {{
  content:""; width:22px; height:2px; border-radius:2px;
  background:linear-gradient(90deg,var(--accent),transparent);
}}
.ind {{ margin-bottom:14px; }}
.ind-top {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }}
.badge {{
  --c:#94a3b8; font-size:11px; font-weight:700; letter-spacing:.08em;
  padding:3px 10px; border-radius:999px; color:var(--c);
  background:color-mix(in srgb, var(--c) 14%, transparent);
  border:1px solid color-mix(in srgb, var(--c) 38%, transparent);
}}
.rid {{ font-family:ui-monospace,Consolas,monospace; font-size:11.5px; color:var(--muted); }}
.spacer {{ flex:1; }}
.chip {{
  font-size:11.5px; padding:3px 9px; border-radius:8px; background:var(--panel2);
  border:1px solid var(--border); color:var(--text);
}}
.sevbar {{ height:4px; border-radius:3px; background:rgba(255,255,255,.06); margin:12px 0 10px; overflow:hidden; }}
.sevbar i {{ display:block; height:100%; border-radius:3px; box-shadow:0 0 12px rgba(239,68,68,.45); }}
.ind h3 {{ margin:2px 0 4px; font-size:16px; }}
.ind-meta {{ display:flex; gap:18px; flex-wrap:wrap; font-size:12.5px; color:var(--muted); margin-top:8px; }}
table {{ width:100%; border-collapse:separate; border-spacing:0; overflow:hidden; border-radius:14px; border:1px solid var(--border); }}
th, td {{ padding:9px 13px; text-align:left; font-size:13px; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ background:var(--panel2); color:var(--muted); font-size:11.5px; letter-spacing:.1em; text-transform:uppercase; }}
tbody tr:last-child td {{ border-bottom:none; }}
tbody tr:hover td {{ background:rgba(255,255,255,.03); }}
pre {{
  background:rgba(0,0,0,.35); border:1px solid var(--border); border-radius:14px;
  padding:16px 18px; overflow:auto; font-size:12.5px; line-height:1.7;
}}
.muted {{ color:var(--muted); }}
ul.plain {{ padding-left:18px; }}
ul.plain li {{ margin:5px 0; }}
footer {{
  margin-top:46px; padding-top:18px; border-top:1px solid var(--border);
  color:var(--muted); font-size:12px; display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap;
}}
@media (max-width:820px) {{ .verdict-hero {{ grid-template-columns:1fr; }} }}
</style></head><body><div class="wrap">

<header class="hero">
  <div class="logo">😈</div>
  <div>
    <h1><b>Devil's Eye</b> — Integrity Report</h1>
    <div class="sub">
      SCAN {esc(p["scan"]["scan_id"])} · MODE {esc(p["scan"]["mode"].upper())} · {esc(p["generated"])} ·
      HOST {esc(str(p["system_overview"]["hostname"]))} · {esc(str(p["system_overview"]["os"]))}
    </div>
  </div>
</header>

<section class="verdict-hero">
  <div class="card verdict-card">
    <div class="verdict-label">Final verdict</div>
    <div class="verdict-level">{esc(v["level"])}</div>
    <span class="verdict-pill">evidence-driven · explainable</span>
    <ul class="rationale">{rationale}</ul>
  </div>
  <div class="card ring-box">
    <div class="ring">
      <svg width="180" height="180">
        <circle class="track" cx="90" cy="90" r="54" fill="none" stroke-width="10"/>
        <circle class="val" cx="90" cy="90" r="54" fill="none" stroke-width="10"
                stroke-dasharray="{circ:.2f}" stroke-dashoffset="{dash:.2f}"/>
      </svg>
      <div class="center"><div><b>{score:.1f}</b><span>risk / 100</span></div></div>
    </div>
  </div>
</section>

<section class="kpis">{kpi_html}</section>

<h2>Protected application policy</h2>
<div class="card"><p style="margin:0">
  Monitoring targets: <b>{esc(protected)}</b> · sensitivity <b>{esc(str(p["policy"].get("sensitivity")))}</b>
  · trusted publishers <b>{p["policy"]["trusted_publishers_count"]}</b>
  · trusted directories <b>{p["policy"]["trusted_directories_count"]}</b>
</p></div>

<h2>Suspicious indicators — What → Where → Evidence → Confidence → Risk</h2>
{indicators_html}

<h2>Correlation groups</h2>
{table(["Subject (hash / path)", "Indicators", "Risk pts", "Corroboration"], corr_rows, "no correlated subjects")}

<h2>Process tree</h2>
<pre>{esc(tree)}</pre>

<h2>Code signatures</h2>
{table(["Path", "Status", "Publisher", "Chain"], sig_rows, "no binaries checked")}

<h2>Drivers</h2>
{table(["Name", "Path", "State", "Signature"], drv_rows, "no drivers captured")}

<h2>Persistence findings</h2>
{table(["Category", "Key", "Value", "Data"], pers_rows, "no persistence entries captured")}

<h2>Network correlation</h2>
{table(["PID", "Process", "Remote", "State"], net_rows, "no endpoints captured")}

<h2>Telemetry availability</h2>
{table(["Source", "Status", "Note"], tel_rows, "no sources reported")}

<h2>Telemetry limitations</h2>
<div class="card"><ul class="plain">{limits}</ul></div>

<h2>Suppressed by allowlist / reputation (audit trail)</h2>
{table(["Rule", "Indicator", "Why suppressed"], sup_rows, "nothing suppressed")}

<footer>
  <span>Devil's Eye is a defensive, read-only integrity monitor. No verdict here is automatic
  enforcement — it is explainable evidence for an operator.</span>
  <span>coverage {100 * cov:.0f}% · confidence {100 * float(v.get("confidence") or 0):.0f}%</span>
</footer>
</div></body></html>'''
