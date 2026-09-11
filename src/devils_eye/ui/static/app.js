/* Devil's Eye dashboard — vanilla JS, no external dependencies. */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const CATEGORY_PANEL = {
  module_integrity: "modules",
  memory_integrity: "memory",
  driver: "drivers",
  persistence: "persistence",
  service: "persistence",
  scheduled_task: "persistence",
  wmi: "persistence",
};

let liveRows = [];

/* ---------- navigation ---------- */
$$("nav a").forEach((a) =>
  a.addEventListener("click", () => {
    $$("nav a").forEach((x) => x.classList.remove("active"));
    $$(".panel").forEach((p) => p.classList.remove("active"));
    a.classList.add("active");
    $("#panel-" + a.dataset.panel).classList.add("active");
    refresh();
  })
);

/* ---------- actions ---------- */
$("#btn-scan").addEventListener("click", () => startScan("scan"));
$("#btn-monitor").addEventListener("click", () => startScan("monitor"));
$("#ev-filter").addEventListener("change", () => loadEvidence());

async function startScan(mode) {
  toast(`Starting ${mode} pass…`);
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode }),
  });
  const data = await res.json();
  if (data.error) toast("⚠ " + data.error);
  else setTimeout(refreshLoop, 1500);
}

let pollTimer = null;
function refreshLoop() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    const st = await getJSON("/api/status");
    if (st.running) refreshLoop();
    else { refresh(); toast("Scan complete."); }
  }, 1200);
}

/* ---------- data helpers ---------- */
async function getJSON(url) {
  const r = await fetch(url);
  return r.json();
}
function esc(s) {
  const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 3500);
}
function verdictClass(level) {
  return (level || "").replace(" ", "").toUpperCase() || "unknown";
}

/* ---------- refresh ---------- */
async function refresh() {
  const st = await getJSON("/api/status");
  if (!st.latest) return;
  const v = st.latest.verdict || {};
  const pill = $("#verdict-pill");
  pill.textContent = (v.level || "NO SCAN");
  pill.className = "pill " + verdictClass(v.level);
  $("#header-meta").textContent =
    `scan ${st.latest.scan_id} · mode ${st.latest.mode} · ` +
    `${st.latest.indicators_total} indicators (${st.latest.indicators_suppressed} suppressed) · ` +
    `coverage ${(100 * (st.latest.coverage || 0)).toFixed(0)}%`;

  /* dashboard */
  $("#kpis").innerHTML = [
    ["Risk score", (v.score || 0).toFixed(1) + " / 100"],
    ["Confidence", (100 * (v.confidence || 0)).toFixed(0) + "%"],
    ["Coverage", (100 * (v.telemetry_coverage || 0)).toFixed(0) + "%"],
    ["Evidence", st.latest.evidence_count],
    ["Indicators", st.latest.indicators_total],
    ["Suppressed", st.latest.indicators_suppressed],
  ].map(([k, val]) => `<div class="kpi"><span>${k}</span><b>${esc(val)}</b></div>`).join("");
  $("#rationale").innerHTML = (v.rationale || []).map((r) => `<li>${esc(r)}</li>`).join("") || "<li>—</li>";
  $("#limits").innerHTML =
    (st.latest.limitations || []).map((l) => `<li><b>${esc(l.source)}</b>: ${esc(l.reason)} — <i>${esc(l.impact)}</i></li>`).join("") ||
    "<li>none</li>";
  const si = st.latest.self_integrity || {};
  $("#selfint").textContent =
    [...(si.status || []), ...(si.changed || []).map((x) => "changed: " + x),
     ...(si.removed || []).map((x) => "removed: " + x)].join("\n") || "n/a";

  /* indicators by category */
  const inds = await getJSON("/api/indicators");
  fillIndicatorTable("#tbl-indicators", inds);
  fillIndicatorTable("#tbl-modules", inds.filter((i) => i.category === "module_integrity" || i.category === "signature"));
  fillIndicatorTable("#tbl-memory", inds.filter((i) => i.category === "memory_integrity"));
  fillIndicatorTable("#tbl-drivers", inds.filter((i) => i.category === "driver" || i.category === "service"));
  fillIndicatorTable(
    "#tbl-persistence",
    inds.filter((i) => ["persistence", "service", "scheduled_task", "wmi"].includes(i.category))
  );

  /* correlation + risk */
  const corr = await getJSON("/api/correlation");
  $("#tbl-correlation tbody").innerHTML = corr
    .map((c) => `<tr><td>${esc(c.subject_key)}</td><td>${c.n}</td><td>${Number(c.pts).toFixed(1)}</td></tr>`)
    .join("") || "<tr><td colspan=3>no correlated subjects</td></tr>";
  const maxPts = Math.max(1, ...inds.map((i) => i.risk_contribution));
  $("#risk-bars").innerHTML = inds
    .slice()
    .sort((a, b) => b.risk_contribution - a.risk_contribution)
    .slice(0, 15)
    .map(
      (i) =>
        `<div class="bar-row"><div class="bar-label" title="${esc(i.title)}">[${esc(i.rule_id)}] ${esc(i.title)}</div>` +
        `<div class="bar" style="width:${(240 * i.risk_contribution) / maxPts}px"></div>` +
        `<div class="bar-val">${i.risk_contribution.toFixed(1)} pts</div></div>`
    )
    .join("") || "<p class='hint'>no risk contributions</p>";

  /* telemetry */
  const tel = await getJSON("/api/telemetry");
  $("#tbl-telemetry tbody").innerHTML = (tel.availability || [])
    .map(
      (t) =>
        `<tr><td>${esc(t.name)}</td><td class="${t.available ? "ok" : "bad"}">${t.available ? "✅ available" : "❌ unavailable"}</td><td>${esc(t.reason)}</td></tr>`
    )
    .join("");

  /* evidence */
  await loadEvidence();

  /* settings + allowlist */
  const policy = await getJSON("/api/policy");
  $("#policy-json").textContent = JSON.stringify(policy, null, 2);
  const allow = await getJSON("/api/allowlist");
  $("#allowlist-json").textContent = JSON.stringify(allow, null, 2);
  $("#tbl-allowlist tbody").innerHTML = allow
    .map((e) => `<tr><td>${esc(e.kind)}</td><td>${esc(e.value)}</td><td>${esc(e.action)}</td><td>${e.factor}</td><td>${esc(e.reason)}</td></tr>`)
    .join("");

  /* live monitor table */
  liveRows.unshift({
    time: new Date((st.latest.started || 0) * 1000).toLocaleTimeString(),
    scan: st.latest.scan_id,
    verdict: v.level || "?",
    news: (st.latest.new_subjects || []).join(", ") || "—",
  });
  liveRows = liveRows.slice(0, 30);
  $("#tbl-live tbody").innerHTML = liveRows
    .map((r) => `<tr><td>${esc(r.time)}</td><td>${esc(r.scan)}</td><td>${esc(r.verdict)}</td><td>${esc(r.news)}</td></tr>`)
    .join("");

  /* files/signatures panel reuses latest report JSON */
  try {
    const rep = await (await fetch("/api/report.json")).json().catch(() => null);
    if (rep && rep.signatures) {
      $("#tbl-sigs tbody").innerHTML = rep.signatures
        .map((s) => `<tr><td>${esc(s.path)}</td><td>${esc(s.status)}</td><td>${esc(s.publisher)}</td><td>${s.chain_valid ? "✅" : "❌"}</td></tr>`)
        .join("");
    }
  } catch (_) { /* report not ready yet */ }
  $("#report-list").textContent = (st.latest.report_paths || []).join("\n");
}

function fillIndicatorTable(sel, rows) {
  $(sel + " tbody").innerHTML =
    rows
      .map((i) => {
        const evLinks = i.evidence_json
          ? JSON.parse(i.evidence_json).length
          : 0;
        return `<tr><td>${esc(i.rule_id)}</td><td>${esc(i.title)}</td><td>${esc(i.location)}</td>` +
          `<td><a href="#" onclick="showEvidence('${esc(i.subject_key)}');return false">${evLinks} items</a></td>` +
          `<td>${Number(i.confidence).toFixed(2)}</td><td>${Number(i.risk_contribution).toFixed(1)}</td>` +
          `<td>×${Number(i.corroboration).toFixed(2)}</td></tr>`;
      })
      .join("") || `<tr><td colspan="7" class="hint">no findings</td></tr>`;
}

async function loadEvidence() {
  const subject = $("#ev-filter").value.trim();
  const rows = await getJSON("/api/evidence" + (subject ? "?subject=" + encodeURIComponent(subject) : ""));
  $("#tbl-evidence tbody").innerHTML = rows
    .slice(0, 200)
    .map(
      (e) =>
        `<tr><td><code>${esc(e.id)}</code></td><td>${esc(e.kind)}</td><td>${esc(e.source)}</td>` +
        `<td>${esc(e.process_path)}</td><td><pre style="margin:0">${esc(JSON.stringify(e.data).slice(0, 400))}</pre></td></tr>`
    )
    .join("") || `<tr><td colspan="5" class="hint">no evidence${subject ? " for this subject" : ""}</td></tr>`;
}

window.showEvidence = function (subject) {
  $("#ev-filter").value = subject;
  $$("nav a").forEach((x) => x.classList.remove("active"));
  document.querySelector('nav a[data-panel="evidence"]').classList.add("active");
  $$(".panel").forEach((p) => p.classList.remove("active"));
  $("#panel-evidence").classList.add("active");
  loadEvidence();
};

/* ---------- boot ---------- */
refresh();
setInterval(async () => {
  const st = await getJSON("/api/status");
  if (st.running) toast("scan in progress…");
}, 5000);
