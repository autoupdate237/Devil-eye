# Devil's Eye — Architecture

> Defensive · transparent · evidence-driven. No bypass, no evasion, no injection.

## 1. Pipeline

```
┌────────────────────────────────────────────────────────────────────────────┐
│ COLLECTOR LAYER                                                            │
│  processes · modules · memory(metadata) · signatures · registry persistence│
│  services · scheduled tasks · WMI subscriptions · drivers · network        │
│  defender · sysmon health · EVTX channels · ETW(opt-in) · forensic artifacts│
│  (always real Windows telemetry; off-Windows ⇒ unavailable + limitations)   │
│  (each collector isolated — failure ⇒ limitation record, never a crash)    │
└──────────────────────────────┬─────────────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ NORMALIZATION LAYER                                                        │
│  Evidence(kind, source, subject, data) ─► HostSnapshot                     │
│  (typed ProcessView graph: modules/memory/threads/network joined to procs) │
└──────────────────────────────┬─────────────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ EVIDENCE STORE (SQLite)                                                    │
│  evidence · indicators · telemetry_status · limitations · verdicts · scans │
└──────────────────────────────┬─────────────────────────────────────────────┘
                               ▼
        CORRELATION ENGINE  ──► subject clusters, corroboration factor (×1.0–1.6),
        DETECTION RULES         process-tree links (parent/child escalation)
                               ▼
        ALLOWLIST/REPUTATION ──► suppress / dampen (fully audited)
                               ▼
        RISK SCORING          ──► per-subject + global score (0–100)
                               ▼
        VERDICT ENGINE        ──► CLEAN / LOW / SUSPICIOUS / HIGH / CRITICAL
                               ▼   (coverage-guarded: thin telemetry ⇒ downgrade)
        REPORT (JSON+HTML) + UI (15-section dashboard)
```

## 2. Folder structure & module responsibilities

```
config/
  default_policy.json       protected processes, trusted publishers/dirs,
                            thresholds, category weights, sensitivity
  allowlist.json            user-managed suppress/dampen entries
docs/                       this documentation set + source coverage catalog
src/devils_eye/
  core/models.py            Evidence, Indicator, Verdict, CorrelationGroup,
                            TelemetryAvailability, TelemetryLimitation…
  core/config.py            Policy loader + defaults
  core/platform_info.py     OS/elevation detection, safe subprocess wrapper
  core/errors.py            error hierarchy (CollectorUnavailable, RuleError…)
  collectors/base.py        Collector ABC + run_collector isolation wrapper
  collectors/*.py           one module per source family (see §3)
  normalization/normalizer  Evidence → HostSnapshot (indexed, cross-linked)
  evidence/store.py         SQLite evidence store (audit + forensic replay)
  correlation/engine.py     subject clustering, corroboration, tree linking
  detection/engine.py       rule registry, isolated execution, doc contract
  detection/rules.py        22 detection rules across 14 categories
  allowlist/reputation.py   hash/publisher/path/directory matching
  scoring/risk.py           contribution model, subject/global aggregation
  verdict/engine.py         thresholds + coverage guard + rationale builder
  telemetry/availability.py coverage computation + limitation extraction
  integrity/self_check.py   self hash-manifest + monitoring-coverage awareness
  pipeline/orchestrator.py  one-click workflow; scan/monitor/forensic modes
  reporting/report.py       JSON + self-contained HTML report
  api/server.py             local stdlib HTTP API (no external deps)
  ui/static/                dashboard (vanilla JS, offline-capable)
scripts/build_exe.py        PyInstaller packaging for the one-click EXE
tests/                      28 unit/integration tests (any OS, stdlib only)
  fake_environment.py       test-only deterministic Windows-host fixture (CI)
```

## 3. Collectors ↔ source-catalog mapping (summary)

| Collector | Catalog families it feeds | Status |
|---|---|---|
| `processes` | process inventory, EID 1/4688 correlation input | implemented |
| `modules` | module inventory, EID 7 input | implemented (budgeted) |
| `signatures` | Authenticode, WinVerifyTrust, certificate chain | implemented |
| `memory` | VAD metadata, thread start addresses | implemented (protected only) |
| `persistence_registry` | Run/RunOnce, Winlogon, IFEO, SilentProcessExit, AppInit, BootExecute | implemented |
| `services` | SCM configuration, EID 7045 input | implemented |
| `scheduled_tasks` | task XML/TaskCache, EID 106/129/140/141 input | implemented |
| `wmi_persistence` | WMI filters/consumers/bindings, EID 5857-61, EID 19-21 input | implemented |
| `drivers` | driver inventory, CodeIntegrity 3033/3034 input | implemented |
| `network` | TCP/UDP tables, DNS client cache | implemented |
| `defender` | Defender status + detections (EID 1116-1119 input) | implemented |
| `sysmon` | Sysmon install/config health (EID 16/255) | implemented |
| `eventlog` | 13 EVTX channels incl. Security/PowerShell/AppLocker/CodeIntegrity | implemented |
| `etw` | ETW provider inventory (Kernel-*, Threat-Intelligence, PowerShell…) | inventory; capture opt-in |
| `artifacts` | Prefetch (parsed); Amcache/SRUM/hives/ActivitiesCache (metadata) | partial → phase 3 |

Full 2000-source mapping: [`reference/SOURCE_COVERAGE.csv`](reference/SOURCE_COVERAGE.csv).

## 4. One-click workflow (requirement 17)

Double-click `DevilsEye.exe` (or `python -m devils_eye scan`):

1. **Environment check** — OS/build, elevation, workspace writability, self-integrity baseline.
2. **Telemetry availability** — every collector probed; coverage % computed.
3. **Protected-app discovery** — policy `protected_processes` matched against live list.
4. **Process inspection** — inventory + ancestry + command lines.
5. **Module inspection** — budgeted deep scan of protected + suspicious processes.
6. **File/signature verification** — Authenticode for every unique observed path.
7. **Driver/service/task/persistence inspection** — remaining collectors.
8. **Correlation engine** — clustering, corroboration, tree links.
9. **Risk scoring** — allowlist applied, contributions summed per subject.
10. **Verdict + report** — JSON + HTML written, dashboard updated.

## 5. Operating modes

| Mode | Command | Behaviour |
|---|---|---|
| scan | `scan` | single full pass (default) |
| real-time | `monitor --interval 10` | repeated passes; Live Monitor shows only NEW subjects with findings |
| forensic | `scan --forensic` | post-session review; artifact emphasis; reports archived |
| dashboard | `serve --port 8080` | scan, then serve the 15-section UI on 127.0.0.1 |

## 6. Safety & quality guarantees

* **Isolation boundary**: every collector and every rule runs inside a
  `try/except` that converts failures into `TelemetryLimitation` records.
* **Read-only**: the only handles ever opened on other processes carry
  `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`; a `PolicyViolation`
  guard fails fast if write access is ever requested.
* **No credential access**: LSA secrets/SAM/NTDS/DPAPI content is never read;
  only existence/tamper metadata is observed.
* **Graceful degradation**: missing permission/source ⇒ confidence lowered and
  limitation listed in every report; HIGH/CRITICAL verdicts are *downgraded*
  automatically when telemetry coverage < 40 %.
* **Version differences**: collectors use WinRT-free backends
  (`Get-CimInstance`, `wevtutil`, registry) that exist from Win10 1607+;
  anything missing is reported, not assumed.
