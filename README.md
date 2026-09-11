# Devil's Eye

**Devil's Eye** is a defensive, transparent, evidence-driven endpoint integrity
monitoring and anti-cheat analysis platform for Windows.

It watches a protected game/application while it runs and correlates many weak
signals — process ancestry, loaded modules, code signatures, memory-region
metadata, persistence locations, and Windows security telemetry — into a single
explainable risk verdict.

> **Design posture (non-negotiable):** Devil's Eye is a *detection and integrity
> verification* tool. It contains **no** process injection, **no** telemetry
> evasion, **no** anti-EDR/anti-anti-cheat bypass, **no** credential access,
> **no** destructive actions and **no** stealth persistence. All inspection is
> read-only and runs with the least privilege the selected mode allows.

---

## Why multi-source correlation?

A single indicator (e.g. "unsigned binary") is nearly meaningless on its own —
indie tools, internal builds and portable apps are unsigned every day. Devil's
Eye therefore never emits a cheat verdict from one signal. Every detection must
answer five questions:

```
What was detected → Where it was detected → Which evidence supports it
                  → Confidence → Risk contribution
```

Example correlation chain:

```
process (unsigned loader.exe in C:\Users\Public\Temp)
 + module (unsigned DLL mapped into the protected game)
 + signature (Authenticode: NotSigned, no timestamp)
 + ancestry (parent = cmd.exe /c, low integrity → SYSTEM escalation attempt)
 + telemetry (Sysmon EID 8 CreateRemoteThread into the game, EID 10 ProcessAccess VM_WRITE)
 + persistence (Run key + WMI ActiveScriptEventConsumer pointing back at loader)
 = HIGH RISK / CRITICAL with itemised evidence
```

A lone weak indicator with no corroboration stays at **LOW RISK** and is clearly
labelled as such.

## Architecture (pipeline)

```
Collector Layer        (processes, modules, memory metadata, signatures, registry,
                        services, tasks, WMI, drivers, network, EVTX/Sysmon, ETW*,
                        Prefetch/Amcache/Shimcache/BAM/UserAssist/ShellBags, Defender)
      │
Normalization Layer    (typed HostSnapshot + raw Evidence records)
      │
Evidence Store         (SQLite — every observation is retained and referenceable)
      │
Correlation Engine     (subject grouping, process-tree linking, corroboration factor)
      │
Detection Rules        (declarative rules, each isolated — a crashing rule is skipped)
      │
Risk Scoring           (severity × confidence × category weight × corroboration,
                        dampened by allowlist/reputation, scaled by telemetry coverage)
      │
Verdict Engine         (CLEAN / LOW RISK / SUSPICIOUS / HIGH RISK / CRITICAL
                        + human-readable rationale)
      │
Report + UI            (JSON/HTML report, local dashboard with 15 sections)
```

\* ETW trace sessions require creating a kernel session; they are **opt-in**
(`--etw`) because the default policy is zero-side-effect inspection.

## Quick start

```bash
# One-click full scan against the bundled simulated environment (any OS):
python -m devils_eye scan --demo

# One-click scan on a real Windows host:
python -m devils_eye scan

# Continuous monitoring (real-time mode):
python -m devils_eye monitor --interval 10

# Post-session forensic review of previously collected artifacts:
python -m devils_eye scan --forensic

# Launch the dashboard (runs a scan first, then serves the UI):
python -m devils_eye serve --port 8080
```

On Windows the project is packaged as a single EXE with PyInstaller
(`scripts/build_exe.py`). Double-clicking it runs the full one-click workflow:
environment check → telemetry availability → protected-app discovery → process,
module, file/signature, driver/service/task/persistence inspection → correlation
→ scoring → final report.

## Repository layout

```
config/                  default policy, default allowlist
docs/                    architecture, detections, scoring, data model, plans
src/devils_eye/
    core/                models, config, errors, platform helpers
    collectors/          one module per data source family (all isolated)
    normalization/       Evidence → HostSnapshot
    evidence/            SQLite evidence store
    correlation/         subject grouping + corroboration
    detection/           rule engine + rule packs
    scoring/             risk scoring engine
    verdict/             verdict engine
    allowlist/           reputation + allowlist matching
    integrity/           self-integrity / tamper awareness
    telemetry/           telemetry availability + coverage scoring
    pipeline/            one-click orchestrator (scan / monitor / forensic)
    reporting/           JSON + HTML reports
    api/                 local HTTP API (stdlib only)
    ui/                  static dashboard (vanilla JS, offline)
tests/                   stdlib-unittest suite (runs on any OS)
```

## Windows telemetry coverage

The original research list of **2000 candidate Windows log/artifact sources**
is mapped into the collector architecture in
[`docs/reference/SOURCE_COVERAGE.csv`](docs/reference/SOURCE_COVERAGE.csv) and
discussed in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Coverage status per
family is *implemented / metadata-only / planned* — nothing silently pretends to
collect data it cannot; missing sources reduce confidence and are shown in the
Telemetry Status panel and in every report.

## Safety requirements implemented

| Requirement | Implementation |
|---|---|
| Least privilege | User-mode scans run unelevated; elevation is requested per-mode and absence of rights degrades gracefully |
| Read-only inspection | No writes to monitored processes, registry or files (only our own session directory) |
| No credential collection | LSA secrets/SAM/NTDS/DPAPI content is **never** read — only *existence/tamper* metadata of those stores is noted |
| No destructive actions | Nothing is quarantined, killed or deleted — Devil's Eye reports, operators decide |
| No stealth persistence | Devil's Eye itself installs nothing at boot; tamper-awareness uses hash manifests, not autoruns |
| No bypass / evasion code | No syscall unhooking, no ETW patching, no signature spoofing — by policy, enforced in code review |
| No single-source dependency | Every collector is isolated; failure → telemetry-limitation record, never a crash |

## License

MIT — see `LICENSE`.
