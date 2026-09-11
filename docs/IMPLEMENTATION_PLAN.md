# Devil's Eye — Implementation Plan

Phases are ordered so every phase ships a *useful, testable* increment.

## Phase 0 — Foundations (this repository, done ✅)
- [x] Core data models (Evidence → Indicator → Verdict)
- [x] Isolated collector framework + 15 collectors (real Windows backends)
- [x] Deterministic Windows-host test fixture (tests/ only, not shipped in product)
- [x] SQLite Evidence Store + forensic replay
- [x] Correlation engine (clustering, corroboration factor, tree links)
- [x] 22 detection rules across 14 categories, each with doc contract
- [x] Allowlist/reputation with audited suppression
- [x] Scoring + verdict engines with coverage guard
- [x] JSON/HTML reports + 15-section dashboard + CLI (scan/monitor/serve)
- [x] Self-integrity manifest + monitoring-coverage awareness
- [x] 27 tests (stdlib only, run on any OS)

## Phase 1 — Windows hardening (next)
- [ ] Signed-driver enumeration via `Win32_PnPSignedDriver` + DriverStore inventory
- [ ] Prefetch deep parser (v17/23/26/30: all run times, volumes, file refs)
- [ ] EVTX field extraction (XML → structured fields for 4688/EID1 command lines)
- [ ] Protected-process PPL query + anti-debug state metadata (read-only)
- [ ] Elevation-aware fallback matrix (document every collector's rights needs)
- [ ] Integration tests on Windows Server 2022 / Win10 / Win11 matrix

## Phase 2 — Deep telemetry (opt-in side effects)
- [ ] ETW trace sessions (Kernel Process/Thread/Image, Threat-Intelligence)
      with explicit operator opt-in and auto-stop
- [ ] Sysmon config audit (hash of active config vs expected baseline)
- [ ] AMSI event correlation (PowerShell/CLR script content *hashes only* —
      never content storage)
- [ ] WFP/firewall log (`pfirewall.log`) parser

## Phase 3 — Forensic artifact parsers
- [ ] Amcache.hve hive walker (File/Program entries, SHA-1)
- [ ] ShimCache (AppCompatCache) per-version parser
- [ ] BAM/DAM registry decoders
- [ ] SRUDB.dat ESE reader (network/app resource usage)
- [ ] ShellBags / Jump Lists / LNK parsers (execution + user activity proof)
- [ ] USN Journal + $MFT timeline builder (file birth/rename/delete)
- [ ] Browser artifacts (history/downloads) — privacy mode: hashes + URLs only

## Phase 4 — Memory & binary forensics
- [ ] PE metadata extractor (sections, imports, Rich header, PDB path, imphash)
- [ ] Module-vs-file consistency (in-memory headers vs on-disk hash)
- [ ] RWX region carving classifier (heuristic shellcode features, metadata only)
- [ ] Thread start-address ↔ VAD backing resolution for all processes (budgeted)

## Phase 5 — Scale & operations
- [ ] Delta engine: persist baseline snapshot, report only changes between scans
- [ ] Case export bundle (evidence DB + reports + manifest, signed zip)
- [ ] WEF/SIEM forwarding (JSON line format)
- [ ] Per-game policy packs (publisher/module/directory allowlists shipped
      with the game's own manifest)
- [ ] Performance budget: <3 s full scan, <200 ms monitor pass on modern CPU

## Acceptance criteria per phase
1. Every new collector ships with availability handling + limitation text.
2. Every new rule ships with the 5-part doc contract + a firing test against
   the tests/ fixture + a benign non-firing test.
3. No phase may introduce write access to monitored processes/registry/files.
4. False-positive regression suite: the benign fixture population must stay
   ≤ LOW RISK under every new rule set.
