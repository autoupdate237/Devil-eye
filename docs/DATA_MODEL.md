# Devil's Eye — Data Model

All records are dataclasses in `core/models.py`, JSON-serialisable, and stored
in SQLite (`evidence/store.py`).

## Entities

### Evidence
One raw observation. The atomic unit of truth — detections may only reference
evidence, never invent facts.

| Field | Meaning |
|---|---|
| `id` | stable id (`ev-…`) used by indicators' `evidence_ids` |
| `kind` | process / module / memory / thread / file / signature / registry / service / scheduled_task / wmi / driver / network / event / artifact / telemetry / system |
| `source` | where it came from (EVTX channel, artifact name, API) |
| `collector` | which collector produced it |
| `ts` | observation time |
| `pid`, `process_path`, `hash_sha256`, `user` | subject linkage (best effort) |
| `data` | kind-specific structured payload |

### TelemetryAvailability
`(name, available, reason, weight, category)` — per source. Feeds coverage.

### Indicator
One fired rule. Carries the mandatory explanation:

```
what   → title/description
where  → location + process_path + pid
evidence → evidence_ids (foreign keys into Evidence)
confidence → 0..1
risk_contribution → filled by ScoringEngine
+ corroboration, allowlist_dampening, suppressed(+reason)
```

### CorrelationGroup
Subject cluster: `subject_key` (hash or path), indicator ids, **independent
evidence sources**, `corroboration_factor`, parent/child subject keys, score.

### Verdict
`(level, score, confidence, telemetry_coverage, rationale[], subject_scores,
top_indicators, limitations)`.

### AllowlistEntry
`(kind: hash|publisher|path_prefix|directory, value, action: dampen|suppress,
factor, reason)`.

### TelemetryLimitation
`(source, reason, impact)` — shown in every report and the Telemetry panel.

## SQLite schema (evidence.db)

```sql
scans(id, mode, started, finished, policy_json, notes)
evidence(id, scan_id, kind, source, collector, ts, pid, process_path,
         hash_sha256, username, data_json)
indicators(id, scan_id, rule_id, rule_name, category, severity, confidence,
           title, description, subject_key, pid, process_path, hash_sha256,
           location, evidence_json, extras_json, suppressed,
           risk_contribution, corroboration, dampening, ts)
telemetry_status(scan_id, name, available, reason, weight, category)
limitations(scan_id, source, reason, impact)
verdicts(scan_id, level, score, confidence, coverage, rationale_json,
         subject_scores_json, ts)
```

Forensic replay: `WHERE scan_id=?` on these six tables reconstructs an entire
session — every verdict is traceable back to raw evidence rows.
