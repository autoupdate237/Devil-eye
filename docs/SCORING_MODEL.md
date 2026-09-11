# Devil's Eye — Scoring Model

Design goals: **high detection confidence + low false positives + explainable
evidence.** No single indicator can manufacture a ban-worthy verdict.

## 1. Per-indicator contribution

```
contribution = severity            (0..10, rule-defined)
             × confidence          (0..1,  rule-defined, per-observation adjusted)
             × category_weight     (policy: memory 1.2, driver 1.2, module 1.1, …)
             × corroboration       (1.0 + 0.15 × (independent_sources − 1), cap 1.6)
             × allowlist_factor    (1.0 default; dampen=0.1–0.4; suppress=0)
             × sensitivity         (conservative 0.8 / balanced 1.0 / aggressive 1.25)
```

*Independent evidence sources* are counted per subject by the Correlation
Engine: process inventory, command line, module inventory, signature status,
memory regions, thread metadata, network endpoints, persistence entries, and
each distinct EVTX event channel/ID — e.g. an unsigned loader seen in the
process list **and** in Sysmon EID 1 **and** Security 4688 **and** holding an
ESTABLISHED socket gets ×1.6, while the same rule firing from a single source
stays at ×1.0.

## 2. Aggregation

```
subject_score = Σ contributions of the subject            (cap 100)
global_score  = max(subject_scores) + 0.15 × Σ others      (cap 100)
```

The 0.15 spread factor means one loud subject dominates; many mediocre
subjects still lift the global score (multi-vector intrusions).

## 3. Verdict thresholds (policy-tunable)

| Score | Verdict |
|---|---|
| < 10 | CLEAN |
| 10–25 | LOW RISK |
| 25–50 | SUSPICIOUS |
| 50–75 | HIGH RISK |
| ≥ 75 | CRITICAL |

## 4. Confidence & coverage guard

```
base_confidence = mean(confidence of top contributors)
final_confidence = base_confidence × (0.5 + 0.5 × telemetry_coverage)
telemetry_coverage = Σ weight(available sources) / Σ weight(all sources)
```

If `telemetry_coverage < 0.40` and the score maps to HIGH/CRITICAL, the
verdict is **downgraded one level** and the downgrade is written into the
rationale — we never claim certainty we cannot evidence.

## 5. Allowlist / reputation (false-positive reduction)

Match order: hash → known-good hashes → publisher (trusted list) → explicit
path/directory entries → policy trusted directories.

| Match | Default action |
|---|---|
| known-good SHA-256 | suppress |
| trusted publisher (Microsoft, GPU vendors, security vendors, game vendors) | dampen ×0.15 |
| trusted OS directory | dampen ×0.15 |
| user entry | per entry |

Every application is persisted in the indicators table (`dampening`,
`suppressed`, reason) so the Evidence Viewer shows *why* something was muted.

## 6. Structural false-positive guards

1. Single weak indicator, single source → ≤ LOW RISK by arithmetic.
2. Unsigned ≠ guilty: unsigned-only rules carry severity 4 / confidence 0.6.
3. Severity jumps come from *context* (protected process, writable path,
   broken signature, corroborating events), never from absence of a signature.
4. Coverage guard prevents thin-telemetry overreach.
5. All suppression is audited; nothing is silently dropped.
