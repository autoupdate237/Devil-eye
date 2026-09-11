"""Generate docs/DETECTIONS.md from the live rule registry (single source of truth)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devils_eye.detection.engine import all_rules  # noqa: E402
from devils_eye.detection import rules  # noqa: F401,E402

HEADER = """# Devil's Eye — Detection Catalogue

Every detection in Devil's Eye is documented in the mandatory format:

> **What was detected → Where it was detected → Which evidence supports it →
> Confidence → Risk contribution**

Rules fire into *indicators*; indicators never equal verdicts. Verdicts are
produced by the scoring engine from the aggregate, allowlist-dampened,
coverage-scaled picture.

"""

lines = [HEADER]
by_cat = {}
for spec in all_rules():
    by_cat.setdefault(spec.category, []).append(spec)

for cat in sorted(by_cat):
    lines.append(f"## Category: `{cat}`\n")
    for spec in sorted(by_cat[cat], key=lambda s: s.id):
        d = spec.doc
        lines.append(f"### {spec.id} — {spec.name}\n")
        lines.append("| Aspect | Detail |")
        lines.append("|---|---|")
        lines.append(f"| **What** | {d['what']} |")
        lines.append(f"| **Where** | {d['where']} |")
        lines.append(f"| **Evidence** | {d['evidence']} |")
        lines.append(f"| **Base confidence** | {spec.base_confidence or 'pattern-dependent'} |")
        lines.append(f"| **Severity** | {spec.severity} / 10 |")
        lines.append(f"| **Risk contribution** | {d['risk']} |\n")

out = Path(__file__).resolve().parents[1] / "docs" / "DETECTIONS.md"
out.write_text("\n".join(lines), encoding="utf-8")
print(f"wrote {out} ({len(all_rules())} rules)")
