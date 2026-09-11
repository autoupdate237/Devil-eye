"""Tamper awareness for Devil's Eye itself.

Two checks (detection-only, never blocking):
1. **Binary/config integrity** — SHA-256 of every package file is compared to
   a manifest written at first run (``self_manifest.json``). Mismatches are
   reported as findings; the manifest is never auto-repaired silently.
2. **Monitoring coverage** — if the set of available collectors shrank between
   scans (e.g. someone stopped Sysmon), the change is surfaced.

No self-persistence is installed; the manifest lives in the data directory.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List

from ..core.config import REPO_ROOT
from ..core.logging_setup import get_logger

log = get_logger("integrity")

PKG_ROOT = Path(__file__).resolve().parents[1]


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest() -> Dict[str, str]:
    manifest: Dict[str, str] = {}
    for pattern in ("**/*.py", "ui/static/*"):
        for path in sorted(PKG_ROOT.glob(pattern)):
            if path.is_file():
                manifest[str(path.relative_to(PKG_ROOT))] = _hash_file(path)
    return manifest


def self_check(data_dir: Path) -> Dict[str, List[str]]:
    """Compare current files against the stored manifest. Returns
    {'status': [...], 'changed': [...], 'added': [...], 'removed': [...]}."""
    import sys

    report: Dict[str, List[str]] = {"status": [], "changed": [], "added": [], "removed": []}
    if getattr(sys, "frozen", False):
        # Frozen build: source files are packed inside the EXE; file-level
        # manifesting is not applicable. Binary integrity is the OS/AV/WDAC's
        # job there; we only record the fact.
        report["status"].append("packaged build — file manifest check not applicable")
        return report
    manifest_path = Path(data_dir) / "self_manifest.json"
    current = build_manifest()
    if not manifest_path.exists():
        try:
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(current, indent=2), encoding="utf-8")
            report["status"].append("manifest created on first run (baseline established)")
        except OSError as exc:
            report["status"].append(f"could not write manifest: {exc}")
        return report
    try:
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report["status"].append(f"manifest unreadable: {exc} — treating as tamper-warning")
        return report
    for name, digest in current.items():
        if name not in baseline:
            report["added"].append(name)
        elif baseline[name] != digest:
            report["changed"].append(name)
    for name in baseline:
        if name not in current:
            report["removed"].append(name)
    if report["changed"] or report["removed"]:
        report["status"].append("WARNING: Devil's Eye files changed since baseline")
    else:
        report["status"].append("self-integrity OK")
    return report
