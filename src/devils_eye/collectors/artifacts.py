"""Forensic artifact collector (offline-friendly).

Coverage tiers (see docs/reference/SOURCE_COVERAGE.csv):

* **implemented** — Prefetch directory inventory + lightweight header parsing
  (executable name, run count, last-run timestamp for the common 0x17/0x1A
  formats), which answers 'was this binary executed and when'.
* **metadata-only** — Amcache.hve, SYSTEM/SOFTWARE hives, RecentFileCache.bcf,
  SRUDB.dat, ActivitiesCache.db: existence + timestamps recorded; deep binary
  parsing is delegated to dedicated parsers in a later phase (clearly reported
  so confidence is never overstated).
* **read-only rule** — hives are NEVER modified; when locked, we note it.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Dict, List

from ..core.models import CollectorResult, Evidence, TelemetryAvailability
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")

METADATA_TARGETS = [
    ("Amcache.hve", r"appcompat\Programs\Amcache.hve"),
    ("RecentFileCache.bcf", r"appcompat\Programs\RecentFileCache.bcf"),
    ("SYSTEM hive", r"System32\config\SYSTEM"),
    ("SOFTWARE hive", r"System32\config\SOFTWARE"),
    ("SAM hive", r"System32\config\SAM"),
    ("SECURITY hive", r"System32\config\SECURITY"),
    ("SRUDB.dat", r"System32\sru\SRUDB.dat"),
    ("ActivitiesCache.db", r"Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db"),
    ("Windows.edb", r"ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"),
]


class ArtifactCollector(Collector):
    name = "artifacts"
    description = "Prefetch + forensic artifact presence (execution evidence)"
    weight = 0.8
    sources = [
        "Prefetch (C:\\Windows\\Prefetch)",
        "Amcache.hve",
        "RecentFileCache.bcf",
        "Registry hives (SYSTEM/SOFTWARE/SAM/SECURITY)",
        "SRUM / SRUDB.dat",
        "ActivitiesCache.db",
        "Windows Search index (Windows.edb)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if not is_windows():
            return r
        self._prefetch(r)
        self._metadata_targets(r)
        r.metrics = {"artifacts": len(r.evidences)}
        return r

    # ------------------------------------------------------------------
    def _prefetch(self, r: CollectorResult) -> None:
        pf_dir = Path(WINDIR) / "Prefetch"
        if not pf_dir.is_dir():
            r.availability.append(
                TelemetryAvailability("Prefetch", False, "Prefetch directory missing or unreadable", self.weight, "artifacts")
            )
            return
        count = 0
        try:
            entries = sorted(pf_dir.glob("*.pf"))
        except OSError:
            r.availability.append(TelemetryAvailability("Prefetch", False, "access denied", self.weight, "artifacts"))
            return
        for entry in entries:
            parsed = self._parse_prefetch(entry)
            if parsed is None:
                continue
            count += 1
            r.evidences.append(
                Evidence(
                    kind="artifact", source=f"Prefetch:{entry.name}", collector=self.name,
                    data={"artifact": "prefetch", **parsed},
                    process_path=parsed.get("executable") or "",
                )
            )
        r.availability.append(
            TelemetryAvailability("Prefetch", True, f"{count} entries parsed", self.weight, "artifacts")
        )

    @staticmethod
    def _parse_prefetch(path: Path) -> Dict | None:
        """Minimal, tolerant parser: version 17/23/26/30 headers only."""
        try:
            with open(path, "rb") as fh:
                header = fh.read(84)
            if len(header) < 84 or header[4:8] not in (b"SCCA", b"MAM\x04"):
                return None
            version = struct.unpack("<I", header[0:4])[0]
            name = header[16:46].split(b"\x00")[0].decode("utf-16le", "replace")
            run_count = struct.unpack("<I", header[76:80])[0] if len(header) >= 80 else 0
            result = {"executable": name, "run_count": run_count, "version": version, "file": str(path)}
            if version in (23, 26):
                with open(path, "rb") as fh:
                    fh.seek(120)
                    ts = fh.read(8)
                if len(ts) == 8:
                    result["last_run_filetime"] = struct.unpack("<Q", ts)[0]
            return result
        except (OSError, struct.error, UnicodeDecodeError):
            return None

    # ------------------------------------------------------------------
    def _metadata_targets(self, r: CollectorResult) -> None:
        import glob

        for label, rel in METADATA_TARGETS:
            if "*" in rel:
                matches = glob.glob(str(Path(WINDIR).parent / rel)) if rel.startswith("Users") else glob.glob(os.path.join(WINDIR, rel))
                found = matches[:1]
            else:
                candidate = Path(WINDIR) / rel
                found = [str(candidate)] if candidate.exists() else []
            if not found:
                r.availability.append(
                    TelemetryAvailability(label, False, "not present or not readable", 0.3, "artifacts")
                )
                continue
            p = Path(found[0])
            try:
                st = p.stat()
                r.evidences.append(
                    Evidence(
                        kind="artifact", source=label, collector=self.name,
                        data={"artifact": "metadata_only", "label": label, "path": str(p),
                              "size": st.st_size, "mtime": st.st_mtime,
                              "note": "deep parsing delegated to dedicated parser (phase 3)"},
                    )
                )
            except OSError:
                pass
