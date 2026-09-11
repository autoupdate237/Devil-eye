"""Code signing collector.

Uses ``Get-AuthenticodeSignature`` (batched) to obtain status/publisher/
timestamp for every unique binary path observed so far. Being unsigned is an
*indicator*, never a verdict — the scoring engine combines it with context.
"""

from __future__ import annotations

from typing import Dict, List

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json


class SignatureCollector(Collector):
    name = "signatures"
    description = "Authenticode status, publisher, timestamp, chain validity"
    weight = 0.9
    sources = [
        "Authenticode Signature",
        "WinVerifyTrust Result",
        "Certificate Chain",
        "TrustedPublisher Store (consulted)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        paths = self._unique_paths(ctx)
        if not paths:
            return r
        status_by_path: Dict[str, dict] = {}
        # Batch in chunks to keep the PowerShell command line sane.
        for i in range(0, len(paths), 64):
            chunk = paths[i : i + 64]
            arr = "@(" + ",".join(f"'{p}'" for p in chunk) + ")"
            rows = powershell_json(
                f"{arr} | ForEach-Object {{ $s = Get-AuthenticodeSignature $_; "
                "[pscustomobject]@{ Path=$_; Status=$s.Status.ToString(); "
                "Publisher=$s.SignerCertificate.Subject; "
                "NotAfter=$s.SignerCertificate.NotAfter.ToString('o'); "
                "Timestamp=$s.TimeStamperCertificate.NotAfter.ToString('o') } }}",
                timeout=90,
            )
            if rows is None:
                r.errors.append("Authenticode query failed for a batch")
                continue
            for row in rows:
                status_by_path[(row.get("Path") or "").lower()] = row
        for p in paths:
            row = status_by_path.get(p.lower()) or {"Status": "UnknownError"}
            status = row.get("Status") or "UnknownError"
            publisher = row.get("Publisher") or ""
            ev = Evidence(
                kind="signature",
                source="Get-AuthenticodeSignature",
                collector=self.name,
                process_path=p,
                data={
                    "path": p,
                    "status": status,
                    "publisher": publisher,
                    "timestamp": row.get("Timestamp") or "",
                    "chain_valid": status == "Valid",
                    "sha256": "",
                },
            )
            r.evidences.append(ev)
        ctx.shared["signatures"] = {
            e.data["path"].lower(): e.data for e in r.evidences
        }
        r.metrics = {"checked": len(paths)}
        return r

    # ------------------------------------------------------------------
    def _unique_paths(self, ctx: PipelineContext) -> List[str]:
        seen: Dict[str, None] = {}
        for proc in ctx.shared.get("processes") or []:
            p = proc.get("path") or ""
            if p:
                seen.setdefault(p)
        for ev_kind in ("module", "service", "driver"):
            for item in ctx.shared.get(f"{ev_kind}s") or []:
                p = item.get("module_path") or item.get("image_path") or ""
                if p:
                    seen.setdefault(p)
        return list(seen)
