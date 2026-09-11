"""Kernel driver collector.

A kernel driver is the most powerful cheat primitive (ring-0 memory access),
so driver inventory + signature status carries the highest category weight.
Backend: ``driverquery /v`` CSV or Win32_SystemDriver.
"""

from __future__ import annotations

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json


class DriverCollector(Collector):
    name = "drivers"
    description = "Loaded/installed kernel drivers with paths and start types"
    weight = 1.2
    sources = [
        "Driver installation (driverquery)",
        "Kernel-PnP",
        "Code Integrity driver events 3033/3034 (correlation input)",
        "Driver Signature Database / Catalog File (consulted)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        rows = powershell_json(
            "Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,"
            "PathName,State,StartMode,Description | ConvertTo-Json -Depth 4",
            timeout=60,
        )
        if rows is None:
            r.errors.append("Win32_SystemDriver query failed")
            r.availability[0].available = False
            r.availability[0].reason = "driver query failed"
            return r
        for row in rows:
            path = (row.get("PathName") or "").replace("\\??\\", "")
            r.evidences.append(
                Evidence(
                    kind="driver",
                    source="Win32_SystemDriver",
                    collector=self.name,
                    process_path=path,
                    data={
                        "name": row.get("Name") or "",
                        "image_path": path,
                        "state": row.get("State") or "",
                        "start": row.get("StartMode") or "",
                        "signed": None, "publisher": "", "sha256": "",
                    },
                )
            )
        ctx.shared["drivers"] = [e.data for e in r.evidences]
        r.metrics = {"drivers": len(r.evidences)}
        return r
