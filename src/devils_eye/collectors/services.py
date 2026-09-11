"""Service collector: configuration + binary path for every installed service."""

from __future__ import annotations

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json


class ServiceCollector(Collector):
    name = "services"
    description = "Installed services with image paths and start types"
    weight = 1.0
    sources = [
        "Services registry (HKLM\\System\\CurrentControlSet\\Services)",
        "Service Control Manager",
        "SCM Event 7045 (correlation input)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        rows = powershell_json(
            "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,"
            "StartMode,State,StartName | ConvertTo-Json -Depth 4",
            timeout=60,
        )
        if rows is None:
            r.errors.append("Win32_Service query failed")
            r.availability[0].available = False
            r.availability[0].reason = "WMI service query failed"
            return r
        for row in rows:
            image = self._clean_path(row.get("PathName") or "")
            r.evidences.append(
                Evidence(
                    kind="service",
                    source="Win32_Service",
                    collector=self.name,
                    process_path=image,
                    data={
                        "name": row.get("Name") or "",
                        "display": row.get("DisplayName") or "",
                        "image_path": image,
                        "start": row.get("StartMode") or "",
                        "status": row.get("State") or "",
                        "user": row.get("StartName") or "",
                        "signed": None, "publisher": "", "sha256": "",
                    },
                )
            )
        ctx.shared["services"] = [e.data for e in r.evidences]
        r.metrics = {"services": len(r.evidences)}
        return r

    @staticmethod
    def _clean_path(pathname: str) -> str:
        p = pathname.strip()
        if p.startswith('"'):
            end = p.find('"', 1)
            if end > 0:
                return p[1:end]
        return p.split(" /")[0].split(" -")[0] if p else ""
