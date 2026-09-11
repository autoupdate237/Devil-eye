"""Process collector: PID/PPID/path/command-line/user/integrity/creation.

Live Windows implementations, in preference order:
1. ``psutil`` (optional dependency) — fast, no subprocess;
2. PowerShell ``Get-CimInstance Win32_Process`` — structured JSON, always
   present on supported Windows.

Both are read-only queries. Missing rights degrade to a limitation record.
"""

from __future__ import annotations

import time
from typing import List, Optional

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json


class ProcessCollector(Collector):
    name = "processes"
    description = "Live process inventory with ancestry and command lines"
    weight = 1.0
    sources = [
        "Process list (Win32_Process)",
        "Security Event 4688 (correlation input)",
        "Sysmon Event ID 1 Process Create (correlation input)",
        "ETW Process Provider (opt-in)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated:
            return r  # simulated environment supplies its own process evidence
        if not is_windows():
            return r
        procs = self._via_psutil() or self._via_powershell()
        if procs is None:
            r.errors.append("no process enumeration backend available (install psutil)")
            r.availability[0].available = False
            r.availability[0].reason = "no enumeration backend"
            return r
        by_pid = {p["pid"]: p for p in procs}
        for p in procs:
            parent = by_pid.get(p.get("ppid") or 0) or {}
            ev = Evidence(
                kind="process",
                source="Win32_Process",
                collector=self.name,
                pid=p["pid"],
                process_path=p.get("path") or p.get("name") or "",
                user=p.get("user") or "",
                data={
                    "pid": p["pid"],
                    "ppid": p.get("ppid"),
                    "name": p.get("name") or "",
                    "path": p.get("path") or "",
                    "cmdline": p.get("cmdline") or "",
                    "user": p.get("user") or "",
                    "integrity_level": p.get("integrity_level") or "",
                    "session": p.get("session"),
                    "created": p.get("created"),
                    "exited": None,
                    "parent_path": parent.get("path") or "",
                    # signature fields filled later by SignatureCollector
                    "sha256": "", "signed": None, "publisher": "",
                    "signature_status": "",
                },
            )
            r.evidences.append(ev)
        ctx.shared["processes"] = [e.data for e in r.evidences]
        r.metrics = {"process_count": len(r.evidences)}
        return r

    # ------------------------------------------------------------------
    def _via_psutil(self) -> Optional[List[dict]]:
        try:
            import psutil  # type: ignore
        except ImportError:
            return None
        out = []
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "sessionid"]
        ):
            try:
                info = proc.info
                cmdline = " ".join(info.get("cmdline") or [])
                out.append(
                    {
                        "pid": info["pid"], "ppid": info["ppid"], "name": info["name"],
                        "path": info.get("exe") or "", "cmdline": cmdline,
                        "user": info.get("username") or "", "session": info.get("sessionid"),
                        "created": info.get("create_time"), "integrity_level": "",
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
        return out

    def _via_powershell(self) -> Optional[List[dict]]:
        script = (
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,"
            "ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Depth 4"
        )
        rows = powershell_json(script, timeout=60)
        if rows is None:
            return None
        out = []
        for row in rows:
            out.append(
                {
                    "pid": row.get("ProcessId"),
                    "ppid": row.get("ParentProcessId"),
                    "name": row.get("Name") or "",
                    "path": row.get("ExecutablePath") or "",
                    "cmdline": row.get("CommandLine") or "",
                    "user": "",
                    "session": None,
                    "created": None,
                    "integrity_level": "",
                }
            )
        return out
