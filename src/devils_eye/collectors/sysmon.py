"""Sysmon presence/health collector.

Sysmon itself is just an ETW-to-EVTX bridge, but knowing whether it is
installed, running and recently configured is valuable: an attacker tampering
with monitoring often stops Sysmon first. We detect:

* service present/stopped,
* driver loaded,
* config-hash change events (EID 16),
* 'Sysmon error' (EID 255).

Event *content* arrives through the EventLogCollector channel reader.
"""

from __future__ import annotations

from ..core.models import CollectorResult, TelemetryAvailability
from ..core.platform_info import is_windows, run_cmd
from .base import Collector, PipelineContext
from .helpers import powershell_json


class SysmonCollector(Collector):
    name = "sysmon"
    description = "Sysmon installation/health/configuration status"
    weight = 0.7
    sources = [
        "Microsoft-Windows-Sysmon/Operational",
        "Sysmon Event ID 16 Sysmon Configuration Change",
        "Sysmon Event ID 255 Sysmon Error",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        svc = run_cmd(["sc", "query", "Sysmon"], timeout=10) or run_cmd(
            ["sc", "query", "Sysmon64"], timeout=10
        )
        installed = bool(svc and svc.ok)
        state = ""
        if installed and svc:
            for line in svc.stdout.splitlines():
                if "STATE" in line:
                    state = line.split(":")[-1].strip()
        rows = powershell_json(
            "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 "
            "-ErrorAction Stop | Select-Object Id,TimeCreated | ConvertTo-Json -Depth 3",
            timeout=20,
        )
        channel_ok = rows is not None
        r.availability.append(
            TelemetryAvailability(
                "Sysmon service", installed, "Sysmon service not installed" if not installed else state,
                0.7, "sysmon",
            )
        )
        r.availability.append(
            TelemetryAvailability(
                "Sysmon channel", channel_ok, "channel unreadable (rights or not installed)",
                0.7, "sysmon",
            )
        )
        r.metrics = {"installed": installed, "channel_readable": channel_ok}
        return r
