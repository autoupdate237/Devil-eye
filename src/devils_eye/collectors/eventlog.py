"""Windows Event Log collector (EVTX channels).

Reads recent events from a configurable channel list via ``Get-WinEvent``.
Channels that don't exist on this host produce availability records, not
errors — this is the 'No single-source dependency' rule in action.

Notable channels (from the 2000-source catalog): Security, System,
Application, Microsoft-Windows-PowerShell/Operational,
Microsoft-Windows-CodeIntegrity/Operational,
Microsoft-Windows-AppLocker/*, Microsoft-Windows-TaskScheduler/Operational,
Microsoft-Windows-WMI-Activity/Operational,
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational,
Microsoft-Windows-WinRM/Operational, Microsoft-Windows-Sysmon/Operational.
"""

from __future__ import annotations

from typing import Dict, List

from ..core.models import CollectorResult, Evidence, TelemetryAvailability
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json

DEFAULT_CHANNELS: List[str] = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-WinRM/Operational",
    "Microsoft-Windows-Sysmon/Operational",
]

# Events interesting for anti-cheat correlation (subset of the catalog).
EVENT_OF_INTEREST = {
    "Security": {4688, 4689, 4656, 4663, 4697, 4698, 4699, 4700, 4701, 4702, 4703},
    "System": {7034, 7035, 7036, 7040, 7045},
    "Microsoft-Windows-PowerShell/Operational": {4103, 4104},
    "Microsoft-Windows-CodeIntegrity/Operational": {3033, 3034, 3076, 3077},
    "Microsoft-Windows-TaskScheduler/Operational": {106, 129, 140, 141, 200, 201},
    "Microsoft-Windows-WMI-Activity/Operational": {5857, 5858, 5859, 5860, 5861},
    "Microsoft-Windows-Windows Defender/Operational": {1006, 1007, 1008, 1116, 1117, 1118, 1119},
    "Microsoft-Windows-Sysmon/Operational": set(range(1, 30)) | {255},
}


class EventLogCollector(Collector):
    name = "eventlog"
    description = "Recent events from configured EVTX channels"
    weight = 0.9
    sources = ["Windows Event Log channels (EVTX)", "Get-WinEvent query"]

    def __init__(self, channels: List[str] | None = None, max_per_channel: int = 200):
        super().__init__()
        self.channels = channels or DEFAULT_CHANNELS
        self.max_per_channel = max_per_channel

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if not is_windows():
            return r
        for channel in self.channels:
            rows = powershell_json(
                f"Get-WinEvent -LogName '{channel}' -MaxEvents {self.max_per_channel} "
                "-ErrorAction Stop | Select-Object Id,TimeCreated,ProviderName,"
                "LevelDisplayName,Message | ConvertTo-Json -Depth 4",
                timeout=45,
            )
            if rows is None:
                r.availability.append(
                    TelemetryAvailability(
                        f"channel:{channel}", False,
                        "not present, not accessible, or empty", 0.6, "eventlog",
                    )
                )
                continue
            wanted = EVENT_OF_INTEREST.get(channel)
            for row in rows:
                eid = row.get("Id")
                if wanted is not None and eid not in wanted:
                    continue
                r.evidences.append(
                    Evidence(
                        kind="event",
                        source=channel,
                        collector=self.name,
                        data={
                            "channel": channel,
                            "event_id": eid,
                            "task": row.get("LevelDisplayName") or "",
                            "provider": row.get("ProviderName") or "",
                            "message": (row.get("Message") or "")[:2000],
                            "fields": {},
                        },
                    )
                )
            r.availability.append(
                TelemetryAvailability(f"channel:{channel}", True, "", 0.6, "eventlog")
            )
        r.metrics = {"events": len(r.evidences)}
        return r
