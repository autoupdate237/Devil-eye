"""ETW collector — **opt-in**.

ETW gives the richest telemetry (Kernel Process/Thread/Image/File providers,
Microsoft-Windows-Threat-Intelligence, .NET CLR…), but starting a trace
session mutates system state, so Devil's Eye never starts one unless the
operator explicitly passes ``--etw`` (policy ``etw_enabled: true``).

Without opt-in this collector only reports which ETW infrastructure is
present (`logman query providers`), so confidence scoring can account for
*potential* coverage.
"""

from __future__ import annotations

from ..core.models import CollectorResult, Evidence, TelemetryAvailability
from ..core.platform_info import is_windows, run_cmd
from .base import Collector, PipelineContext

INTERESTING_PROVIDERS = [
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-Kernel-Thread",
    "Microsoft-Windows-Kernel-Image",
    "Microsoft-Windows-Kernel-File",
    "Microsoft-Windows-Kernel-Network",
    "Microsoft-Windows-Threat-Intelligence",
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-CodeIntegrity",
    "Microsoft-Windows-DNS-Client",
]


class EtwCollector(Collector):
    name = "etw"
    description = "ETW provider inventory (trace capture is opt-in)"
    weight = 0.6
    sources = [f"ETW provider: {p}" for p in INTERESTING_PROVIDERS]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        res = run_cmd(["logman", "query", "providers"], timeout=20)
        if res is None or not res.ok:
            r.availability.append(
                TelemetryAvailability("ETW provider list", False, "logman unavailable", self.weight, "etw")
            )
            return r
        text = res.stdout
        for provider in INTERESTING_PROVIDERS:
            present = provider.lower() in text.lower()
            r.availability.append(
                TelemetryAvailability(f"ETW provider: {provider}", present,
                                      "provider not registered" if not present else "",
                                      0.4, "etw")
            )
        enabled = bool(ctx.policy.get("etw_enabled", False))
        if enabled:
            # NOTE: deliberately minimal — a production build would drive
            # `logman create/stop` with a trace profile here. We keep the side
            # effect explicit and logged.
            r.evidences.append(
                Evidence(
                    kind="telemetry", source="ETW", collector=self.name,
                    data={"component": "etw_capture", "status": "requested",
                          "note": "opt-in trace session capture enabled"},
                )
            )
        else:
            r.metrics = {"note": "trace capture disabled (opt-in via --etw)"}
        return r
