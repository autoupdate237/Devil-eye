"""Microsoft Defender status + recent detections (read-only WMI/Cmdlet view)."""

from __future__ import annotations

from ..core.models import CollectorResult, Evidence, TelemetryAvailability
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json


class DefenderCollector(Collector):
    name = "defender"
    description = "Defender health + recent threat detections"
    weight = 0.8
    sources = [
        "Microsoft Defender Operational",
        "Defender Detection History",
        "Get-MpComputerStatus / Get-MpThreatDetection",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        status = powershell_json(
            "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,"
            "AntivirusEnabled,BehaviorMonitorEnabled,AntivirusSignatureAge | ConvertTo-Json",
            timeout=30,
        )
        if status is None:
            r.availability.append(
                TelemetryAvailability("Defender cmdlets", False, "Defender not present or cmdlets blocked", self.weight, "defender")
            )
            return r
        s = status[0] if status else {}
        r.evidences.append(
            Evidence(
                kind="telemetry", source="Get-MpComputerStatus", collector=self.name,
                data={
                    "component": "defender_status",
                    "real_time_protection": bool(s.get("RealTimeProtectionEnabled")),
                    "antivirus_enabled": bool(s.get("AntivirusEnabled")),
                    "behavior_monitor": bool(s.get("BehaviorMonitorEnabled")),
                    "signature_age_hours": s.get("AntivirusSignatureAge"),
                },
            )
        )
        threats = powershell_json(
            "Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 50 "
            "ThreatName,Resources,InitialDetectionTime,ActionSuccess | ConvertTo-Json -Depth 4",
            timeout=45,
        )
        if threats is not None:
            for t in threats:
                r.evidences.append(
                    Evidence(
                        kind="telemetry", source="Get-MpThreatDetection", collector=self.name,
                        data={
                            "component": "defender_detection",
                            "threat": t.get("ThreatName") or "",
                            "path": "; ".join(t.get("Resources") or [])[:512],
                            "action": "success" if t.get("ActionSuccess") else "failed",
                            "initial_detection_time": t.get("InitialDetectionTime"),
                        },
                    )
                )
        r.metrics = {"detections": len([e for e in r.evidences if e.data.get("component") == "defender_detection"])}
        return r
