"""Compute telemetry coverage from availability records.

coverage = Σ(weight of available sources) / Σ(weight of all expected sources)

Sources that are merely 'metadata-only' count at half weight — they exist but
don't yet yield parsed fields. Missing mandatory sources become
TelemetryLimitation rows shown in every report.
"""

from __future__ import annotations

from typing import List, Tuple

from ..core.models import TelemetryAvailability, TelemetryLimitation

MANDATORY_FOR_HIGH_CONFIDENCE = {
    "processes", "signatures", "modules", "persistence_registry",
}


def compute_coverage(rows: List[TelemetryAvailability]) -> Tuple[float, List[TelemetryLimitation]]:
    total = sum(r.weight for r in rows) or 1.0
    available = sum(r.weight for r in rows if r.available)
    coverage = max(0.0, min(1.0, available / total))
    limitations: List[TelemetryLimitation] = []
    available_names = {r.name for r in rows if r.available}
    # In demo/CI mode the simulated environment stands in for every source.
    simulated_mode = "simulated" in available_names
    for name in sorted(MANDATORY_FOR_HIGH_CONFIDENCE):
        if simulated_mode:
            continue
        if name not in available_names and not any(r.name == name and r.available for r in rows):
            reason = next((r.reason for r in rows if r.name == name), "not reported")
            limitations.append(
                TelemetryLimitation(
                    source=name,
                    reason=f"{name} unavailable: {reason}",
                    impact="detections relying on this source run with reduced confidence",
                )
            )
    for r in rows:
        if not r.available and r.name.startswith("channel:"):
            limitations.append(
                TelemetryLimitation(
                    source=r.name, reason=f"{r.name}: {r.reason}",
                    impact="corroborating event telemetry unavailable",
                )
            )
    return coverage, limitations
