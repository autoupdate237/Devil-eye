"""Collector base class and isolation wrapper."""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import Policy
from ..core.errors import CollectorError, CollectorUnavailable
from ..core.logging_setup import get_logger
from ..core.models import CollectorResult, TelemetryAvailability

log = get_logger("collectors")


@dataclass
class PipelineContext:
    """Everything a collector may look at. Collectors must treat it as
    read-only."""

    policy: Policy
    mode: str = "scan"                      # scan | monitor | forensic
    elevated: bool = False
    workspace: Optional[Path] = None
    options: Dict[str, Any] = field(default_factory=dict)
    # Filled in by earlier collectors (e.g. process list for deep scans)
    shared: Dict[str, Any] = field(default_factory=dict)


class Collector(abc.ABC):
    """Abstract collector.

    ``sources`` lists the catalog source names this collector feeds, so the
    Telemetry Status panel can show which candidate sources are reachable at
    family granularity.
    """

    name: str = "abstract"
    description: str = ""
    sources: List[str] = []
    weight: float = 1.0                     # importance for confidence scaling
    requires_windows: bool = True

    def __init__(self) -> None:
        self._log = get_logger(f"collectors.{self.name}")

    # ------------------------------------------------------------------
    def available(self, ctx: PipelineContext) -> TelemetryAvailability:
        """Cheap availability probe. Default: requires Windows."""
        if self.requires_windows:
            from ..core.platform_info import is_windows

            if not is_windows():
                return TelemetryAvailability(
                    self.name, False, "not a Windows host", self.weight, self.name
                )
        return TelemetryAvailability(self.name, True, "", self.weight, self.name)

    @abc.abstractmethod
    def collect(self, ctx: PipelineContext) -> CollectorResult:
        """Collect evidence. Implementations should raise CollectorUnavailable
        for expected missing sources; unexpected errors are caught by
        ``run_collector`` and converted into limitations."""

    def _result(self) -> CollectorResult:
        return CollectorResult(collector=self.name)


def run_collector(collector: Collector, ctx: PipelineContext) -> CollectorResult:
    """Isolated execution: ANY failure becomes a result with availability
    records and error strings — the pipeline never aborts because of one
    source ('No single-source dependency')."""
    started = time.monotonic()
    result = CollectorResult(collector=collector.name)
    try:
        availability = collector.available(ctx)
        result.availability.append(availability)
        if not availability.available:
            result.duration_s = time.monotonic() - started
            return result
        result = collector.collect(ctx)
        result.availability.insert(0, availability)
    except CollectorUnavailable as exc:
        result.errors.append(str(exc))
        result.availability = [
            TelemetryAvailability(collector.name, False, exc.reason, collector.weight, collector.name)
        ]
    except (CollectorError, Exception) as exc:  # noqa: BLE001 — isolation boundary
        log.warning("collector %s failed: %s", collector.name, exc)
        result.errors.append(f"unexpected: {exc}")
        result.availability = [
            TelemetryAvailability(
                collector.name, False, f"collector error: {exc}", collector.weight, collector.name
            )
        ]
    result.duration_s = time.monotonic() - started
    return result
