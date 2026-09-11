"""Collector Layer.

Each collector maps to one or more families of the Windows telemetry catalog
(see docs/reference/SOURCE_COVERAGE.csv). Rules for this layer:

* a collector must NEVER crash the pipeline — the orchestrator isolates it;
* a collector must NEVER write to the monitored system (read-only posture);
* missing permissions / missing sources become TelemetryAvailability records,
  not exceptions.
"""

from .base import Collector, PipelineContext, run_collector  # noqa: F401
from .registry import all_collectors  # noqa: F401
