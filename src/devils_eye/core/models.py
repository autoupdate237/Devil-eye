"""Data models shared across every pipeline layer.

Pipeline: Collector → Normalization → Evidence Store → Correlation → Detection
Rules → Risk Scoring → Verdict Engine → Report/UI.

Every record here is JSON-serialisable so the Evidence Store (SQLite), the HTTP
API and the reports all consume the same shapes.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------
# Evidence — one raw observation from any collector
# --------------------------------------------------------------------------

class EvidenceKind(str, enum.Enum):
    PROCESS = "process"
    MODULE = "module"
    MEMORY = "memory"
    THREAD = "thread"
    FILE = "file"
    SIGNATURE = "signature"
    REGISTRY = "registry"
    SERVICE = "service"
    TASK = "scheduled_task"
    WMI = "wmi"
    DRIVER = "driver"
    NETWORK = "network"
    EVENT = "event"            # EVTX / Sysmon / ETW-derived events
    ARTIFACT = "artifact"      # Prefetch/Amcache/Shimcache/BAM/UserAssist/...
    SYSTEM = "system"
    TELEMETRY = "telemetry"


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Evidence:
    """A single observation. ``source`` names *where it came from* (channel,
    artifact path, collector...), which feeds the Evidence Viewer and the
    'Which evidence supports it' part of every detection explanation."""

    kind: str
    source: str                       # e.g. "Microsoft-Windows-Sysmon/Operational EID1"
    collector: str                    # collector name that produced it
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: _new_id("ev"))
    # Subject linkage (best effort; empty string when not applicable)
    pid: Optional[int] = None
    process_path: str = ""
    hash_sha256: str = ""
    user: str = ""
    # Free-form structured payload (normalised per kind)
    data: Dict[str, Any] = field(default_factory=dict)

    def subject_key(self) -> str:
        """Stable grouping key used by correlation + scoring."""
        return (self.hash_sha256 or self.process_path or "").lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Telemetry availability — 'No single-source dependency' requirement
# --------------------------------------------------------------------------

@dataclass
class TelemetryAvailability:
    name: str                     # collector / channel / artifact name
    available: bool
    reason: str = ""              # why unavailable (not installed, no rights…)
    weight: float = 1.0           # importance for confidence scaling
    category: str = "general"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Indicators / Detections / Verdict
# --------------------------------------------------------------------------

class IndicatorCategory(str, enum.Enum):
    PROCESS_INTEGRITY = "process_integrity"
    MODULE_INTEGRITY = "module_integrity"
    MEMORY_INTEGRITY = "memory_integrity"
    SIGNATURE = "signature"
    ANCESTRY = "ancestry"
    COMMAND_LINE = "command_line"
    PERSISTENCE = "persistence"
    NETWORK = "network"
    DRIVER = "driver"
    SERVICE = "service"
    TASK = "scheduled_task"
    WMI = "wmi"
    FILE_INTEGRITY = "file_integrity"
    TELEMETRY = "telemetry"


class VerdictLevel(str, enum.Enum):
    CLEAN = "CLEAN"
    LOW_RISK = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {
            VerdictLevel.CLEAN: 0,
            VerdictLevel.LOW_RISK: 1,
            VerdictLevel.SUSPICIOUS: 2,
            VerdictLevel.HIGH_RISK: 3,
            VerdictLevel.CRITICAL: 4,
        }[self]


@dataclass
class Indicator:
    """One fired detection rule. Answers:
    What   -> title + description
    Where  -> subject (pid/path/hash) + location fields
    Evidence -> evidence_ids (into the Evidence Store)
    Confidence -> 0..1
    Risk contribution -> computed by the scoring engine."""

    rule_id: str
    rule_name: str
    category: str
    severity: float                # 0..10
    confidence: float              # 0..1
    title: str
    description: str
    subject_key: str = ""
    pid: Optional[int] = None
    process_path: str = ""
    hash_sha256: str = ""
    location: str = ""             # registry key / file path / memory region…
    evidence_ids: List[str] = field(default_factory=list)
    extras: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: _new_id("ind"))
    ts: float = field(default_factory=time.time)
    # Filled by correlation/scoring:
    corroboration: float = 1.0
    allowlist_dampening: float = 1.0
    risk_contribution: float = 0.0
    suppressed: bool = False
    suppressed_reason: str = ""

    def explanation(self) -> Dict[str, Any]:
        """The mandatory 5-part explanation format."""
        return {
            "what": self.title,
            "where": self.location or self.process_path or "(host-wide)",
            "evidence": self.evidence_ids,
            "confidence": round(self.confidence, 3),
            "risk_contribution": round(self.risk_contribution, 2),
        }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationGroup:
    """Indicators + evidence clustered around one subject (binary/process)."""

    subject_key: str
    process_path: str = ""
    pid: Optional[int] = None
    indicator_ids: List[str] = field(default_factory=list)
    evidence_sources: List[str] = field(default_factory=list)
    corroboration_factor: float = 1.0
    parent_key: str = ""
    child_keys: List[str] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    level: str
    score: float                   # 0..100
    confidence: float              # 0..1 (telemetry-coverage scaled)
    telemetry_coverage: float      # 0..1
    rationale: List[str] = field(default_factory=list)
    subject_scores: Dict[str, float] = field(default_factory=dict)
    top_indicators: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Collector plumbing
# --------------------------------------------------------------------------

@dataclass
class CollectorResult:
    collector: str
    evidences: List[Evidence] = field(default_factory=list)
    availability: List[TelemetryAvailability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------
# Allowlist / policy
# --------------------------------------------------------------------------

@dataclass
class AllowlistEntry:
    kind: str                      # hash | publisher | path_prefix | directory
    value: str
    action: str = "dampen"         # dampen | suppress
    factor: float = 0.15           # risk multiplier when dampening
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TelemetryLimitation:
    source: str
    reason: str
    impact: str                    # what detection confidence this reduces

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
