"""Detection Rule engine.

Rules are registered via ``@rule(...)`` and executed in isolation: a rule that
raises is recorded as a RuleError limitation and skipped, never aborting the
scan. Every rule must emit Indicator objects whose evidence_ids point into the
Evidence Store ('Which evidence supports it').
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from ..core.config import Policy
from ..core.errors import RuleError
from ..core.logging_setup import get_logger
from ..core.models import Indicator, TelemetryLimitation
from ..normalization.normalizer import HostSnapshot

log = get_logger("detection")

RuleFn = Callable[[HostSnapshot, Policy], List[Indicator]]


@dataclass
class RuleSpec:
    id: str
    name: str
    category: str
    severity: float
    base_confidence: float
    fn: RuleFn
    description: str = ""
    doc: dict = field(default_factory=dict)   # What/Where/Evidence/Confidence/Risk


_REGISTRY: List[RuleSpec] = []


def rule(rule_id: str, name: str, category: str, severity: float, confidence: float,
         what: str, where: str, evidence: str, risk: str):
    """Decorator registering a detection rule with its explanation contract."""

    def deco(fn: RuleFn) -> RuleFn:
        _REGISTRY.append(
            RuleSpec(
                id=rule_id, name=name, category=category, severity=severity,
                base_confidence=confidence, fn=fn,
                doc={"what": what, "where": where, "evidence": evidence, "risk": risk},
            )
        )
        return fn

    return deco


def all_rules() -> List[RuleSpec]:
    return list(_REGISTRY)


class DetectionEngine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def run(self, snapshot: HostSnapshot) -> tuple[List[Indicator], List[TelemetryLimitation]]:
        indicators: List[Indicator] = []
        limitations: List[TelemetryLimitation] = []
        # Import rule packs so their @rule decorators execute.
        from . import rules  # noqa: F401

        for spec in _REGISTRY:
            try:
                found = spec.fn(snapshot, self.policy) or []
                for ind in found:
                    # Backfill stable fields from the spec.
                    ind.rule_id = ind.rule_id or spec.id
                    ind.rule_name = ind.rule_name or spec.name
                    ind.category = ind.category or spec.category
                    ind.severity = ind.severity if ind.severity else spec.severity
                    ind.confidence = ind.confidence if ind.confidence else spec.base_confidence
                indicators.extend(found)
            except Exception as exc:  # noqa: BLE001 — rule isolation boundary
                log.warning("rule %s failed: %s", spec.id, exc)
                limitations.append(
                    TelemetryLimitation(
                        source=f"rule:{spec.id}",
                        reason=str(RuleError(spec.id, exc)),
                        impact="this detection is unavailable in this scan",
                    )
                )
        return indicators, limitations
