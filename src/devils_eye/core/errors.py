"""Error hierarchy for Devil's Eye.

Design rule: collector/rule/scoring failures must *never* kill the pipeline.
They raise one of these, and the orchestrator converts them into
``TelemetryLimitation`` records that lower confidence and appear in reports.
"""

from __future__ import annotations


class DevilsEyeError(Exception):
    """Base class for all Devil's Eye errors."""


class CollectorUnavailable(DevilsEyeError):
    """A data source does not exist / is not accessible on this host.

    This is an *expected* condition (e.g. Sysmon not installed, no admin
    rights, running off-Windows) and is reported, not raised loudly.
    """

    def __init__(self, collector: str, reason: str):
        super().__init__(f"{collector}: {reason}")
        self.collector = collector
        self.reason = reason


class CollectorError(DevilsEyeError):
    """A collector exists but failed unexpectedly."""


class NormalizationError(DevilsEyeError):
    pass


class RuleError(DevilsEyeError):
    """A detection rule crashed; the rule engine isolates and skips it."""

    def __init__(self, rule_id: str, original: BaseException):
        super().__init__(f"rule {rule_id} failed: {original}")
        self.rule_id = rule_id
        self.original = original


class EvidenceStoreError(DevilsEyeError):
    pass


class ConfigError(DevilsEyeError):
    pass


class PolicyViolation(DevilsEyeError):
    """Raised when code attempts something against the defensive posture
    (e.g. opening a process with write access)."""
