"""Collector registry — the single place where the pipeline learns which data
sources exist. Order matters: earlier collectors populate ``ctx.shared`` for
later ones (processes → modules → signatures → memory …)."""

from __future__ import annotations

from typing import List

from .artifacts import ArtifactCollector
from .base import Collector
from .defender import DefenderCollector
from .drivers import DriverCollector
from .etw import EtwCollector
from .eventlog import EventLogCollector
from .memory import MemoryCollector
from .modules import ModuleCollector
from .network import NetworkCollector
from .persistence import RegistryPersistenceCollector
from .processes import ProcessCollector
from .scheduled_tasks import ScheduledTaskCollector
from .services import ServiceCollector
from .signatures import SignatureCollector
from .sysmon import SysmonCollector
from .wmi_persist import WmiSubscriptionCollector


def all_collectors() -> List[Collector]:
    return [
        ProcessCollector(),
        ModuleCollector(),
        SignatureCollector(),
        MemoryCollector(),
        RegistryPersistenceCollector(),
        ServiceCollector(),
        ScheduledTaskCollector(),
        WmiSubscriptionCollector(),
        DriverCollector(),
        NetworkCollector(),
        DefenderCollector(),
        SysmonCollector(),
        EventLogCollector(),
        EtwCollector(),
        ArtifactCollector(),
    ]
