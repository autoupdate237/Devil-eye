"""WMI permanent event subscription collector (classic fileless persistence)."""

from __future__ import annotations

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json

QUERIES = [
    ("filter", "Get-CimInstance __EventFilter -Namespace root/subscription"),
    ("consumer", "Get-CimInstance __EventConsumer -Namespace root/subscription"),
    ("binding", "Get-CimInstance __FilterToConsumerBinding -Namespace root/subscription"),
]


class WmiSubscriptionCollector(Collector):
    name = "wmi_persistence"
    description = "WMI permanent event subscriptions (filters/consumers/bindings)"
    weight = 1.0
    sources = [
        "WMI Permanent Consumer",
        "WMI Event Filter",
        "WMI Event Binding",
        "WMI Event 5857-5861 (correlation input)",
        "Sysmon Event ID 19/20/21 WMI (correlation input)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        for kind, script in QUERIES:
            rows = powershell_json(f"{script} | ConvertTo-Json -Depth 4", timeout=45)
            if rows is None:
                r.errors.append(f"WMI {kind} query failed")
                continue
            for row in rows:
                data = {"type": kind, "namespace": r"root\subscription"}
                if kind == "filter":
                    data.update(name=row.get("Name") or "", query=row.get("Query") or "")
                elif kind == "consumer":
                    data.update(
                        name=row.get("Name") or "",
                        consumer_type=(row.get("CimClass") or {}).get("CimClassName") or "",
                        command=row.get("ScriptText") or row.get("CommandLineTemplate") or "",
                    )
                else:
                    data.update(
                        name=row.get("Filter") or "",
                        filter=str(row.get("Filter") or ""),
                        consumer=str(row.get("Consumer") or ""),
                    )
                r.evidences.append(
                    Evidence(kind="wmi", source="WMI repository", collector=self.name, data=data)
                )
        ctx.shared["wmi_subscriptions"] = [e.data for e in r.evidences]
        r.metrics = {"entries": len(r.evidences)}
        return r
