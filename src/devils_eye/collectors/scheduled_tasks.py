"""Scheduled task collector (Task Scheduler registrations + XML)."""

from __future__ import annotations

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json


class ScheduledTaskCollector(Collector):
    name = "scheduled_tasks"
    description = "Registered scheduled tasks with actions and triggers"
    weight = 1.0
    sources = [
        "Scheduled Tasks (C:\\Windows\\System32\\Tasks XML)",
        "TaskCache",
        "TaskScheduler Event 106/129/140/141 (correlation input)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or not is_windows():
            return r
        rows = powershell_json(
            "Get-ScheduledTask | Select-Object TaskName,TaskPath,Author,State,"
            "@{n='Actions';e={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}},"
            "@{n='Triggers';e={($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '; '}} | "
            "ConvertTo-Json -Depth 4",
            timeout=90,
        )
        if rows is None:
            r.errors.append("Get-ScheduledTask failed")
            r.availability[0].available = False
            r.availability[0].reason = "ScheduledTasks API unavailable"
            return r
        for row in rows:
            r.evidences.append(
                Evidence(
                    kind="scheduled_task",
                    source="Get-ScheduledTask",
                    collector=self.name,
                    data={
                        "name": row.get("TaskName") or "",
                        "path": (row.get("TaskPath") or "") + (row.get("TaskName") or ""),
                        "actions": row.get("Actions") or "",
                        "triggers": row.get("Triggers") or "",
                        "author": row.get("Author") or "",
                        "enabled": (row.get("State") or "") != "Disabled",
                        "state": row.get("State") or "",
                    },
                    process_path=self._first_exe(row.get("Actions") or ""),
                )
            )
        ctx.shared["tasks"] = [e.data for e in r.evidences]
        r.metrics = {"tasks": len(r.evidences)}
        return r

    @staticmethod
    def _first_exe(actions: str) -> str:
        for part in actions.split(";"):
            part = part.strip().strip('"')
            if part:
                return part.split(" ")[0]
        return ""
