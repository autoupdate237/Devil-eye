"""Correlation Engine.

Responsibilities:
1. cluster indicators by subject (binary hash/path);
2. count *independent evidence sources* backing each cluster → corroboration
   factor (the core anti-false-positive lever);
3. link parent/child subjects so chains (loader → injector → game) can be
   escalated as a unit;
4. NEVER decide verdicts — that is the Verdict Engine's job.
"""

from __future__ import annotations

from typing import Dict, List

from ..core.models import CorrelationGroup, Indicator
from ..normalization.normalizer import HostSnapshot

CORROBORATION_STEP = 0.15
CORROBORATION_CAP = 1.6


class CorrelationEngine:
    def run(self, snapshot: HostSnapshot, indicators: List[Indicator]) -> Dict[str, CorrelationGroup]:
        groups: Dict[str, CorrelationGroup] = {}
        for ind in indicators:
            if ind.suppressed:
                continue
            key = ind.subject_key or ind.process_path.lower() or "(host)"
            g = groups.setdefault(
                key,
                CorrelationGroup(subject_key=key, process_path=ind.process_path, pid=ind.pid),
            )
            g.indicator_ids.append(ind.id)
        # Count distinct evidence sources per subject from the snapshot.
        source_map = self._evidence_source_map(snapshot)
        for key, g in groups.items():
            sources = source_map.get(key, set())
            g.evidence_sources = sorted(sources)
            n = max(1, len(sources))
            g.corroboration_factor = min(CORROBORATION_CAP, 1.0 + CORROBORATION_STEP * (n - 1))
        # Link process tree using snapshot ancestry.
        key_by_path = {}
        for view in snapshot.processes.values():
            if view.path:
                key_by_path[view.path.lower()] = view.key
        for key, g in groups.items():
            view = snapshot.find_process_by_path(g.process_path)
            if view and view.parent_path:
                parent_key = key_by_path.get(view.parent_path.lower(), "")
                if parent_key and parent_key in groups:
                    g.parent_key = parent_key
                    groups[parent_key].child_keys.append(key)
        return groups

    # ------------------------------------------------------------------
    @staticmethod
    def _evidence_source_map(snapshot: HostSnapshot) -> Dict[str, set]:
        m: Dict[str, set] = {}

        def add(key: str, source: str) -> None:
            if key:
                m.setdefault(key, set()).add(source)

        for view in snapshot.processes.values():
            add(view.key, "process_inventory")
            if view.signature_status:
                add(view.key, f"signature:{view.signature_status}")
            if view.cmdline:
                add(view.key, "command_line")
            for mod in view.modules:
                mpath = (mod.data.get("module_path") or "").lower()
                add(mpath, "module_inventory")
                if mod.data.get("signature_status"):
                    add(mpath, f"signature:{mod.data.get('signature_status')}")
            for _ in view.memory_regions:
                add(view.key, "memory_regions")
            for t in view.threads:
                if not t.data.get("backed_by_image", True):
                    add(view.key, "thread_metadata")
            for _ in view.network:
                add(view.key, "network_endpoints")
            for ev in view.related_events:
                add(view.key, f"event:{ev.source}#{ev.data.get('event_id')}")
        for ev in snapshot.persistence:
            add((ev.process_path or ev.data.get("data") or "").lower(), f"persistence:{ev.source}")
            add((ev.data.get("data") or "").split(" ")[0].lower(), f"persistence:{ev.source}")
        for ev in snapshot.services + snapshot.drivers:
            add((ev.data.get("image_path") or "").lower(), f"{ev.kind}:{ev.source}")
        for ev in snapshot.tasks:
            action = (ev.data.get("actions") or "").split(";")[0].strip().strip('"')
            add((action.split(" ")[0] if action else "").lower(), f"task:{ev.source}")
        for ev in snapshot.events:
            for key_field in ("Image", "SourceImage", "TargetImage", "NewProcessName"):
                p = (ev.data.get("fields") or {}).get(key_field)
                if p:
                    add(p.lower(), f"event:{ev.source}#{ev.data.get('event_id')}")
        return m
