"""Build a typed, cross-linked HostSnapshot from raw Evidence records.

The normalizer never invents facts: it only indexes and joins what collectors
reported. Every field it exposes is traceable back to evidence ids, which the
Evidence Viewer shows to the operator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..core.models import Evidence


@dataclass
class ProcessView:
    pid: int
    ppid: int = 0
    name: str = ""
    path: str = ""
    cmdline: str = ""
    user: str = ""
    integrity_level: str = ""
    parent_path: str = ""
    created: Optional[float] = None
    sha256: str = ""
    signed: Optional[bool] = None
    publisher: str = ""
    signature_status: str = ""
    protected: bool = False
    modules: List[Evidence] = field(default_factory=list)
    memory_regions: List[Evidence] = field(default_factory=list)
    threads: List[Evidence] = field(default_factory=list)
    network: List[Evidence] = field(default_factory=list)
    related_events: List[Evidence] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return (self.sha256 or self.path).lower()


@dataclass
class HostSnapshot:
    processes: Dict[int, ProcessView] = field(default_factory=dict)
    persistence: List[Evidence] = field(default_factory=list)
    services: List[Evidence] = field(default_factory=list)
    tasks: List[Evidence] = field(default_factory=list)
    wmi_subscriptions: List[Evidence] = field(default_factory=list)
    drivers: List[Evidence] = field(default_factory=list)
    signatures: Dict[str, Evidence] = field(default_factory=dict)   # path.lower()
    events: List[Evidence] = field(default_factory=list)
    artifacts: List[Evidence] = field(default_factory=list)
    defender: List[Evidence] = field(default_factory=list)
    system: List[Evidence] = field(default_factory=list)
    by_path: Dict[str, ProcessView] = field(default_factory=dict)

    def protected_processes(self) -> List[ProcessView]:
        return [p for p in self.processes.values() if p.protected]

    def find_process_by_path(self, path: str) -> Optional[ProcessView]:
        return self.by_path.get((path or "").lower())


class Normalizer:
    def build(self, evidences: List[Evidence], protected_names: List[str]) -> HostSnapshot:
        snap = HostSnapshot()
        # Pass 1 — bucket by kind
        for ev in evidences:
            kind = ev.kind
            if kind == "process":
                self._process(snap, ev, protected_names)
            elif kind == "module":
                proc = snap.processes.get(ev.pid or -1)
                if proc:
                    proc.modules.append(ev)
            elif kind == "memory":
                proc = snap.processes.get(ev.pid or -1)
                if proc:
                    proc.memory_regions.append(ev)
            elif kind == "thread":
                proc = snap.processes.get(ev.pid or -1)
                if proc:
                    proc.threads.append(ev)
            elif kind == "network":
                proc = snap.processes.get(ev.pid or -1)
                if proc:
                    proc.network.append(ev)
            elif kind == "registry":
                snap.persistence.append(ev)
            elif kind == "service":
                snap.services.append(ev)
            elif kind == "scheduled_task":
                snap.tasks.append(ev)
            elif kind == "wmi":
                snap.wmi_subscriptions.append(ev)
            elif kind == "driver":
                snap.drivers.append(ev)
            elif kind == "signature":
                path = (ev.data.get("path") or ev.process_path or "").lower()
                if path:
                    snap.signatures[path] = ev
            elif kind == "event":
                snap.events.append(ev)
                self._attach_event(snap, ev)
            elif kind == "artifact":
                snap.artifacts.append(ev)
            elif kind == "telemetry":
                snap.defender.append(ev)
            elif kind == "system":
                snap.system.append(ev)
        # Pass 2 — join signatures onto processes/modules/services/drivers
        self._join_signatures(snap)
        return snap

    # ------------------------------------------------------------------
    def _process(self, snap: HostSnapshot, ev: Evidence, protected_names: List[str]) -> None:
        d = ev.data
        name = (d.get("name") or "").lower()
        view = ProcessView(
            pid=int(d.get("pid") or ev.pid or 0),
            ppid=int(d.get("ppid") or 0),
            name=d.get("name") or "",
            path=d.get("path") or "",
            cmdline=d.get("cmdline") or "",
            user=d.get("user") or "",
            integrity_level=d.get("integrity_level") or "",
            parent_path=d.get("parent_path") or "",
            created=d.get("created"),
            sha256=d.get("sha256") or "",
            signed=d.get("signed"),
            publisher=d.get("publisher") or "",
            signature_status=d.get("signature_status") or "",
            protected=any(name == p.lower() or name.endswith("\\" + p.lower()) for p in protected_names),
        )
        view.evidence_ids.append(ev.id)
        snap.processes[view.pid] = view
        if view.path:
            snap.by_path[view.path.lower()] = view

    def _attach_event(self, snap: HostSnapshot, ev: Evidence) -> None:
        fields = ev.data.get("fields") or {}
        for key in ("Image", "SourceImage", "TargetImage", "NewProcessName"):
            path = fields.get(key)
            if path:
                view = snap.find_process_by_path(path)
                if view:
                    view.related_events.append(ev)
                break

    def _join_signatures(self, snap: HostSnapshot) -> None:
        for view in snap.processes.values():
            sig = snap.signatures.get(view.path.lower())
            if sig:
                if view.signature_status == "":
                    view.signature_status = sig.data.get("status") or ""
                if not view.publisher:
                    view.publisher = sig.data.get("publisher") or ""
                if view.signed is None:
                    view.signed = (sig.data.get("status") == "Valid")
        for ev_list in (snap.services, snap.drivers):
            for ev in ev_list:
                sig = snap.signatures.get((ev.data.get("image_path") or "").lower())
                if sig and ev.data.get("signed") is None:
                    ev.data["signed"] = sig.data.get("status") == "Valid"
                    ev.data["publisher"] = sig.data.get("publisher") or ""
                    ev.data["signature_status"] = sig.data.get("status") or ""
        for view in snap.processes.values():
            for mod in view.modules:
                sig = snap.signatures.get((mod.data.get("module_path") or "").lower())
                if sig and mod.data.get("signed") is None:
                    mod.data["signed"] = sig.data.get("status") == "Valid"
                    mod.data["publisher"] = sig.data.get("publisher") or ""
                    mod.data["signature_status"] = sig.data.get("status") or ""
