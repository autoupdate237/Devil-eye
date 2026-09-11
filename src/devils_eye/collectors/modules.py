"""Module/DLL collector.

Enumerating modules of every process requires PROCESS_QUERY_INFORMATION +
PROCESS_VM_READ on each — expensive and rights-sensitive. Strategy:

* enumerate modules for *protected* processes and *shortlisted* processes
  (unsigned / suspicious path / user config) up to ``max_processes_deep``;
* PowerShell ``Get-Process -Module`` is the read-only backend.
"""

from __future__ import annotations

from typing import List

from ..core.models import CollectorResult, Evidence
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext
from .helpers import powershell_json

# Kernel-provided modules that legitimately load from System32 — used by the
# masquerade rule; keep this list short and conservative.
KNOWN_SYSTEM_MODULES = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "ole32.dll", "shell32.dll", "ws2_32.dll", "crypt32.dll",
}


class ModuleCollector(Collector):
    name = "modules"
    description = "Loaded module inventory for protected/shortlisted processes"
    weight = 1.0
    sources = [
        "Process module list (EnumProcessModules)",
        "Sysmon Event ID 7 Image Loaded (correlation input)",
        "ETW Image Load Provider (opt-in)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if not is_windows():
            return r
        targets = self._select_targets(ctx)
        if not targets:
            r.metrics = {"note": "no protected/shortlisted processes running"}
            return r
        budget = int(ctx.policy.get("max_processes_deep", 40))
        for proc in targets[:budget]:
            rows = powershell_json(
                f"(Get-Process -Id {proc['pid']} -ErrorAction SilentlyContinue).Modules | "
                "Select-Object FileName,ModuleName,BaseAddress,ModuleMemorySize | "
                "ConvertTo-Json -Depth 4",
                timeout=30,
            )
            if rows is None:
                r.errors.append(f"module enumeration denied for pid {proc['pid']}")
                continue
            for m in rows:
                r.evidences.append(
                    Evidence(
                        kind="module",
                        source="EnumProcessModules",
                        collector=self.name,
                        pid=proc["pid"],
                        process_path=proc.get("path") or "",
                        data={
                            "pid": proc["pid"],
                            "process_path": proc.get("path") or "",
                            "module_path": m.get("FileName") or "",
                            "name": m.get("ModuleName") or "",
                            "base": m.get("BaseAddress") or "",
                            "size": m.get("ModuleMemorySize"),
                            "sha256": "", "signed": None, "publisher": "",
                            "signature_status": "",
                        },
                    )
                )
        r.metrics = {"targets": len(targets), "modules": len(r.evidences)}
        return r

    # ------------------------------------------------------------------
    def _select_targets(self, ctx: PipelineContext) -> List[dict]:
        procs = ctx.shared.get("processes") or []
        targets, seen = [], set()
        # 1) protected processes always
        for p in procs:
            name = (p.get("name") or "").lower()
            if ctx.policy.is_protected_name(name) and p["pid"] not in seen:
                targets.append(p)
                seen.add(p["pid"])
        # 2) suspicious candidates: temp/public paths, unsigned (if known)
        for p in procs:
            path = (p.get("path") or "").lower()
            suspicious = any(
                frag in path
                for frag in ("\\temp\\", "\\users\\public\\", "\\appdata\\local\\temp", "\\desktop\\")
            )
            if suspicious and p["pid"] not in seen:
                targets.append(p)
                seen.add(p["pid"])
        return targets
