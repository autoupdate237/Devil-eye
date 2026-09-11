"""Memory-region metadata collector — strictly READ-ONLY.

We only *query* virtual memory descriptors of protected processes
(VirtualQueryEx) and classify regions:

* MEM_PRIVATE + PAGE_EXECUTE_*      → shellcode/JIT-injection candidate
* image-backed executable regions   → normal
* thread start addresses outside any module (when obtainable) → injected thread

Devil's Eye never writes to another process, never allocates remotely, and
never opens handles with write access. ``PolicyViolation`` guards that.
"""

from __future__ import annotations

import ctypes
from typing import Dict, List

from ..core.errors import PolicyViolation
from ..core.models import CollectorResult, Evidence, TelemetryAvailability
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext

# Allowed handle rights: query + read only. Anything else is a policy bug.
PROCESS_QUERY_LIMITED = 0x1000
PROCESS_VM_READ = 0x0010
ALLOWED_ACCESS = PROCESS_QUERY_LIMITED | PROCESS_VM_READ

MEM_IMAGE = 0x1000000
MEM_PRIVATE = 0x20000
EXECUTABLE_PROTECTIONS = {
    0x02,  # PAGE_EXECUTE
    0x04,  # PAGE_EXECUTE_READ
    0x08,  # PAGE_EXECUTE_READWRITE
    0x10,  # PAGE_EXECUTE_WRITECOPY
    0x40,  # PAGE_EXECUTE_READWRITE + GUARD
}
PROT_NAMES = {
    0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY", 0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
}


class MemoryCollector(Collector):
    name = "memory"
    description = "Read-only VAD/metadata inspection of protected processes"
    weight = 1.2
    sources = [
        "Virtual Address Descriptor (VirtualQueryEx)",
        "Thread start address metadata",
        "Sysmon Event ID 25 Process Tampering (correlation input)",
    ]

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        mode = ctx.policy.get("memory_inspection", "protected")
        if mode == "none":
            r.availability.append(
                TelemetryAvailability(self.name, False, "disabled by policy", self.weight, "memory")
            )
            return r
        if not is_windows():
            return r
        targets = [p for p in ctx.shared.get("processes") or []
                   if ctx.policy.is_protected_name(p.get("name") or "")]
        for proc in targets:
            regions = self._scan_process(int(proc["pid"]))
            if regions is None:
                r.errors.append(f"memory scan denied for pid {proc['pid']}")
                continue
            for region in regions:
                region.update({"pid": proc["pid"], "process_path": proc.get("path") or ""})
                r.evidences.append(
                    Evidence(
                        kind="memory", source="VirtualQueryEx", collector=self.name,
                        pid=proc["pid"], process_path=proc.get("path") or "", data=region,
                    )
                )
        ctx.shared["memory"] = [e.data for e in r.evidences]
        r.metrics = {"targets": len(targets), "regions_flagged": sum(1 for e in r.evidences if e.data.get("suspicious"))}
        return r

    # ------------------------------------------------------------------
    def _scan_process(self, pid: int) -> List[Dict] | None:
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover
            return None
        handle = kernel32.OpenProcess(ALLOWED_ACCESS, False, pid)
        if not handle:
            return None
        try:
            # Paranoia guard: we must never hold a write-capable handle.
            if ALLOWED_ACCESS & 0x0020:  # PROCESS_VM_WRITE
                raise PolicyViolation("memory collector attempted write access")

            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_uint32),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_uint32),
                    ("Protect", ctypes.c_uint32),
                    ("Type", ctypes.c_uint32),
                ]

            mbi = MEMORY_BASIC_INFORMATION()
            regions: List[Dict] = []
            address = 0
            max_address = 0x7FFFFFFFFFFF if 64 else 0x7FFEFFFF  # type: ignore[name-defined]
            flagged = 0
            while address < max_address:
                ret = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                                              ctypes.byref(mbi), ctypes.sizeof(mbi))
                if ret == 0:
                    break
                protect = mbi.Protect & 0xFF
                is_exec_private = (
                    mbi.State == 0x1000  # MEM_COMMIT
                    and mbi.Type == MEM_PRIVATE
                    and protect in EXECUTABLE_PROTECTIONS
                )
                if is_exec_private:
                    flagged += 1
                    regions.append(
                        {
                            "base": f"0x{mbi.BaseAddress or 0:012X}",
                            "size": mbi.RegionSize,
                            "state": "MEM_PRIVATE" if mbi.Type == MEM_PRIVATE else "MEM_IMAGE" if mbi.Type == MEM_IMAGE else hex(mbi.Type),
                            "protect": PROT_NAMES.get(protect, hex(protect)),
                            "note": "RWX/executable private region",
                            "suspicious": True,
                        }
                    )
                    if flagged >= 64:  # keep evidence volume sane
                        break
                address += mbi.RegionSize or 0x1000
            return regions
        finally:
            kernel32.CloseHandle(handle)
