"""Detection rule packs.

Each rule answers the mandatory format:
What was detected → Where → Which evidence → Confidence → Risk contribution.

Imported by the DetectionEngine; every rule executes in isolation.
"""

from __future__ import annotations

import re
from typing import List

from ..core.config import Policy
from ..core.models import Evidence, Indicator
from ..normalization.normalizer import HostSnapshot, ProcessView
from .engine import rule

SYSTEM_MODULE_DIRS = (r"c:\windows\system32", r"c:\windows\syswow64", r"c:\windows\winsxs")
WRITABLE_SHARED_FRAGMENTS = (
    "\\users\\public\\", "\\temp\\", "\\appdata\\local\\temp",
    "\\appdata\\local\\microsoft\\windows\\inetcache",
)
SUSPICIOUS_PARENTS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                      "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe")
KNOWN_SYSTEM_MODULES = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "ole32.dll", "shell32.dll", "ws2_32.dll", "crypt32.dll",
}
CMDLINE_PATTERNS = [
    (re.compile(r"--inject\b|/inject\b", re.I), "explicit injection flag on command line", 8.0),
    (re.compile(r"powershell.*-(e|enc|encodedcommand)\b", re.I), "encoded PowerShell command", 6.0),
    (re.compile(r"regsvr32\s+/i:https?://", re.I), "regsvr32 squiblydoo-style remote load", 8.0),
    (re.compile(r"mshta\s+(vbscript:|javascript:|https?://)", re.I), "mshta script execution", 7.0),
    (re.compile(r"rundll32(\\.exe)?.*[\\/]temp[\\/].*\.dll", re.I), "rundll32 executing DLL from temp", 7.5),
    (re.compile(r"-nop(rofile)?\s+-w(indowstyle)?\s+hidden", re.I), "hidden PowerShell window", 4.0),
]


def _mk(title: str, description: str, view_or_path, evidence_ids: List[str],
        location: str = "", confidence: float = 0.0, **extras) -> Indicator:
    if isinstance(view_or_path, ProcessView):
        path, pid, sha = view_or_path.path, view_or_path.pid, view_or_path.sha256
    else:
        path, pid, sha = str(view_or_path or ""), None, ""
    return Indicator(
        rule_id="", rule_name="", category="", severity=0.0, confidence=confidence,
        title=title, description=description,
        subject_key=(sha or path).lower(), pid=pid, process_path=path, hash_sha256=sha,
        location=location or path, evidence_ids=list(evidence_ids), extras=extras,
    )


def _in_writable_shared(path: str) -> bool:
    p = path.lower()
    return any(f in p for f in WRITABLE_SHARED_FRAGMENTS)


def _in_system_dir(path: str) -> bool:
    p = path.lower()
    return any(p.startswith(d) for d in SYSTEM_MODULE_DIRS)


def _sig_evidence_ids(snap: HostSnapshot, path: str) -> List[str]:
    ev = snap.signatures.get(path.lower())
    return [ev.id] if ev else []


# ==========================================================================
# Process integrity
# ==========================================================================

@rule(
    "DE-PROC-001", "Unsigned executable outside trusted directories",
    "process_integrity", 4.0, 0.6,
    what="A running executable has no valid Authenticode signature and lives outside trusted OS directories.",
    where="Process inventory (path of the image).",
    evidence="Process evidence + Authenticode status evidence for the same path.",
    risk="Weak on its own; gains weight only when corroborated (modules, network, telemetry).",
)
def unsigned_executable(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.processes.values():
        if view.signed is not False:
            continue
        if policy.in_trusted_directory(view.path) or not view.path:
            continue
        ev_ids = view.evidence_ids + _sig_evidence_ids(snap, view.path)
        out.append(_mk(
            f"Unsigned executable: {view.name}",
            f"'{view.path}' is running without a valid signature (pid {view.pid}).",
            view, ev_ids, confidence=0.6,
        ))
    return out


@rule(
    "DE-PROC-002", "Executable running from world-writable/shared location",
    "process_integrity", 6.0, 0.7,
    what="Code executes from Users\\Public, Temp or INetCache — classic dropper staging areas.",
    where="Process inventory + file path.",
    evidence="Process evidence; path string; signature status when present.",
    risk="Medium: legitimate installers sometimes stage here, so confidence stays moderate.",
)
def executable_in_writable_shared(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.processes.values():
        if view.path and _in_writable_shared(view.path):
            ev_ids = view.evidence_ids + _sig_evidence_ids(snap, view.path)
            out.append(_mk(
                f"Executable staged in writable location: {view.name}",
                f"'{view.path}' (pid {view.pid}) runs from a world-writable staging directory.",
                view, ev_ids, confidence=0.7,
            ))
    return out


# ==========================================================================
# Ancestry / command line
# ==========================================================================

@rule(
    "DE-ANC-001", "Protected process launched by a scripting/shell host",
    "ancestry", 6.0, 0.65,
    what="The protected game was started by cmd/powershell/wscript/mshta instead of its normal launcher.",
    where="Process tree (parent→child relation).",
    evidence="Process evidence for both parent and child.",
    risk="Medium-high for games; cheat loaders frequently boot games through a shell.",
)
def suspicious_parent_of_protected(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.protected_processes():
        parent_name = view.parent_path.rsplit("\\", 1)[-1].lower()
        if parent_name in SUSPICIOUS_PARENTS:
            parent = snap.find_process_by_path(view.parent_path)
            ev_ids = view.evidence_ids + (parent.evidence_ids if parent else [])
            out.append(_mk(
                f"Protected process '{view.name}' launched by {parent_name}",
                f"Parent '{view.parent_path}' → child '{view.path}'.",
                view, ev_ids, confidence=0.65, parent=view.parent_path,
            ))
    return out


@rule(
    "DE-CMD-001", "Suspicious command-line pattern",
    "command_line", 5.0, 0.0,  # confidence & severity adjusted per pattern
    what="Command line matches known injection/obfuscation/living-off-the-land patterns.",
    where="Process command line (process inventory / Sysmon EID1 / Security 4688).",
    evidence="Process evidence carrying the raw command line.",
    risk="Varies by pattern; encoded PowerShell alone is low, explicit --inject is high.",
)
def cmdline_patterns(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.processes.values():
        cmdline = view.cmdline or ""
        if not cmdline:
            continue
        for pattern, label, severity in CMDLINE_PATTERNS:
            if pattern.search(cmdline):
                ind = _mk(
                    f"Command-line indicator: {label}",
                    f"'{cmdline[:400]}' on pid {view.pid}.",
                    view, view.evidence_ids, location=view.path, confidence=0.7,
                )
                ind.severity = severity
                out.append(ind)
    return out


# ==========================================================================
# Module / DLL integrity
# ==========================================================================

@rule(
    "DE-MOD-001", "Unsigned module loaded into the protected process",
    "module_integrity", 8.0, 0.85,
    what="A DLL without a valid signature is mapped into the protected game.",
    where="Module inventory of the protected process.",
    evidence="Module evidence (path/base/size) + signature evidence.",
    risk="High: injected cheat DLLs are typically unsigned or stolen-signed.",
)
def unsigned_module_in_protected(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.protected_processes():
        for mod in view.modules:
            d = mod.data
            if d.get("signed") is False:
                out.append(_mk(
                    f"Unsigned module in protected process: {d.get('name')}",
                    f"'{d.get('module_path')}' mapped into '{view.path}' (pid {view.pid}).",
                    view, [mod.id] + _sig_evidence_ids(snap, d.get("module_path") or ""),
                    location=d.get("module_path") or "", confidence=0.85,
                ))
    return out


@rule(
    "DE-MOD-002", "System module masquerading (wrong path)",
    "module_integrity", 9.0, 0.9,
    what="A module carries the name of a core Windows DLL but is loaded from outside System32/SysWOW64.",
    where="Module inventory; path vs. canonical system directories.",
    evidence="Module evidence with path + name; catalog of canonical locations.",
    risk="Very high: ntdll/kernel32 can only legitimately come from system directories.",
)
def module_masquerade(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.processes.values():
        for mod in view.modules:
            d = mod.data
            name = (d.get("name") or "").lower()
            mpath = d.get("module_path") or ""
            if name in KNOWN_SYSTEM_MODULES and mpath and not _in_system_dir(mpath):
                out.append(_mk(
                    f"Masquerading system module: {name}",
                    f"'{mpath}' loaded into '{view.path}' but genuine {name} lives in System32.",
                    view, [mod.id], location=mpath, confidence=0.9,
                ))
    return out


@rule(
    "DE-MOD-003", "Module loaded from temp/public directory",
    "module_integrity", 5.0, 0.7,
    what="A DLL is mapped from a staging directory into any process.",
    where="Module inventory.",
    evidence="Module evidence (path).",
    risk="Medium: updaters do this occasionally; corroborate before escalation.",
)
def module_from_writable_shared(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    seen = set()
    for view in snap.processes.values():
        for mod in view.modules:
            mpath = mod.data.get("module_path") or ""
            if mpath and _in_writable_shared(mpath) and mpath.lower() not in seen:
                seen.add(mpath.lower())
                out.append(_mk(
                    f"Module staged in writable location: {mod.data.get('name')}",
                    f"'{mpath}' mapped into '{view.path}'.",
                    view, [mod.id], location=mpath, confidence=0.7,
                ))
    return out


# ==========================================================================
# Memory integrity (metadata only)
# ==========================================================================

@rule(
    "DE-MEM-001", "Executable private memory in the protected process",
    "memory_integrity", 8.0, 0.75,
    what="MEM_PRIVATE region with execute protection — classic shellcode/injected-code shape.",
    where="Virtual memory region metadata of the protected process.",
    evidence="Memory region evidence (base/size/state/protect).",
    risk="High for a protected game (JIT engines normally use image-backed or RW→RX transitions).",
)
def rwx_private_memory(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.protected_processes():
        flagged = [m for m in view.memory_regions if m.data.get("suspicious")]
        if flagged:
            out.append(_mk(
                f"{len(flagged)} executable private region(s) in {view.name}",
                "Private (not image-backed) memory with execute rights in the protected process.",
                view, [m.id for m in flagged],
                location=flagged[0].data.get("base") or "", confidence=0.75,
                region_count=len(flagged),
            ))
    return out


@rule(
    "DE-MEM-002", "Thread start address outside any module",
    "memory_integrity", 9.0, 0.85,
    what="A thread begins executing at an address not backed by a mapped image — injected thread.",
    where="Thread metadata of the protected process.",
    evidence="Thread evidence (tid/start_address/backing module).",
    risk="Very high: legitimate threads start inside ntdll/CLR/loader stubs.",
)
def thread_start_outside_image(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.protected_processes():
        bad = [t for t in view.threads if t.data.get("backed_by_image") is False]
        for t in bad:
            out.append(_mk(
                f"Injected-thread indicator in {view.name} (tid {t.data.get('tid')})",
                f"Start address {t.data.get('start_address')} has no backing module.",
                view, [t.id], location=str(t.data.get("start_address")), confidence=0.85,
            ))
    return out


# ==========================================================================
# Signatures
# ==========================================================================

@rule(
    "DE-SIG-001", "Broken/tampered Authenticode signature",
    "signature", 8.0, 0.9,
    what="Signature validation failed (HashMismatch/NotSigned-on-expected/revoked) for a running image.",
    where="Authenticode verification result for the file path.",
    evidence="Signature evidence (status, publisher, chain validity).",
    risk="High: a *broken* signature (vs. absent) usually means a modified binary.",
)
def broken_signature(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    bad_states = ("HashMismatch", "UnknownError", "NotSigned")
    for path, ev in snap.signatures.items():
        status = ev.data.get("status") or ""
        if status in ("HashMismatch", "UnknownError"):
            view = snap.find_process_by_path(path) or path
            out.append(_mk(
                f"Signature integrity failure: {path.rsplit(chr(92), 1)[-1]}",
                f"Authenticode status '{status}' for '{path}'.",
                view, [ev.id], location=path, confidence=0.9,
            ))
    return out


# ==========================================================================
# Drivers / services / tasks / WMI / persistence
# ==========================================================================

@rule(
    "DE-DRV-001", "Driver with invalid or missing signature",
    "driver", 10.0, 0.9,
    what="A kernel driver is unsigned or fails integrity checks.",
    where="Driver inventory + CodeIntegrity operational events.",
    evidence="Driver evidence + CodeIntegrity 3033/3034 events when present.",
    risk="Critical: ring-0 code can read/write any game memory.",
)
def bad_driver_signature(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for drv in snap.drivers:
        d = drv.data
        status = d.get("signature_status") or ("" if d.get("signed") else "NotSigned")
        if d.get("signed") is False or status in ("HashMismatch", "NotSigned"):
            ci_events = [e.id for e in snap.events
                         if e.data.get("channel", "").startswith("Microsoft-Windows-CodeIntegrity")
                         and str(e.data.get("event_id")) in ("3033", "3034")
                         and (d.get("image_path") or "").lower() in str(e.data.get("fields")).lower()]
            out.append(_mk(
                f"Driver signature failure: {d.get('name')}",
                f"'{d.get('image_path')}' status='{status or 'unknown'}', state={d.get('state')}.",
                d.get("image_path") or "", [drv.id] + ci_events,
                location=d.get("image_path") or "", confidence=0.9,
            ))
    return out


@rule(
    "DE-SVC-001", "Service pointing at unsigned binary in writable path",
    "service", 8.0, 0.8,
    what="An installed service runs an unsigned binary from Temp/Public/AppData.",
    where="Service configuration (ImagePath).",
    evidence="Service evidence + signature evidence for the image path.",
    risk="High: persistence with SYSTEM start.",
)
def service_in_writable_path(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for svc in snap.services:
        d = svc.data
        path = d.get("image_path") or ""
        if path and _in_writable_shared(path) and d.get("signed") is not True:
            out.append(_mk(
                f"Suspicious service: {d.get('name')}",
                f"Service '{d.get('name')}' runs '{path}' (start={d.get('start')}, user={d.get('user')}).",
                path, [svc.id] + _sig_evidence_ids(snap, path), location=path, confidence=0.8,
            ))
    return out


@rule(
    "DE-TASK-001", "Scheduled task executing from temp",
    "scheduled_task", 7.0, 0.75,
    what="A scheduled task's action runs a binary staged in Temp/AppData temp.",
    where="Task Scheduler registrations (XML / TaskCache).",
    evidence="Task evidence (actions string).",
    risk="High: common fileless persistence.",
)
def task_from_temp(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for task in snap.tasks:
        actions = task.data.get("actions") or ""
        exe = actions.split(";")[0].strip().strip('"').split(" ")[0] if actions else ""
        if exe and _in_writable_shared(exe):
            out.append(_mk(
                f"Scheduled task staged in temp: {task.data.get('name')}",
                f"Task '{task.data.get('path')}' executes '{actions[:300]}'.",
                exe, [task.id], location=exe, confidence=0.75,
            ))
    return out


@rule(
    "DE-WMI-001", "WMI permanent subscription with script consumer",
    "wmi", 7.0, 0.7,
    what="A __EventFilter is permanently bound to an ActiveScript/CommandLine consumer.",
    where="WMI repository (root\\subscription).",
    evidence="Filter/consumer/binding evidence.",
    risk="High: fileless persistence used by real intrusions.",
)
def wmi_subscription(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    consumers = [w for w in snap.wmi_subscriptions if w.data.get("type") == "consumer"]
    bindings = [w for w in snap.wmi_subscriptions if w.data.get("type") == "binding"]
    for c in consumers:
        ctype = c.data.get("consumer_type") or ""
        if ctype in ("ActiveScriptEventConsumer", "CommandLineEventConsumer"):
            ev_ids = [c.id] + [b.id for b in bindings if c.data.get("name") in str(b.data)]
            out.append(_mk(
                f"WMI script consumer: {c.data.get('name')}",
                f"{ctype} bound permanently in {c.data.get('namespace')}.",
                c.data.get("command") or ctype, ev_ids,
                location=f"{c.data.get('namespace')}\\{c.data.get('name')}", confidence=0.7,
            ))
    return out


@rule(
    "DE-PERS-001", "Run key pointing at writable/shared location",
    "persistence", 7.0, 0.8,
    what="An autorun (Run/RunOnce) value starts a binary from Temp/Public/AppData.",
    where="HKLM/HKCU Run keys.",
    evidence="Registry evidence (hive/key/value/data).",
    risk="High: boots with the user session on every logon.",
)
def run_key_writable_path(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for ev in snap.persistence:
        if ev.data.get("category") != "run_key":
            continue
        data = (ev.data.get("data") or "").strip().strip('"')
        exe = data.split(" ")[0]
        if exe and _in_writable_shared(exe):
            out.append(_mk(
                f"Run-key persistence from staging dir: {ev.data.get('value')}",
                f"{ev.data.get('hive')}\\{ev.data.get('key')} → '{data}'.",
                exe, [ev.id], location=f"{ev.data.get('hive')}\\{ev.data.get('key')}", confidence=0.8,
            ))
    return out


@rule(
    "DE-PERS-002", "IFEO debugger hijack",
    "persistence", 9.0, 0.9,
    what="Image File Execution Options sets a Debugger for an image — execution redirection.",
    where=r"HKLM\...\Image File Execution Options\<image>.",
    evidence="Registry evidence for the IFEO subkey.",
    risk="Very high when the debugger path is not a trusted debugger (especially on the protected game).",
)
def ifeo_debugger(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for ev in snap.persistence:
        if ev.data.get("category") not in ("ifeo", "ifeo_debugger") or ev.data.get("value") != "Debugger":
            continue
        target = ev.data.get("key", "").rsplit("\\", 1)[-1]
        debugger = ev.data.get("data") or ""
        trusted = debugger.lower().startswith(("c:\\windows\\system32", "c:\\windows\\syswow64"))
        if not trusted:
            conf = 0.95 if policy.is_protected_name(target) else 0.8
            out.append(_mk(
                f"IFEO Debugger hijack on {target}",
                f"'{target}' will launch '{debugger}' instead of itself.",
                debugger, [ev.id], location=ev.data.get("key", ""), confidence=conf,
            ))
    return out


@rule(
    "DE-PERS-003", "AppInit_DLLs configured",
    "persistence", 7.0, 0.75,
    what="AppInit_DLLs loads a DLL into every GUI process at startup.",
    where=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows.",
    evidence="Registry evidence.",
    risk="High: global injection primitive (mostly disabled on modern Windows, still a red flag).",
)
def appinit_dlls(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for ev in snap.persistence:
        if ev.data.get("category") == "appinit_dlls" and (ev.data.get("data") or "").strip():
            out.append(_mk(
                f"AppInit_DLLs configured: {ev.data.get('value')}",
                f"Value '{ev.data.get('data')}' injects into every GUI process.",
                ev.data.get("data") or "", [ev.id],
                location=f"{ev.data.get('hive')}\\{ev.data.get('key')}", confidence=0.75,
            ))
    return out


# ==========================================================================
# Network correlation
# ==========================================================================

@rule(
    "DE-NET-001", "Unsigned/staged process with established outbound connection",
    "network", 6.0, 0.7,
    what="A process whose binary is unsigned or staged in a temp dir holds an ESTABLISHED connection.",
    where="TCP connection table joined with process + signature data.",
    evidence="Network evidence + process + signature evidence.",
    risk="Medium-high: C2 for loaders; benign portable tools can false-positive → dampening applied.",
)
def suspicious_network(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for view in snap.processes.values():
        if not view.network:
            continue
        staged = _in_writable_shared(view.path)
        if view.signed is False or staged:
            established = [n for n in view.network if n.data.get("state") == "ESTABLISHED"
                           and not str(n.data.get("remote", "")).startswith(("127.", "0.0.0.0"))]
            if established:
                remotes = ", ".join(n.data.get("remote", "") for n in established[:3])
                out.append(_mk(
                    f"Outbound connection from {'staged' if staged else 'unsigned'} process {view.name}",
                    f"'{view.path}' → {remotes}.",
                    view, view.evidence_ids + [n.id for n in established],
                    location=remotes, confidence=0.7,
                ))
    return out


# ==========================================================================
# Telemetry corroboration (Sysmon / Security / Defender / CodeIntegrity)
# ==========================================================================

@rule(
    "DE-TEL-001", "CreateRemoteThread into the protected process",
    "telemetry", 9.0, 0.85,
    what="Sysmon EID 8: another process created a thread inside the protected game.",
    where="Microsoft-Windows-Sysmon/Operational.",
    evidence="Event evidence (EID 8) with source/target images.",
    risk="Very high: the canonical DLL/shellcode injection signal.",
)
def sysmon_remote_thread(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    protected_paths = {p.path.lower() for p in snap.protected_processes()}
    for ev in snap.events:
        if ev.data.get("event_id") != 8 or "Sysmon" not in ev.source:
            continue
        fields = ev.data.get("fields") or {}
        target = (fields.get("TargetImage") or "").lower()
        if target in protected_paths:
            out.append(_mk(
                f"Remote thread into protected process from {str(fields.get('SourceImage','')).rsplit(chr(92),1)[-1]}",
                f"{fields.get('SourceImage')} → {fields.get('TargetImage')} "
                f"(StartAddress {fields.get('StartAddress')}).",
                fields.get("TargetImage") or "", [ev.id],
                location=str(fields.get("StartAddress")), confidence=0.85,
            ))
    return out


@rule(
    "DE-TEL-002", "High-rights process access to the protected process",
    "telemetry", 7.0, 0.7,
    what="Sysmon EID 10: a process opened the game with VM_WRITE/ALL_ACCESS rights.",
    where="Microsoft-Windows-Sysmon/Operational.",
    evidence="Event evidence (EID 10) GrantedAccess.",
    risk="High: write access to game memory is the cheat primitive.",
)
def sysmon_process_access(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    protected_paths = {p.path.lower() for p in snap.protected_processes()}
    write_bits = (0x1FFFFF, 0x1F0FFF, 0x0020, 0x0800 | 0x0020)
    for ev in snap.events:
        if ev.data.get("event_id") != 10 or "Sysmon" not in ev.source:
            continue
        fields = ev.data.get("fields") or {}
        target = (fields.get("TargetImage") or "").lower()
        if target not in protected_paths:
            continue
        try:
            granted = int(str(fields.get("GrantedAccess", "0")), 16)
        except ValueError:
            granted = 0
        if granted in write_bits or granted & 0x0020:
            out.append(_mk(
                f"Write-capable handle on protected process by {str(fields.get('SourceImage','')).rsplit(chr(92),1)[-1]}",
                f"GrantedAccess={fields.get('GrantedAccess')} from {fields.get('SourceImage')}.",
                fields.get("TargetImage") or "", [ev.id], confidence=0.7,
            ))
    return out


@rule(
    "DE-TEL-003", "Defender detection references an observed binary",
    "telemetry", 8.0, 0.8,
    what="Microsoft Defender flagged a path that also appears in our process/persistence evidence.",
    where="Defender Operational / Get-MpThreatDetection.",
    evidence="Defender detection evidence + matching process/persistence evidence.",
    risk="High: independent security product corroborates our findings.",
)
def defender_corroboration(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    for ev in snap.defender:
        if ev.data.get("component") != "defender_detection":
            continue
        path = ev.data.get("path") or ""
        if not path:
            continue
        view = snap.find_process_by_path(path)
        out.append(_mk(
            f"Defender detection overlaps observed artifact: {ev.data.get('threat')}",
            f"Defender flagged '{path}' (action={ev.data.get('action')}).",
            view or path, [ev.id], location=path, confidence=0.8,
        ))
    return out


# ==========================================================================
# Offline artifact corroboration
# ==========================================================================

@rule(
    "DE-FILE-001", "Prefetch proves execution of a staged binary",
    "file_integrity", 4.0, 0.8,
    what="Prefetch contains an entry for a binary that is also staged in a temp dir — executed, not just dropped.",
    where="C:\\Windows\\Prefetch.",
    evidence="Prefetch artifact evidence + matching process/persistence path.",
    risk="Low alone, but upgrades drop-only findings to 'executed'.",
)
def prefetch_execution(snap: HostSnapshot, policy: Policy) -> List[Indicator]:
    out = []
    prefetched = {
        (a.data.get("executable") or "").lower(): a
        for a in snap.artifacts if a.data.get("artifact") == "prefetch"
    }
    staged_paths = set()
    for view in snap.processes.values():
        if _in_writable_shared(view.path):
            staged_paths.add(view.path)
    for ev in snap.persistence:
        data = (ev.data.get("data") or "").strip().strip('"').split(" ")[0]
        if data and _in_writable_shared(data):
            staged_paths.add(data)
    for path in staged_paths:
        name = path.rsplit("\\", 1)[-1].lower()
        pf = prefetched.get(name)
        if pf:
            out.append(_mk(
                f"Execution proven by Prefetch: {name}",
                f"'{path}' has a Prefetch record (run_count={pf.data.get('run_count')}).",
                path, [pf.id], location=str(pf.data.get("file")), confidence=0.8,
            ))
    return out
