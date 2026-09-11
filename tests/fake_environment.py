"""TEST FIXTURE ONLY — not part of the product runtime.

A deterministic fake Windows host used by the unit/integration tests so the
pipeline, rules, scoring and verdict engines can be verified on any OS without
Windows telemetry. It contains one benign software population AND one
realistic 'cheat' intrusion chain (unsigned loader -> DLL mapped into the
protected game -> RWX private memory -> remote-thread telemetry -> persistence
+ C2 network), which lets the tests assert that correlation raises confidence
while a lone weak indicator stays LOW RISK.

It emits Evidence records with exactly the same shapes real collectors use, so
everything downstream is exercised identically. This file ships in tests/ only;
the product itself always reads real Windows telemetry.
"""

from __future__ import annotations

import time
from typing import Dict, List

from devils_eye.core.models import CollectorResult, Evidence, TelemetryAvailability
from devils_eye.collectors.base import Collector, PipelineContext

NOW = time.time()


def _ev(kind: str, source: str, data: Dict, **subject) -> Evidence:
    return Evidence(
        kind=kind,
        source=source,
        collector="fake_host",
        ts=NOW,
        data=data,
        pid=subject.get("pid"),
        process_path=subject.get("process_path", ""),
        hash_sha256=subject.get("hash_sha256", ""),
        user=subject.get("user", ""),
    )


class FakeWindowsHostCollector(Collector):
    name = "fake_windows_host"
    description = "Deterministic fake Windows host (test fixture only)"
    requires_windows = False
    weight = 0.5
    sources = [
        "Fixture: process list",
        "Fixture: module inventory",
        "Fixture: memory regions",
        "Fixture: registry persistence",
        "Fixture: services",
        "Fixture: scheduled tasks",
        "Fixture: WMI subscriptions",
        "Fixture: drivers",
        "Fixture: network endpoints",
        "Fixture: Sysmon events",
        "Fixture: Defender status",
    ]

    # ------------------------------------------------------------------
    def available(self, ctx: PipelineContext) -> TelemetryAvailability:
        return TelemetryAvailability(self.name, True, "built-in", self.weight, self.name)

    # ------------------------------------------------------------------
    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        for src in ("processes", "modules", "signatures", "persistence_registry",
                    "services", "scheduled_tasks", "wmi_persistence", "drivers",
                    "network", "defender", "sysmon", "eventlog", "memory"):
            r.availability.append(TelemetryAvailability(src, True, "fixture", 1.0, src))
        ev = r.evidences
        ev.extend(self._system())
        ev.extend(self._processes())
        ev.extend(self._modules())
        ev.extend(self._memory())
        ev.extend(self._threads())
        ev.extend(self._signatures())
        ev.extend(self._persistence())
        ev.extend(self._services())
        ev.extend(self._tasks())
        ev.extend(self._wmi())
        ev.extend(self._drivers())
        ev.extend(self._network())
        ev.extend(self._telemetry_events())
        ev.extend(self._defender())
        r.metrics = {"evidence_count": len(ev)}
        return r

    # ------------------------------------------------------------------
    def _system(self) -> List[Evidence]:
        return [
            _ev(
                "system",
                "Fixture host",
                {
                    "hostname": "SIM-GAMING-01",
                    "os": "Windows 11 Pro (build 22631)",
                    "user": "TEST\\Player",
                    "elevated": True,
                    "boot_time": NOW - 6 * 3600,
                },
            )
        ]

    # ------------------------------------------------------------------
    def _processes(self) -> List[Evidence]:
        procs = [
            # pid, ppid, name, path, cmdline, user, integrity, sha256, signed, publisher, created
            (4, 0, "System", "System", "", "SYSTEM", "System", "0" * 64, True, "Microsoft Windows", NOW - 21600),
            (620, 4, "smss.exe", r"C:\Windows\System32\smss.exe", r"C:\Windows\System32\smss.exe", "SYSTEM", "System", "aa" * 32, True, "Microsoft Windows", NOW - 21590),
            (780, 620, "winlogon.exe", r"C:\Windows\System32\winlogon.exe", "winlogon.exe", "SYSTEM", "High", "bb" * 32, True, "Microsoft Windows", NOW - 21500),
            (860, 780, "services.exe", r"C:\Windows\System32\services.exe", r"C:\Windows\system32\services.exe", "SYSTEM", "High", "cc" * 32, True, "Microsoft Windows", NOW - 21490),
            (1100, 860, "svchost.exe", r"C:\Windows\System32\svchost.exe", r'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule', "SYSTEM", "System", "dd" * 32, True, "Microsoft Windows", NOW - 21480),
            (3020, 860, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24070.5-0\MsMpEng.exe", "MsMpEng.exe", "SYSTEM", "System", "ee" * 32, True, "Microsoft Corporation", NOW - 21400),
            (5400, 780, "explorer.exe", r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", "TEST\\Player", "Medium", "11" * 32, True, "Microsoft Windows", NOW - 21000),
            (7210, 5400, "Discord.exe", r"C:\Users\Player\AppData\Local\Discord\app-1.0.9182\Discord.exe", r'"C:\Users\Player\AppData\Local\Discord\app-1.0.9182\Discord.exe"', "TEST\\Player", "Medium", "22" * 32, True, "Discord Inc.", NOW - 7200),
            (8830, 5400, "r5apex.exe", r"C:\Games\Apex Legends\r5apex.exe", r'"C:\Games\Apex Legends\r5apex.exe" +launch_via_ea', "TEST\\Player", "Medium", "33" * 32, True, "Electronic Arts, Inc.", NOW - 3600),
            # --- intrusion chain ---
            (9340, 5400, "cmd.exe", r"C:\Windows\System32\cmd.exe", r'C:\Windows\system32\cmd.exe /c start "" "C:\Users\Public\Temp\updhelper.exe"', "TEST\\Player", "Medium", "44" * 32, True, "Microsoft Windows", NOW - 1800),
            (9412, 9340, "updhelper.exe", r"C:\Users\Public\Temp\updhelper.exe", r'"C:\Users\Public\Temp\updhelper.exe" -silent --inject r5apex.exe', "TEST\\Player", "Medium", "55" * 32, False, "", NOW - 1750),
            (9577, 9412, "rundll32.exe", r"C:\Windows\System32\rundll32.exe", r'C:\Windows\System32\rundll32.exe "C:\Users\Public\Temp\aimcore.dll",#1', "TEST\\Player", "Medium", "56" * 32, True, "Microsoft Windows", NOW - 1700),
        ]
        out = []
        for (pid, ppid, name, path, cmdline, user, il, sha, signed, pub, created) in procs:
            parent_path = next((p[3] for p in procs if p[0] == ppid), "")
            out.append(
                _ev(
                    "process",
                    "Fixture: process list",
                    {
                        "pid": pid, "ppid": ppid, "name": name, "path": path,
                        "cmdline": cmdline, "user": user, "integrity_level": il,
                        "session": 1, "created": created, "exited": None,
                        "parent_path": parent_path,
                        "sha256": sha, "signed": signed, "publisher": pub,
                        "signature_status": "Valid" if signed else "NotSigned",
                    },
                    pid=pid, process_path=path, hash_sha256=sha, user=user,
                )
            )
        return out

    # ------------------------------------------------------------------
    def _modules(self) -> List[Evidence]:
        game = r"C:\Games\Apex Legends\r5apex.exe"
        mods = [
            # (proc_pid, proc_path, module_path, name, signed, publisher, sha256)
            (8830, game, r"C:\Windows\System32\ntdll.dll", "ntdll.dll", True, "Microsoft Windows", "a1" * 32),
            (8830, game, r"C:\Windows\System32\kernel32.dll", "kernel32.dll", True, "Microsoft Windows", "a2" * 32),
            (8830, game, r"C:\Games\Apex Legends\r5apex.exe", "r5apex.exe", True, "Electronic Arts, Inc.", "33" * 32),
            (8830, game, r"C:\Games\Apex Legends\EasyAntiCheat_launcher.exe".replace("EasyAntiCheat_launcher", "client"), "client.dll", True, "Electronic Arts, Inc.", "a3" * 32),
            # suspicious: unsigned DLL mapped into the protected game
            (8830, game, r"C:\Users\Public\Temp\aimcore.dll", "aimcore.dll", False, "", "5f" * 32),
            # masquerade: ntdll.dll name but loaded from a temp dir into loader
            (9412, r"C:\Users\Public\Temp\updhelper.exe", r"C:\Users\Public\Temp\ntdll.dll", "ntdll.dll", False, "", "5e" * 32),
            (9412, r"C:\Users\Public\Temp\updhelper.exe", r"C:\Windows\System32\kernel32.dll", "kernel32.dll", True, "Microsoft Windows", "a2" * 32),
            (7210, r"C:\Users\Player\AppData\Local\Discord\app-1.0.9182\Discord.exe", r"C:\Windows\System32\ntdll.dll", "ntdll.dll", True, "Microsoft Windows", "a1" * 32),
        ]
        out = []
        for pid, ppath, mpath, mname, signed, pub, sha in mods:
            out.append(
                _ev(
                    "module",
                    "Fixture: module inventory",
                    {
                        "pid": pid, "process_path": ppath, "module_path": mpath,
                        "name": mname, "base": "0x7FF%08X" % (abs(hash(mpath)) % 10**8),
                        "size": 120_000 if signed else 88_432,
                        "sha256": sha, "signed": signed, "publisher": pub,
                        "signature_status": "Valid" if signed else "NotSigned",
                    },
                    pid=pid, process_path=ppath, hash_sha256=sha,
                )
            )
        return out

    # ------------------------------------------------------------------
    def _memory(self) -> List[Evidence]:
        game = r"C:\Games\Apex Legends\r5apex.exe"
        regions = [
            (8830, game, "0x7FF900000000", 4096, "MEM_IMAGE", "PAGE_EXECUTE_READ", "image-backed", False),
            (8830, game, "0x000001C2A0000000", 262144, "MEM_PRIVATE", "PAGE_READWRITE", "private heap", False),
            (8830, game, "0x000001C2B4000000", 65536, "MEM_PRIVATE", "PAGE_EXECUTE_READWRITE", "RWX private region", True),
            (8830, game, "0x000001C2B8000000", 32768, "MEM_PRIVATE", "PAGE_EXECUTE_READ", "executable private (shellcode-like)", True),
        ]
        out = []
        for pid, ppath, base, size, state, prot, note, sus in regions:
            out.append(
                _ev(
                    "memory",
                    "Fixture: memory regions",
                    {"pid": pid, "process_path": ppath, "base": base, "size": size,
                     "state": state, "protect": prot, "note": note, "suspicious": sus},
                    pid=pid, process_path=ppath,
                )
            )
        return out

    def _threads(self) -> List[Evidence]:
        return [
            _ev(
                "thread", "Fixture: thread metadata",
                {"pid": 8830, "process_path": r"C:\Games\Apex Legends\r5apex.exe",
                 "tid": 14200, "start_address": "0x000001C2B4001234",
                 "backed_by_image": False, "backing_module": "",
                 "note": "thread start address inside private RWX memory"},
                pid=8830, process_path=r"C:\Games\Apex Legends\r5apex.exe",
            ),
            _ev(
                "thread", "Fixture: thread metadata",
                {"pid": 8830, "process_path": r"C:\Games\Apex Legends\r5apex.exe",
                 "tid": 9000, "start_address": "0x7FF900123456",
                 "backed_by_image": True, "backing_module": r"C:\Windows\System32\ntdll.dll",
                 "note": ""},
                pid=8830, process_path=r"C:\Games\Apex Legends\r5apex.exe",
            ),
        ]

    # ------------------------------------------------------------------
    def _signatures(self) -> List[Evidence]:
        entries = [
            (r"C:\Games\Apex Legends\r5apex.exe", "Valid", "Electronic Arts, Inc.", True, "33" * 32),
            (r"C:\Users\Public\Temp\updhelper.exe", "NotSigned", "", False, "55" * 32),
            (r"C:\Users\Public\Temp\aimcore.dll", "NotSigned", "", False, "5f" * 32),
            (r"C:\Users\Public\Temp\ntdll.dll", "NotSigned", "", False, "5e" * 32),
            (r"C:\Windows\System32\ntdll.dll", "Valid", "Microsoft Windows", True, "a1" * 32),
            (r"C:\Windows\System32\drivers\cheatdrv.sys", "HashMismatch", "ExampleSigner OOU", False, "9d" * 32),
        ]
        out = []
        for path, status, publisher, chain_ok, sha in entries:
            out.append(
                _ev(
                    "signature", "Fixture: Authenticode",
                    {"path": path, "status": status, "publisher": publisher,
                     "timestamp": "2025-04-01T00:00:00Z" if chain_ok else "",
                     "chain_valid": chain_ok, "sha256": sha},
                    process_path=path, hash_sha256=sha,
                )
            )
        return out

    # ------------------------------------------------------------------
    def _persistence(self) -> List[Evidence]:
        return [
            _ev("registry", "Fixture: registry persistence",
                {"hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
                 "value": "UpdateHelper", "data": r"C:\Users\Public\Temp\updhelper.exe -silent",
                 "category": "run_key"},
                process_path=r"C:\Users\Public\Temp\updhelper.exe"),
            _ev("registry", "Fixture: registry persistence",
                {"hive": "HKLM", "key": r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\r5apex.exe",
                 "value": "Debugger", "data": r"C:\Users\Public\Temp\hookdbg.exe",
                 "category": "ifeo_debugger"},
                process_path=r"C:\Users\Public\Temp\hookdbg.exe"),
            _ev("registry", "Fixture: registry persistence",
                {"hive": "HKLM", "key": r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                 "value": "AppInit_DLLs", "data": r"C:\Users\Public\Temp\aimcore.dll",
                 "category": "appinit_dlls"}),
            # benign persistence
            _ev("registry", "Fixture: registry persistence",
                {"hive": "HKLM", "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
                 "value": "SecurityHealth", "data": r"%ProgramFiles%\Windows Defender\MSASCuiL.exe",
                 "category": "run_key"},
                process_path=r"C:\Program Files\Windows Defender\MSASCuiL.exe"),
        ]

    def _services(self) -> List[Evidence]:
        return [
            _ev("service", "Fixture: services",
                {"name": "WinDefend", "display": "Microsoft Defender Antivirus Service",
                 "image_path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24070.5-0\MsMpEng.exe",
                 "start": "AUTO_START", "status": "RUNNING", "user": "LocalSystem",
                 "signed": True, "publisher": "Microsoft Corporation", "sha256": "ee" * 32}),
            _ev("service", "Fixture: services",
                {"name": "SvcHelper", "display": "Windows Update Helper",
                 "image_path": r"C:\Users\Public\Temp\svchelp.exe",
                 "start": "AUTO_START", "status": "RUNNING", "user": "LocalSystem",
                 "signed": False, "publisher": "", "sha256": "77" * 32}),
        ]

    def _tasks(self) -> List[Evidence]:
        return [
            _ev("scheduled_task", "Fixture: scheduled tasks",
                {"name": "WinSvcHost", "path": r"\Microsoft\Windows\Maintenance\WinSvcHost",
                 "actions": r"C:\Users\Player\AppData\Local\Temp\svc.exe /run",
                 "triggers": "AtLogOn", "author": "TEST\\Player", "enabled": True, "state": "Ready"}),
            _ev("scheduled_task", "Fixture: scheduled tasks",
                {"name": "OneDrive Reporting Task", "path": r"\OneDrive Reporting Task",
                 "actions": r"C:\Users\Player\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe /report",
                 "triggers": "Daily", "author": "Microsoft Corporation", "enabled": True, "state": "Ready"}),
        ]

    def _wmi(self) -> List[Evidence]:
        return [
            _ev("wmi", "Fixture: WMI subscriptions",
                {"type": "filter", "name": "SysPerfFilter", "namespace": r"root\cimv2",
                 "query": 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_Processor"'}),
            _ev("wmi", "Fixture: WMI subscriptions",
                {"type": "consumer", "name": "SysPerfConsumer", "namespace": r"root\cimv2",
                 "consumer_type": "ActiveScriptEventConsumer",
                 "command": 'VBScript: Set o=GetObject("winmgmts:root\\cimv2").ExecQuery("select * from win32_process")'}),
            _ev("wmi", "Fixture: WMI subscriptions",
                {"type": "binding", "name": "SysPerfBinding", "namespace": r"root\cimv2",
                 "filter": "SysPerfFilter", "consumer": "SysPerfConsumer"}),
        ]

    def _drivers(self) -> List[Evidence]:
        return [
            _ev("driver", "Fixture: drivers",
                {"name": "Wdf01000", "image_path": r"C:\Windows\System32\drivers\Wdf01000.sys",
                 "state": "RUNNING", "start": "DEMAND_START", "signed": True,
                 "publisher": "Microsoft Windows", "sha256": "88" * 32}),
            _ev("driver", "Fixture: drivers",
                {"name": "nvlddmkm", "image_path": r"C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf\nvlddmkm.sys",
                 "state": "RUNNING", "start": "AUTO_START", "signed": True,
                 "publisher": "NVIDIA Corporation", "sha256": "89" * 32}),
            _ev("driver", "Fixture: drivers",
                {"name": "cheatdrv", "image_path": r"C:\Windows\System32\drivers\cheatdrv.sys",
                 "state": "RUNNING", "start": "AUTO_START", "signed": True,
                 "signature_status": "HashMismatch", "publisher": "ExampleSigner OOU", "sha256": "9d" * 32}),
        ]

    def _network(self) -> List[Evidence]:
        return [
            _ev("network", "Fixture: network endpoints",
                {"pid": 9412, "process_path": r"C:\Users\Public\Temp\updhelper.exe",
                 "local": "192.168.1.24:51244", "remote": "185.220.101.45:443",
                 "state": "ESTABLISHED", "protocol": "TCP"},
                pid=9412, process_path=r"C:\Users\Public\Temp\updhelper.exe", hash_sha256="55" * 32),
            _ev("network", "Fixture: network endpoints",
                {"pid": 8830, "process_path": r"C:\Games\Apex Legends\r5apex.exe",
                 "local": "192.168.1.24:51100", "remote": "23.51.165.27:443",
                 "state": "ESTABLISHED", "protocol": "TCP"},
                pid=8830, process_path=r"C:\Games\Apex Legends\r5apex.exe", hash_sha256="33" * 32),
            _ev("network", "Fixture: network endpoints",
                {"pid": 7210, "process_path": r"C:\Users\Player\AppData\Local\Discord\app-1.0.9182\Discord.exe",
                 "local": "192.168.1.24:51300", "remote": "162.159.128.233:443",
                 "state": "ESTABLISHED", "protocol": "TCP"},
                pid=7210, process_path=r"C:\Users\Player\AppData\Local\Discord\app-1.0.9182\Discord.exe", hash_sha256="22" * 32),
        ]

    # ------------------------------------------------------------------
    def _telemetry_events(self) -> List[Evidence]:
        events = [
            ("Microsoft-Windows-Sysmon/Operational", 1, "Process created",
             {"Image": r"C:\Users\Public\Temp\updhelper.exe", "ParentImage": r"C:\Windows\System32\cmd.exe",
              "CommandLine": r'"C:\Users\Public\Temp\updhelper.exe" -silent --inject r5apex.exe',
              "User": "TEST\\Player", "ProcessId": 9412}),
            ("Microsoft-Windows-Sysmon/Operational", 8, "CreateRemoteThread detected",
             {"SourceImage": r"C:\Users\Public\Temp\updhelper.exe",
              "TargetImage": r"C:\Games\Apex Legends\r5apex.exe",
              "StartAddress": "0x000001C2B4001234", "SourceProcessId": 9412, "TargetProcessId": 8830}),
            ("Microsoft-Windows-Sysmon/Operational", 10, "Process accessed",
             {"SourceImage": r"C:\Users\Public\Temp\updhelper.exe",
              "TargetImage": r"C:\Games\Apex Legends\r5apex.exe",
              "GrantedAccess": "0x1FFFFF", "CallTrace": "unknown|unknown"}),
            ("Microsoft-Windows-Sysmon/Operational", 7, "Image loaded",
             {"Image": r"C:\Games\Apex Legends\r5apex.exe",
              "ImageLoaded": r"C:\Users\Public\Temp\aimcore.dll", "Signed": "false"}),
            ("Microsoft-Windows-Sysmon/Operational", 22, "DNS query",
             {"Image": r"C:\Users\Public\Temp\updhelper.exe", "QueryName": "cdn-update-check.top",
              "QueryStatus": "0", "QueryResults": "185.220.101.45"}),
            ("Security", 4688, "A new process has been created",
             {"NewProcessName": r"C:\Users\Public\Temp\updhelper.exe",
              "CreatorProcessName": r"C:\Windows\System32\cmd.exe",
              "CommandLine": r'"C:\Users\Public\Temp\updhelper.exe" -silent --inject r5apex.exe'}),
            ("Microsoft-Windows-CodeIntegrity/Operational", 3033, "Driver failed integrity check",
             {"FilePath": r"\Device\HarddiskVolume2\Windows\System32\drivers\cheatdrv.sys"}),
        ]
        return [
            _ev("event", channel,
                {"channel": channel, "event_id": eid, "task": task, "fields": fields},
                process_path=str(fields.get("Image") or fields.get("SourceImage") or ""))
            for channel, eid, task, fields in events
        ]

    def _defender(self) -> List[Evidence]:
        return [
            _ev("telemetry", "Fixture: Microsoft Defender Operational",
                {"component": "defender_status",
                 "real_time_protection": True, "antivirus_enabled": True,
                 "signature_age_hours": 6, "behavior_monitor": True}),
            _ev("telemetry", "Fixture: Microsoft Defender Operational",
                {"component": "defender_detection",
                 "threat": "HackTool:Win32/AutoKMS", "path": r"C:\Users\Public\Temp\svchelp.exe",
                 "action": "Quarantine failed", "initial_detection_time": NOW - 900}),
        ]
