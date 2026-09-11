"""Registry persistence collector.

Read-only enumeration of the classic persistence locations from the source
catalog: Run/RunOnce/RunServices, Winlogon (Shell/Userinit/Notify/GPExtensions),
AppInit_DLLs, IFEO (Debugger/GlobalFlag/SilentProcessExit), Services,
StartupApproved, Explorer Run. Values are recorded as evidence; verdicts are
made by rules + scoring, never here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..core.models import CollectorResult, Evidence, TelemetryAvailability
from ..core.platform_info import is_windows
from .base import Collector, PipelineContext

try:  # winreg exists only on Windows
    import winreg  # type: ignore
except ImportError:  # pragma: no cover
    winreg = None


# (hive_name, key, value-filter(None=all), category)
TARGETS: List[Tuple[str, str, Any, str]] = [
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", None, "run_key"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", None, "run_key"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServices", None, "run_key"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", None, "run_key"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", None, "run_key"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", None, "run_key"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", None, "run_key"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "winlogon"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", "winlogon"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Notify", "winlogon"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "AppSetup", "winlogon"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "appinit_dlls"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "Load", "appinit_dlls"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", None, "ifeo"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit", None, "silent_process_exit"),
    ("HKLM", r"System\CurrentControlSet\Control\Session Manager", "BootExecute", "boot_execute"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Common Startup", "startup_folder"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", None, "startup_approved"),
]


class RegistryPersistenceCollector(Collector):
    name = "persistence_registry"
    description = "Registry persistence locations (Run keys, Winlogon, IFEO…)"
    weight = 1.0
    sources = [
        "Run / RunOnce / RunServices",
        "Winlogon Shell/Userinit/Notify",
        "AppInit_DLLs",
        "IFEO Debugger/GlobalFlag",
        "SilentProcessExit",
        "Session Manager BootExecute",
        "StartupApproved",
    ]

    def available(self, ctx: PipelineContext) -> TelemetryAvailability:
        if winreg is None and not ctx.simulated:
            return TelemetryAvailability(self.name, False, "winreg unavailable (non-Windows)", self.weight, self.name)
        return TelemetryAvailability(self.name, True, "", self.weight, self.name)

    def collect(self, ctx: PipelineContext) -> CollectorResult:
        r = self._result()
        if ctx.simulated or winreg is None:
            return r
        hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
        for hive_name, key_path, value_filter, category in TARGETS:
            try:
                handle = winreg.OpenKey(hives[hive_name], key_path, 0, winreg.KEY_READ)
            except OSError:
                continue  # key absent on this Windows version — fine
            try:
                if category == "ifeo" or category == "silent_process_exit":
                    self._enum_subeffects(r, hive_name, key_path, handle, category)
                else:
                    i = 0
                    while True:
                        try:
                            value, data, _vtype = winreg.EnumValue(handle, i)
                        except OSError:
                            break
                        i += 1
                        if value_filter is not None and value != value_filter:
                            continue
                        r.evidences.append(
                            Evidence(
                                kind="registry",
                                source=f"registry:{hive_name}\\{key_path}",
                                collector=self.name,
                                data={
                                    "hive": hive_name, "key": key_path,
                                    "value": value, "data": str(data)[:1024],
                                    "category": category,
                                },
                                process_path=self._extract_path(str(data)),
                            )
                        )
            finally:
                winreg.CloseKey(handle)
        ctx.shared["registry_persistence"] = [e.data for e in r.evidences]
        r.metrics = {"entries": len(r.evidences)}
        return r

    # ------------------------------------------------------------------
    def _enum_subeffects(self, r, hive_name, key_path, handle, category) -> None:
        """IFEO/SilentProcessExit: interesting data lives in per-image subkeys."""
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(handle, i)
            except OSError:
                break
            i += 1
            try:
                sub_handle = winreg.OpenKey(handle, sub, 0, winreg.KEY_READ)
            except OSError:
                continue
            try:
                j = 0
                while True:
                    try:
                        value, data, _vtype = winreg.EnumValue(sub_handle, j)
                    except OSError:
                        break
                    j += 1
                    if value not in ("Debugger", "GlobalFlag", "MonitorProcess", "NotificationPackage"):
                        continue
                    r.evidences.append(
                        Evidence(
                            kind="registry",
                            source=f"registry:{hive_name}\\{key_path}\\{sub}",
                            collector=self.name,
                            data={
                                "hive": hive_name, "key": f"{key_path}\\{sub}",
                                "value": value, "data": str(data)[:1024],
                                "category": category,
                            },
                            process_path=self._extract_path(str(data)),
                        )
                    )
            finally:
                winreg.CloseKey(sub_handle)

    @staticmethod
    def _extract_path(data: str) -> str:
        d = data.strip().strip('"')
        if d and (":" in d or d.startswith("%")):
            return d.split(" ")[0]
        return ""
