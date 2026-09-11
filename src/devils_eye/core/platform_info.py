"""Platform detection and safe subprocess helpers.

Devil's Eye collects real Windows telemetry; on a non-Windows host every
collector reports itself unavailable (graceful degradation) instead of
failing, so the pipeline and its reports still run everywhere.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence


def is_windows() -> bool:
    return os.name == "nt" or platform.system() == "Windows"


def is_linux() -> bool:
    return platform.system() == "Linux"


def python_bits() -> int:
    return 64 if sys.maxsize > 2**32 else 32


def os_description() -> str:
    if is_windows():
        try:
            ver = platform.version()
            return f"Windows {platform.release()} (build {ver})"
        except Exception:  # pragma: no cover
            return "Windows"
    return f"{platform.system()} {platform.release()}"


def is_elevated() -> bool:
    """Best-effort admin check. Absence of elevation is not fatal: every
    collector that needs more rights reports a telemetry limitation instead."""
    try:
        if is_windows():
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


@dataclass
class CmdResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_cmd(
    args: Sequence[str],
    timeout: float = 30.0,
    shell: bool = False,
    powershell: bool = False,
) -> Optional[CmdResult]:
    """Run a command safely. Returns None when the executable is missing or
    the command times out — callers must treat that as 'source unavailable',
    never as a crash."""
    try:
        if powershell:
            exe = shutil.which("pwsh") or shutil.which("powershell")
            if not exe:
                return None
            args = [exe, "-NoProfile", "-NonInteractive", "-Command", " ".join(args)]
            shell = False
        proc = subprocess.run(  # noqa: S603 — args are constructed internally
            list(args) if not shell else " ".join(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            creationflags=0x08000000 if is_windows() else 0,  # CREATE_NO_WINDOW
        )
        return CmdResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        return None


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def username() -> str:
    try:
        import getpass

        return getpass.getuser()
    except Exception:  # pragma: no cover
        return "unknown"


def hostname() -> str:
    try:
        return platform.node() or "unknown"
    except Exception:  # pragma: no cover
        return "unknown"


def windows_version_tokens() -> List[str]:
    """Return (major, minor, build) for Windows, else []."""
    if not is_windows():
        return []
    try:
        return platform.version().split(".")
    except Exception:  # pragma: no cover
        return []
