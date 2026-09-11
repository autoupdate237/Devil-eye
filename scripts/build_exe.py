"""Package Devil's Eye as a single Windows EXE (one-click workflow).

Usage (on Windows, inside a venv):
    pip install .[build]
    python scripts/build_exe.py

The EXE double-click experience: environment check → telemetry availability →
protected-app discovery → full inspection → correlation → scoring → report,
then the dashboard opens at http://127.0.0.1:8080.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI_DIR = ROOT / "src" / "devils_eye" / "ui" / "static"
CONFIG_DIR = ROOT / "config"


def main() -> int:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "DevilsEye",
        "--noconfirm",
        "--clean",
        "--onedir",                                # onedir starts faster than onefile
        "--add-data", f"{UI_DIR}{';' if sys.platform == 'win32' else ':'}devils_eye/ui/static",
        "--add-data", f"{CONFIG_DIR}{';' if sys.platform == 'win32' else ':'}config",
        "--collect-submodules", "devils_eye",
        str(ROOT / "src" / "devils_eye" / "__main__.py"),
    ]
    print("running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
