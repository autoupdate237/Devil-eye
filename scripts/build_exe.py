"""Build Devil's Eye as a Windows executable.

Run this ON WINDOWS (PyInstaller cannot cross-compile):

    pip install pyinstaller
    python scripts/build_exe.py             # onedir  (dist/DevilsEye/)
    python scripts/build_exe.py --onefile   # single EXE (dist/DevilsEye.exe)

or simply double-click ``scripts/build_exe.bat``.

On GitHub every push also triggers ``.github/workflows/build-windows-exe.yml``
which builds both variants on a real ``windows-latest`` runner and uploads
them as artifacts — so an EXE is produced even without a local Windows box.

Double-clicking the resulting EXE runs the one-click workflow:
environment check → telemetry availability → full inspection → correlation →
risk scoring → report, then opens the dashboard in the default browser.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
# NOTE: the entry point is a thin wrapper with absolute imports. Passing
# src/devils_eye/__main__.py directly breaks because that module uses
# package-relative imports.
ENTRY = ROOT / "packaging" / "entrypoint.py"
UI_PKG_PATH = "devils_eye/ui/static"           # destination inside the bundle
ICON = ROOT / "packaging" / "devils_eye.ico"
VERSION_FILE = ROOT / "packaging" / "version_info.txt"
SEP = ";" if sys.platform == "win32" else ":"


def build(onefile: bool = False, clean: bool = True) -> int:
    if shutil.which("pyinstaller") is None and sys.platform == "win32":
        print("PyInstaller not found — installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "DevilsEye",
        "--noconfirm",
        "--console",                          # show scan progress in the console
        "--paths", str(SRC),
        "--collect-submodules", "devils_eye",
        "--add-data", f"{SRC / 'devils_eye' / 'ui' / 'static'}{SEP}{UI_PKG_PATH}",
        "--add-data", f"{ROOT / 'config'}{SEP}config",
        "--hidden-import", "devils_eye.detection.rules",
    ]
    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")
    if clean:
        cmd.append("--clean")
    if ICON.exists():
        cmd += ["--icon", str(ICON)]
    if VERSION_FILE.exists() and sys.platform == "win32":
        cmd += ["--version-file", str(VERSION_FILE)]
    cmd.append(str(ENTRY))

    print("running:", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    rc = subprocess.call(cmd, cwd=str(ROOT))
    if rc == 0:
        out = ROOT / "dist" / ("DevilsEye.exe" if onefile else "DevilsEye")
        print(f"\n✔ build complete: {out}")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Devil's Eye Windows EXE")
    ap.add_argument("--onefile", action="store_true", help="single DevilsEye.exe")
    ap.add_argument("--no-clean", action="store_true")
    args = ap.parse_args()
    return build(onefile=args.onefile, clean=not args.no_clean)


if __name__ == "__main__":
    raise SystemExit(main())
