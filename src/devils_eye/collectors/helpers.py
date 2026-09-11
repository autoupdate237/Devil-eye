"""Shared collector helpers: PowerShell JSON bridge + file hashing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.platform_info import run_cmd

PS_JSON_PROLOGUE = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='SilentlyContinue';"


def powershell_json(script: str, timeout: float = 45.0) -> Optional[List[Dict[str, Any]]]:
    """Run a PowerShell snippet that emits JSON; return parsed objects.
    Returns None when PowerShell is missing, times out or emits nothing —
    callers translate that into 'source unavailable'."""
    wrapped = f"{PS_JSON_PROLOGUE} {script} | ConvertTo-Json -Depth 6 -Compress"
    res = run_cmd([wrapped], timeout=timeout, powershell=True)
    if res is None or not res.ok or not res.stdout.strip():
        return None
    text = res.stdout.strip()
    # PowerShell emits bare objects for single-element arrays: normalise.
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        try:
            parsed = json.loads("[" + text + "]")
        except json.JSONDecodeError:
            return None
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [p for p in parsed if isinstance(p, dict)]
    return None


def hash_file(path: str, algo: str = "sha256", limit_bytes: int = 0) -> str:
    """Streaming hash. ``limit_bytes>0`` caps work for huge files (we hash the
    first N bytes then note it in the evidence). Errors return ''."""
    try:
        h = hashlib.new(algo)
        read = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
                if limit_bytes and read >= limit_bytes:
                    break
        return h.hexdigest()
    except (OSError, ValueError):
        return ""


def file_metadata(path: str) -> Dict[str, Any]:
    try:
        p = Path(path)
        st = p.stat()
        return {"size": st.st_size, "mtime": st.st_mtime, "ctime": st.st_ctime}
    except OSError:
        return {}
