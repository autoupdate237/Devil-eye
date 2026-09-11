"""Policy + runtime configuration.

The policy is the *per-deployment* configuration: which game/process is
protected, trusted publishers/directories/hashes, detection sensitivity,
exclusion rules. The default policy ships in ``config/default_policy.json``.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .errors import ConfigError

REPO_ROOT = Path(__file__).resolve().parents[3]


def bundle_root() -> Path:
    """Where bundled resources live at runtime.

    * frozen (PyInstaller EXE): the extraction/internal directory that
      contains the ``config/`` folder added via ``--add-data``;
    * normal Python: the repository root.
    """
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", str(Path(sys.executable).parent)))
    return REPO_ROOT


def find_bundled(*relative: str) -> Optional[Path]:
    """Locate a bundled resource file (bundle root first, repo root second)."""
    for root in (bundle_root(), REPO_ROOT):
        cand = root.joinpath(*relative)
        if cand.exists():
            return cand
    return None


def default_workspace() -> Path:
    """Session data root. On Windows a real deployment would use
    %PROGRAMDATA%\\DevilsEye; we keep it relocatable via DEVILSEYE_HOME.
    When frozen and no env var is set, data lives next to the EXE."""
    env = os.environ.get("DEVILSEYE_HOME")
    if env:
        return Path(env).expanduser()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "DevilsEyeData"
    return REPO_ROOT / "data"


DEFAULT_POLICY: Dict[str, Any] = {
    "protected_processes": [
        {"name": "r5apex.exe", "path": ""},
        {"name": "game.exe", "path": ""},
    ],
    "trusted_publishers": [
        "Microsoft Windows",
        "Microsoft Corporation",
        "Microsoft Windows Publisher",
        "NVIDIA Corporation",
        "NVIDIA",
        "AMD",
        "Advanced Micro Devices, Inc.",
        "Intel Corporation",
        "Intel(R) pGFX",
        "Realtek Semiconductor Corp.",
        "Valve Corp.",
        "Epic Games Inc.",
        "Electronic Arts, Inc.",
        "Riot Games, Inc.",
        "Activision Publishing Inc",
        "Blizzard Entertainment, Inc.",
        "Discord Inc.",
        "ESET, spol. s r.o.",
        "Kaspersky",
        "Bitdefender SRL",
        "Elasticsearch, Inc.",
        "CrowdStrike, Inc.",
        "SentinelOne",
        "Carbon Black, Inc.",
    ],
    "trusted_directories": [
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Windows\\WinSxS",
        "C:\\Windows\\SystemResources",
        "C:\\Windows\\servicing",
        "C:\\Windows\\explorer.exe",
        "C:\\Program Files\\WindowsApps",
    ],
    "known_good_hashes": [],
    "exclusions": [],
    "sensitivity": "balanced",          # conservative | balanced | aggressive
    "score_thresholds": {
        "low": 10.0,
        "suspicious": 25.0,
        "high": 50.0,
        "critical": 75.0,
    },
    "category_weights": {
        "process_integrity": 1.0,
        "module_integrity": 1.1,
        "memory_integrity": 1.2,
        "signature": 0.8,
        "ancestry": 0.9,
        "command_line": 0.8,
        "persistence": 1.0,
        "network": 0.9,
        "driver": 1.2,
        "service": 1.0,
        "scheduled_task": 1.0,
        "wmi": 1.0,
        "file_integrity": 0.9,
        "telemetry": 0.7,
    },
    "etw_enabled": False,               # opt-in: creating trace sessions has side effects
    "memory_inspection": "protected",   # none | protected | all
    "max_processes_deep": 40,           # modules/memory deep-scan budget
}


@dataclass
class Policy:
    raw: Dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_POLICY))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Policy":
        data: Dict[str, Any] = json.loads(json.dumps(DEFAULT_POLICY))
        if path is None:
            path = find_bundled("config", "default_policy.json")
        if path is not None:
            if not Path(path).exists():
                raise ConfigError(f"policy file not found: {path}")
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    user = json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                raise ConfigError(f"invalid policy file {path}: {exc}") from exc
            _deep_merge(data, user)
        return cls(raw=data)

    # Convenience accessors -------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    @property
    def protected_names(self) -> List[str]:
        return [p.get("name", "").lower() for p in self.raw.get("protected_processes", [])]

    @property
    def trusted_publishers(self) -> List[str]:
        return [t.lower() for t in self.raw.get("trusted_publishers", [])]

    @property
    def trusted_directories(self) -> List[str]:
        return [t.lower() for t in self.raw.get("trusted_directories", [])]

    @property
    def known_good_hashes(self) -> List[str]:
        return [h.lower() for h in self.raw.get("known_good_hashes", [])]

    @property
    def thresholds(self) -> Dict[str, float]:
        return dict(DEFAULT_POLICY["score_thresholds"], **self.raw.get("score_thresholds", {}))

    @property
    def category_weights(self) -> Dict[str, float]:
        return dict(DEFAULT_POLICY["category_weights"], **self.raw.get("category_weights", {}))

    def is_protected_name(self, name: str) -> bool:
        n = name.lower()
        return any(n == p or n.endswith("\\" + p) for p in self.protected_names)

    def in_trusted_directory(self, path: str) -> bool:
        p = path.lower()
        return any(p.startswith(d) for d in self.trusted_directories if d)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
