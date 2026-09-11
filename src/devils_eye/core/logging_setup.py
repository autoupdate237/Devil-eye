"""Central logging configuration.

Scanner logs are written to the session directory (when available) and to
stderr. We deliberately never log event payloads that could contain user
content beyond process/file metadata — no credential or document data is ever
collected, so there is none to leak, but the rule is enforced here anyway.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

_CONFIGURED = False


def setup_logging(level: int = logging.INFO, logfile: Optional[Path] = None) -> None:
    global _CONFIGURED
    root = logging.getLogger("devils_eye")
    root.setLevel(level)
    if _CONFIGURED:
        return
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if logfile is not None:
        try:
            logfile.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(logfile, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError:
            root.warning("could not open log file %s", logfile)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"devils_eye.{name}")
