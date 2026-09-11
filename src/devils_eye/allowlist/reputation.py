"""Allowlist + reputation matching.

Four match kinds, strongest first:
  hash        exact SHA-256 of a known-good binary
  publisher   Authenticode publisher from the trusted list
  path_prefix file/dir prefix explicitly approved
  directory   trusted OS/vendor directory

Actions:
  suppress  → indicator kept for audit but contributes zero risk
  dampen    → risk contribution multiplied by ``factor`` (default 0.15)

Every application is recorded so operators can see *why* something was muted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..core.config import Policy, find_bundled
from ..core.models import AllowlistEntry


@dataclass
class AllowMatch:
    entry: AllowlistEntry
    matched_on: str


class ReputationService:
    def __init__(self, policy: Policy, entries: Optional[List[AllowlistEntry]] = None):
        self.policy = policy
        self.entries: List[AllowlistEntry] = entries if entries is not None else self._load_defaults()

    # ------------------------------------------------------------------
    @staticmethod
    def _load_defaults() -> List[AllowlistEntry]:
        entries: List[AllowlistEntry] = []
        path = find_bundled("config", "allowlist.json")
        if path is not None:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                for item in raw.get("entries", []):
                    entries.append(AllowlistEntry(**item))
            except (json.JSONDecodeError, TypeError, KeyError):
                pass
        return entries

    # ------------------------------------------------------------------
    def match(self, *, path: str = "", hash_sha256: str = "", publisher: str = "") -> Optional[AllowMatch]:
        h = (hash_sha256 or "").lower()
        p = (path or "").lower()
        pub = (publisher or "").lower()
        # 1) explicit hash
        for e in self.entries:
            if e.kind == "hash" and h and e.value.lower() == h:
                return AllowMatch(e, "hash")
        if h in self.policy.known_good_hashes:
            return AllowMatch(AllowlistEntry("hash", h, "suppress", 0.0, "policy known-good hash"), "hash")
        # 2) publisher
        for e in self.entries:
            if e.kind == "publisher" and pub and e.value.lower() in pub:
                return AllowMatch(e, "publisher")
        if pub and any(t in pub for t in self.policy.trusted_publishers):
            return AllowMatch(AllowlistEntry("publisher", pub, "dampen", 0.15, "trusted publisher (policy)"), "publisher")
        # 3) explicit path prefix / directory entries
        for e in self.entries:
            if e.kind in ("path_prefix", "directory") and p and p.startswith(e.value.lower()):
                return AllowMatch(e, e.kind)
        # 4) policy trusted directories
        if p and self.policy.in_trusted_directory(p):
            return AllowMatch(AllowlistEntry("directory", p, "dampen", 0.15, "trusted directory (policy)"), "directory")
        return None

    # ------------------------------------------------------------------
    def apply(self, indicators: List) -> Dict[str, str]:
        """Attach suppress/dampen to each indicator. Returns audit map."""
        audit: Dict[str, str] = {}
        for ind in indicators:
            publisher = ind.extras.get("publisher", "") if isinstance(ind.extras, dict) else ""
            m = self.match(path=ind.process_path or ind.location, hash_sha256=ind.hash_sha256, publisher=publisher)
            if m is None:
                continue
            if m.entry.action == "suppress":
                ind.suppressed = True
                ind.suppressed_reason = f"allowlist:{m.matched_on}={m.entry.value} ({m.entry.reason})"
                ind.risk_contribution = 0.0
            else:
                ind.allowlist_dampening = m.entry.factor
            audit[ind.id] = f"{m.entry.action} via {m.matched_on}: {m.entry.reason or m.entry.value}"
        return audit
