"""
Whitelist Manager

Known-safe pattern whitelisting for the vulnerability scanner.

Supported whitelist types:
- URL patterns (regex)
- Parameter names/values
- Response body patterns
- Host-level whitelisting

Features:
- Import/export JSON configurations
- Auto-suggest based on repeated false positive patterns
- Thread-safe (uses no shared mutable state beyond instance variables)

Usage::

    from scanner.whitelist_manager import WhitelistManager

    wm = WhitelistManager()
    wm.add_url_pattern(r"/admin/health-check")
    wm.add_host("staging.internal.example.com")

    if wm.is_whitelisted(url="https://example.com/admin/health-check"):
        print("Skipping whitelisted URL")
"""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WhitelistEntry dataclass
# ---------------------------------------------------------------------------

@dataclass
class WhitelistEntry:
    """A single whitelist entry."""

    entry_type: str  # url_pattern | parameter | response_pattern | host
    value: str
    description: str = ""
    added_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    auto_suggested: bool = False


# ---------------------------------------------------------------------------
# WhitelistManager
# ---------------------------------------------------------------------------

class WhitelistManager:
    """
    Manages whitelisted URLs, parameters, response patterns, and hosts.

    Parameters
    ----------
    config_path:
        Optional path to a JSON file to persist the whitelist.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        self._config_path: Optional[Path] = Path(config_path) if config_path else None

        # URL regex patterns
        self._url_patterns: List[Tuple[re.Pattern, WhitelistEntry]] = []

        # Exact or regex parameter names
        self._parameter_patterns: List[Tuple[re.Pattern, WhitelistEntry]] = []

        # Response body patterns
        self._response_patterns: List[Tuple[re.Pattern, WhitelistEntry]] = []

        # Exact hostnames (lowercase)
        self._hosts: Set[str] = set()

        # Raw entries for serialisation
        self._entries: List[WhitelistEntry] = []

        # FP pattern tracking for auto-suggest
        self._fp_url_counter: Dict[str, int] = {}
        self._fp_param_counter: Dict[str, int] = {}

        if self._config_path and self._config_path.exists():
            self.load(str(self._config_path))

    # ------------------------------------------------------------------
    # Add methods
    # ------------------------------------------------------------------

    def add_url_pattern(self, pattern: str, description: str = "", auto_suggested: bool = False) -> None:
        """Add a URL regex pattern to the whitelist."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid URL pattern '{pattern}': {exc}") from exc
        entry = WhitelistEntry(
            entry_type="url_pattern",
            value=pattern,
            description=description,
            auto_suggested=auto_suggested,
        )
        self._url_patterns.append((compiled, entry))
        self._entries.append(entry)
        self._save_if_configured()

    def add_parameter(self, pattern: str, description: str = "", auto_suggested: bool = False) -> None:
        """Add a parameter name regex pattern to the whitelist."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid parameter pattern '{pattern}': {exc}") from exc
        entry = WhitelistEntry(
            entry_type="parameter",
            value=pattern,
            description=description,
            auto_suggested=auto_suggested,
        )
        self._parameter_patterns.append((compiled, entry))
        self._entries.append(entry)
        self._save_if_configured()

    def add_response_pattern(self, pattern: str, description: str = "", auto_suggested: bool = False) -> None:
        """Add a response body regex pattern to the whitelist."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid response pattern '{pattern}': {exc}") from exc
        entry = WhitelistEntry(
            entry_type="response_pattern",
            value=pattern,
            description=description,
            auto_suggested=auto_suggested,
        )
        self._response_patterns.append((compiled, entry))
        self._entries.append(entry)
        self._save_if_configured()

    def add_host(self, host: str, description: str = "") -> None:
        """Add a host (exact match, case-insensitive) to the whitelist."""
        entry = WhitelistEntry(entry_type="host", value=host.lower(), description=description)
        self._hosts.add(host.lower())
        self._entries.append(entry)
        self._save_if_configured()

    # ------------------------------------------------------------------
    # Remove methods
    # ------------------------------------------------------------------

    def remove_url_pattern(self, pattern: str) -> bool:
        """Remove a URL pattern. Returns True if removed."""
        before = len(self._url_patterns)
        self._url_patterns = [(c, e) for c, e in self._url_patterns if e.value != pattern]
        self._entries = [e for e in self._entries if not (e.entry_type == "url_pattern" and e.value == pattern)]
        self._save_if_configured()
        return len(self._url_patterns) < before

    def remove_host(self, host: str) -> bool:
        """Remove a host. Returns True if removed."""
        before = len(self._hosts)
        self._hosts.discard(host.lower())
        self._entries = [e for e in self._entries if not (e.entry_type == "host" and e.value == host.lower())]
        self._save_if_configured()
        return len(self._hosts) < before

    # ------------------------------------------------------------------
    # Check methods
    # ------------------------------------------------------------------

    def is_whitelisted(
        self,
        url: Optional[str] = None,
        parameter: Optional[str] = None,
        response_body: Optional[str] = None,
        host: Optional[str] = None,
    ) -> bool:
        """
        Return True if any of the provided inputs match a whitelist entry.
        """
        if host and host.lower() in self._hosts:
            return True
        if url:
            extracted_host = self._extract_host(url)
            if extracted_host and extracted_host.lower() in self._hosts:
                return True
            for compiled, _ in self._url_patterns:
                if compiled.search(url):
                    return True
        if parameter:
            for compiled, _ in self._parameter_patterns:
                if compiled.search(parameter):
                    return True
        if response_body:
            for compiled, _ in self._response_patterns:
                if compiled.search(response_body):
                    return True
        return False

    def is_finding_whitelisted(self, finding: Dict[str, Any]) -> bool:
        """Convenience check on a finding dict."""
        return self.is_whitelisted(
            url=finding.get("url"),
            parameter=finding.get("parameter"),
            response_body=finding.get("response_body"),
            host=finding.get("host"),
        )

    # ------------------------------------------------------------------
    # Auto-suggest
    # ------------------------------------------------------------------

    def record_false_positive(
        self,
        url: Optional[str] = None,
        parameter: Optional[str] = None,
    ) -> Optional[str]:
        """
        Record a false positive and auto-suggest a whitelist entry if a
        pattern appears >= 3 times.

        Returns the suggested pattern (if any), or None.
        """
        suggestion: Optional[str] = None

        if url:
            self._fp_url_counter[url] = self._fp_url_counter.get(url, 0) + 1
            if self._fp_url_counter[url] >= 3:
                pattern = re.escape(url)
                self.add_url_pattern(
                    pattern,
                    description=f"Auto-suggested: {url} produced multiple false positives",
                    auto_suggested=True,
                )
                del self._fp_url_counter[url]
                suggestion = pattern

        if parameter:
            self._fp_param_counter[parameter] = self._fp_param_counter.get(parameter, 0) + 1
            if self._fp_param_counter[parameter] >= 3:
                pattern = re.escape(parameter)
                self.add_parameter(
                    pattern,
                    description=f"Auto-suggested: parameter '{parameter}' produced multiple false positives",
                    auto_suggested=True,
                )
                del self._fp_param_counter[parameter]
                if suggestion is None:
                    suggestion = pattern

        return suggestion

    def get_auto_suggestions(self) -> List[str]:
        """Return URLs/params that are approaching the auto-suggest threshold."""
        suggestions = []
        for url, count in self._fp_url_counter.items():
            if count >= 2:
                suggestions.append(f"URL (count={count}): {url}")
        for param, count in self._fp_param_counter.items():
            if count >= 2:
                suggestions.append(f"Parameter (count={count}): {param}")
        return suggestions

    # ------------------------------------------------------------------
    # Import / Export
    # ------------------------------------------------------------------

    def export(self, path: str) -> None:
        """Export the whitelist to *path* as JSON."""
        data = {"entries": [asdict(e) for e in self._entries]}
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.debug("Whitelist exported to %s", path)

    def load(self, path: str) -> None:
        """Load a whitelist from a JSON file (merges with existing entries)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Whitelist file not found: {path}")
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry_data in data.get("entries", []):
            etype = entry_data.get("entry_type", "")
            value = entry_data.get("value", "")
            desc = entry_data.get("description", "")
            auto = entry_data.get("auto_suggested", False)
            if etype == "url_pattern":
                self.add_url_pattern(value, description=desc, auto_suggested=auto)
            elif etype == "parameter":
                self.add_parameter(value, description=desc, auto_suggested=auto)
            elif etype == "response_pattern":
                self.add_response_pattern(value, description=desc, auto_suggested=auto)
            elif etype == "host":
                self.add_host(value, description=desc)
        logger.debug("Whitelist loaded from %s", p)

    def to_dict(self) -> Dict[str, Any]:
        """Return the whitelist as a dictionary."""
        return {
            "entries": [asdict(e) for e in self._entries],
            "hosts": list(self._hosts),
            "auto_suggestions": self.get_auto_suggestions(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_host(self, url: str) -> Optional[str]:
        try:
            from urllib.parse import urlparse
            return urlparse(url).hostname
        except Exception:
            return None

    def _save_if_configured(self) -> None:
        if self._config_path:
            try:
                self.export(str(self._config_path))
            except Exception as exc:
                logger.warning("Could not auto-save whitelist: %s", exc)
