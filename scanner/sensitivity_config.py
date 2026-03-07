"""
Plugin Sensitivity Configuration

Per-plugin confidence threshold management with preset scan profiles
(aggressive / balanced / precise) and dynamic threshold adjustment.

Usage::

    from scanner.sensitivity_config import SensitivityConfig, ScanProfile

    cfg = SensitivityConfig()
    cfg.apply_profile(ScanProfile.PRECISE)
    threshold = cfg.get_threshold("xss")   # -> 0.85
    cfg.save("config/sensitivity.json")
"""

import json
import logging
from copy import deepcopy
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

class ScanProfile(str, Enum):
    AGGRESSIVE = "aggressive"
    BALANCED = "balanced"
    PRECISE = "precise"


# ---------------------------------------------------------------------------
# Default thresholds per profile
# ---------------------------------------------------------------------------

_PROFILE_THRESHOLDS: Dict[ScanProfile, Dict[str, float]] = {
    ScanProfile.AGGRESSIVE: {
        "xss": 0.50,
        "sqli": 0.55,
        "ssrf": 0.50,
        "xxe": 0.50,
        "clickjacking": 0.40,
        "csrf": 0.40,
        "cors": 0.45,
        "lfi": 0.50,
        "rfi": 0.50,
        "open_redirect": 0.40,
        "idor": 0.45,
        "ssti": 0.55,
        "command_injection": 0.60,
        "default": 0.40,
    },
    ScanProfile.BALANCED: {
        "xss": 0.70,
        "sqli": 0.80,
        "ssrf": 0.75,
        "xxe": 0.75,
        "clickjacking": 0.60,
        "csrf": 0.65,
        "cors": 0.70,
        "lfi": 0.75,
        "rfi": 0.75,
        "open_redirect": 0.65,
        "idor": 0.70,
        "ssti": 0.80,
        "command_injection": 0.85,
        "default": 0.60,
    },
    ScanProfile.PRECISE: {
        "xss": 0.85,
        "sqli": 0.90,
        "ssrf": 0.88,
        "xxe": 0.88,
        "clickjacking": 0.80,
        "csrf": 0.82,
        "cors": 0.85,
        "lfi": 0.88,
        "rfi": 0.88,
        "open_redirect": 0.82,
        "idor": 0.85,
        "ssti": 0.92,
        "command_injection": 0.95,
        "default": 0.80,
    },
}

# Default enabled plugins per profile
_PROFILE_PLUGINS: Dict[ScanProfile, Optional[List[str]]] = {
    ScanProfile.AGGRESSIVE: None,   # None = all plugins enabled
    ScanProfile.BALANCED: None,
    ScanProfile.PRECISE: [
        "xss",
        "sqli",
        "ssrf",
        "xxe",
        "command_injection",
        "ssti",
        "lfi",
        "rfi",
        "idor",
    ],
}


# ---------------------------------------------------------------------------
# SensitivityConfig
# ---------------------------------------------------------------------------

class SensitivityConfig:
    """
    Manages per-plugin sensitivity thresholds.

    Parameters
    ----------
    config_path:
        Path to a JSON file to load/save configuration.
        If *None* (default) configuration is in-memory only.
    profile:
        Initial profile to apply.  Defaults to ``ScanProfile.BALANCED``.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        profile: ScanProfile = ScanProfile.BALANCED,
    ) -> None:
        self._config_path: Optional[Path] = Path(config_path) if config_path else None
        self._thresholds: Dict[str, float] = {}
        self._enabled_plugins: Optional[Set[str]] = None
        self._fp_counter: Dict[str, int] = {}  # plugin_type -> consecutive FP count
        self._current_profile: ScanProfile = profile
        self._dynamic_adjustment: bool = True

        # Apply the initial profile
        self.apply_profile(profile)

        # Load from file (overrides profile defaults if file exists)
        if self._config_path and self._config_path.exists():
            self.load(str(self._config_path))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply_profile(self, profile: ScanProfile) -> None:
        """Apply a preset scan profile, resetting thresholds and plugin list."""
        self._current_profile = profile
        self._thresholds = deepcopy(_PROFILE_THRESHOLDS[profile])
        plugin_list = _PROFILE_PLUGINS[profile]
        self._enabled_plugins = set(plugin_list) if plugin_list is not None else None
        logger.debug("Applied scan profile: %s", profile.value)

    def get_threshold(self, plugin_type: str) -> float:
        """Return the confidence threshold for *plugin_type*."""
        return self._thresholds.get(plugin_type.lower(), self._thresholds.get("default", 0.6))

    def set_threshold(self, plugin_type: str, threshold: float) -> None:
        """Manually set the threshold for *plugin_type*."""
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"Threshold must be 0–1, got {threshold}")
        self._thresholds[plugin_type.lower()] = threshold

    def is_plugin_enabled(self, plugin_type: str) -> bool:
        """Return whether *plugin_type* is enabled for scanning."""
        if self._enabled_plugins is None:
            return True  # all enabled
        return plugin_type.lower() in self._enabled_plugins

    def enable_plugin(self, plugin_type: str) -> None:
        """Enable a specific plugin."""
        if self._enabled_plugins is None:
            return  # already all-enabled
        self._enabled_plugins.add(plugin_type.lower())

    def disable_plugin(self, plugin_type: str) -> None:
        """Disable a specific plugin."""
        if self._enabled_plugins is None:
            self._enabled_plugins = set(self._thresholds.keys())
        self._enabled_plugins.discard(plugin_type.lower())

    def record_false_positive(self, plugin_type: str) -> None:
        """
        Record a false positive from *plugin_type*.

        If dynamic adjustment is enabled, automatically raises the threshold
        after a series of consecutive false positives.
        """
        ptype = plugin_type.lower()
        self._fp_counter[ptype] = self._fp_counter.get(ptype, 0) + 1
        count = self._fp_counter[ptype]

        if self._dynamic_adjustment and count >= 3:
            current = self.get_threshold(ptype)
            new_threshold = min(0.98, current + 0.05)
            if new_threshold != current:
                logger.info(
                    "Dynamic adjustment: raising %s threshold %.2f -> %.2f (FP count=%d)",
                    ptype,
                    current,
                    new_threshold,
                    count,
                )
                self._thresholds[ptype] = new_threshold
            # Reset counter after adjustment
            self._fp_counter[ptype] = 0

    def reset_fp_counter(self, plugin_type: str) -> None:
        """Reset the false positive counter for *plugin_type*."""
        self._fp_counter.pop(plugin_type.lower(), None)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the configuration to a dictionary."""
        return {
            "profile": self._current_profile.value,
            "thresholds": dict(self._thresholds),
            "enabled_plugins": list(self._enabled_plugins) if self._enabled_plugins is not None else None,
            "dynamic_adjustment": self._dynamic_adjustment,
        }

    def save(self, path: Optional[str] = None) -> None:
        """Save configuration to *path* (or the configured path)."""
        target = Path(path) if path else self._config_path
        if target is None:
            raise ValueError("No config path configured for save()")
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        logger.debug("Sensitivity config saved to %s", target)

    def load(self, path: str) -> None:
        """Load configuration from *path*."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        if "profile" in data:
            try:
                self._current_profile = ScanProfile(data["profile"])
            except ValueError:
                pass

        if "thresholds" in data:
            self._thresholds.update(data["thresholds"])

        if "enabled_plugins" in data:
            ep = data["enabled_plugins"]
            self._enabled_plugins = set(ep) if ep is not None else None

        if "dynamic_adjustment" in data:
            self._dynamic_adjustment = bool(data["dynamic_adjustment"])

        logger.debug("Sensitivity config loaded from %s", p)

    @property
    def current_profile(self) -> ScanProfile:
        return self._current_profile

    @property
    def dynamic_adjustment(self) -> bool:
        return self._dynamic_adjustment

    @dynamic_adjustment.setter
    def dynamic_adjustment(self, value: bool) -> None:
        self._dynamic_adjustment = bool(value)
