"""
Tracker Configuration

Dataclass and loader for issue tracker integration settings.
Values can be supplied programmatically or loaded from environment variables
(which may themselves be populated by a ``.env`` file via python-dotenv or
similar tooling).
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TrackerConfig:
    """
    Centralised configuration for issue tracker integration.

    All string fields default to ``""`` so callers can check truthiness
    instead of ``None``-checking.
    """

    # ------------------------------------------------------------------ #
    # Which tracker to use
    # ------------------------------------------------------------------ #
    tracker_type: str = "none"  # "none" | "jira" | "bugzilla"

    # ------------------------------------------------------------------ #
    # Jira settings
    # ------------------------------------------------------------------ #
    jira_url: str = ""
    jira_project_key: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_issue_type: str = "Bug"

    # ------------------------------------------------------------------ #
    # Bugzilla settings
    # ------------------------------------------------------------------ #
    bugzilla_url: str = ""
    bugzilla_api_key: str = ""
    bugzilla_product: str = ""
    bugzilla_component: str = ""
    bugzilla_version: str = "unspecified"

    # ------------------------------------------------------------------ #
    # Behaviour flags
    # ------------------------------------------------------------------ #
    auto_create_on_confirmed: bool = True
    auto_create_on_false_positive: bool = True
    sync_interval_minutes: int = 30

    # Minimum severity level to auto-create tickets.
    # Accepted values: "critical", "high", "medium", "low", "info"
    severity_threshold: str = "medium"

    # ------------------------------------------------------------------ #
    # Severity → tracker priority mapping
    # ------------------------------------------------------------------ #
    priority_mapping: dict = field(default_factory=lambda: {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    })

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "TrackerConfig":
        """
        Build a ``TrackerConfig`` from environment variables.

        Variable names follow the pattern documented in ``.env.example``.
        """
        def _bool(val: Optional[str], default: bool) -> bool:
            if val is None:
                return default
            return val.strip().lower() in ("1", "true", "yes")

        def _int(val: Optional[str], default: int) -> int:
            try:
                return int(val)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return default

        return cls(
            tracker_type=os.getenv("TRACKER_TYPE", "none").lower(),
            jira_url=os.getenv("JIRA_URL", ""),
            jira_project_key=os.getenv("JIRA_PROJECT_KEY", ""),
            jira_email=os.getenv("JIRA_EMAIL", ""),
            jira_api_token=os.getenv("JIRA_API_TOKEN", ""),
            jira_issue_type=os.getenv("JIRA_ISSUE_TYPE", "Bug"),
            bugzilla_url=os.getenv("BUGZILLA_URL", ""),
            bugzilla_api_key=os.getenv("BUGZILLA_API_KEY", ""),
            bugzilla_product=os.getenv("BUGZILLA_PRODUCT", ""),
            bugzilla_component=os.getenv("BUGZILLA_COMPONENT", ""),
            bugzilla_version=os.getenv("BUGZILLA_VERSION", "unspecified"),
            auto_create_on_confirmed=_bool(
                os.getenv("TRACKER_AUTO_CREATE_CONFIRMED"), True
            ),
            auto_create_on_false_positive=_bool(
                os.getenv("TRACKER_AUTO_CREATE_FP"), True
            ),
            sync_interval_minutes=_int(
                os.getenv("TRACKER_SYNC_INTERVAL"), 30
            ),
            severity_threshold=os.getenv(
                "TRACKER_SEVERITY_THRESHOLD", "medium"
            ).lower(),
        )
