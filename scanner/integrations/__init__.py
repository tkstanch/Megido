"""
Issue Tracker Integrations Package

Provides centralised issue tracker integration classes for Megido.
Supported backends: Jira, Bugzilla.

Usage::

    from scanner.integrations import JiraTracker, BugzillaTracker, TrackerConfig

    config = TrackerConfig.from_env()
    if config.tracker_type == "jira":
        tracker = JiraTracker(
            jira_url=config.jira_url,
            project_key=config.jira_project_key,
            api_token=config.jira_api_token,
            email=config.jira_email,
        )
"""

from .base_tracker import BaseIssueTracker
from .bugzilla_tracker import BugzillaTracker
from .jira_tracker import JiraTracker
from .tracker_config import TrackerConfig

__all__ = [
    "BaseIssueTracker",
    "JiraTracker",
    "BugzillaTracker",
    "TrackerConfig",
]
