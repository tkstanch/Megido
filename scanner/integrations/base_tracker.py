"""
Base Issue Tracker

Abstract base class for issue tracker integrations (Jira, Bugzilla, etc.).
Provides a consistent interface for creating, updating, and querying tickets.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseIssueTracker(ABC):
    """
    Abstract base class for issue tracker integrations.

    Subclasses implement the concrete REST API calls for each tracker.
    All methods accept/return plain dicts so callers don't need to import
    tracker-specific types.
    """

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def create_issue(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a ticket for a confirmed finding.

        Args:
            finding: Finding data dict (as produced by FindingTracker).

        Returns:
            Dict containing at least ``issue_id`` and ``issue_url``.
        """

    @abstractmethod
    def create_false_positive_issue(
        self, finding: Dict[str, Any], reason: str
    ) -> Dict[str, Any]:
        """
        Create a ticket specifically for false-positive tracking.

        Args:
            finding: Finding data dict.
            reason:  Human-readable explanation of why this is a FP.

        Returns:
            Dict containing at least ``issue_id`` and ``issue_url``.
        """

    @abstractmethod
    def update_issue(
        self, issue_id: str, status: str, comment: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update an existing ticket's status and optionally add a comment.

        Args:
            issue_id: Tracker-native ticket identifier.
            status:   New status string (e.g. ``"In Progress"``).
            comment:  Optional comment to add to the ticket.

        Returns:
            Updated ticket data dict.
        """

    @abstractmethod
    def get_issue(self, issue_id: str) -> Dict[str, Any]:
        """
        Retrieve full ticket details.

        Args:
            issue_id: Tracker-native ticket identifier.

        Returns:
            Ticket data dict.
        """

    @abstractmethod
    def sync_status(self, finding_id: str) -> Dict[str, Any]:
        """
        Synchronise status between Megido and the tracker.

        Args:
            finding_id: Megido finding UUID.

        Returns:
            Dict with ``megido_status`` and ``tracker_status`` keys.
        """

    @abstractmethod
    def search_issues(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for existing tickets matching *query*.

        Args:
            query: Tracker-native search query string.

        Returns:
            List of matching ticket data dicts.
        """

    @abstractmethod
    def close_issue(self, issue_id: str, resolution: str) -> Dict[str, Any]:
        """
        Close a ticket with the given resolution.

        Args:
            issue_id:   Tracker-native ticket identifier.
            resolution: Resolution string (e.g. ``"Fixed"``, ``"Won't Fix"``).

        Returns:
            Updated ticket data dict.
        """
