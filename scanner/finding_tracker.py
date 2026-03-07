"""
Finding Tracker

Centralised lifecycle tracker for vulnerability findings discovered by Megido.

Finding lifecycle::

    detected → verified → confirmed → exploited → reported → remediated
                                 ↘
                               false_positive

Each finding is identified by a UUID and carries full evidence, impact data,
and an optional link to an external issue tracker (Jira / Bugzilla).
"""

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding status enum
# ---------------------------------------------------------------------------

class FindingStatus(str, Enum):
    DETECTED = "detected"
    VERIFIED = "verified"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    REPORTED = "reported"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


# Valid forward state transitions
_VALID_TRANSITIONS: Dict[FindingStatus, List[FindingStatus]] = {
    FindingStatus.DETECTED: [
        FindingStatus.VERIFIED,
        FindingStatus.FALSE_POSITIVE,
    ],
    FindingStatus.VERIFIED: [
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
    ],
    FindingStatus.CONFIRMED: [
        FindingStatus.EXPLOITED,
        FindingStatus.REPORTED,
        FindingStatus.REMEDIATED,
        FindingStatus.FALSE_POSITIVE,
    ],
    FindingStatus.EXPLOITED: [
        FindingStatus.REPORTED,
        FindingStatus.REMEDIATED,
        FindingStatus.FALSE_POSITIVE,
    ],
    FindingStatus.REPORTED: [
        FindingStatus.REMEDIATED,
    ],
    FindingStatus.REMEDIATED: [],
    FindingStatus.FALSE_POSITIVE: [],
}


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single vulnerability finding with its full lifecycle state."""

    # Identity
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: FindingStatus = FindingStatus.DETECTED

    # Vulnerability metadata
    vulnerability_type: str = ""
    target_url: str = ""
    parameter: str = ""
    severity: str = "medium"       # critical | high | medium | low | info
    confidence_score: float = 0.0  # 0.0 – 1.0

    # Evidence at different lifecycle stages
    detection_evidence: Optional[str] = None
    verification_evidence: Optional[str] = None
    exploitation_evidence: Optional[str] = None

    # Impact determined by ImpactAnalyzer
    real_impact: Optional[Dict[str, Any]] = None

    # False-positive tracking
    false_positive_reason: Optional[str] = None

    # External issue tracker linkage
    tracker_issue_id: Optional[str] = None
    tracker_issue_url: Optional[str] = None

    # Timestamps (ISO-8601 strings for JSON-serialisability)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    verified_at: Optional[str] = None
    exploited_at: Optional[str] = None

    # Vulnerability chaining — list of other finding_ids this finding chains with
    chain_findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict representation (JSON-serialisable)."""
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ---------------------------------------------------------------------------
# FindingTracker
# ---------------------------------------------------------------------------

class FindingTracker:
    """
    Registry and lifecycle manager for vulnerability findings.

    Thread-safety: this implementation is **not** thread-safe by design; it is
    intended to be used within a single scan session.  For multi-threaded
    environments wrap accesses with an external lock.
    """

    def __init__(self) -> None:
        self._findings: Dict[str, Finding] = {}

    # ------------------------------------------------------------------
    # CRUD helpers
    # ------------------------------------------------------------------

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_finding(self, finding_data: Dict[str, Any]) -> Finding:
        """
        Register a new finding.

        Args:
            finding_data: Dict of finding fields.  A new UUID is generated if
                          ``finding_id`` is absent.  ``status`` defaults to
                          ``FindingStatus.DETECTED``.

        Returns:
            The newly created ``Finding`` instance.
        """
        # Allow callers to pass a status string
        status_raw = finding_data.pop("status", FindingStatus.DETECTED)
        if isinstance(status_raw, str):
            status_raw = FindingStatus(status_raw)

        finding = Finding(status=status_raw, **finding_data)
        self._findings[finding.finding_id] = finding
        logger.debug("Registered finding %s (%s)", finding.finding_id, finding.vulnerability_type)
        return finding

    def update_status(
        self,
        finding_id: str,
        new_status: FindingStatus,
        evidence: Optional[str] = None,
    ) -> Finding:
        """
        Transition a finding to *new_status*.

        Args:
            finding_id: UUID of the finding to update.
            new_status: Target ``FindingStatus``.
            evidence:   Optional evidence string stored with the transition.

        Returns:
            The updated ``Finding`` instance.

        Raises:
            KeyError: If *finding_id* is unknown.
            ValueError: If the transition is not allowed.
        """
        finding = self._get_or_raise(finding_id)

        allowed = _VALID_TRANSITIONS.get(finding.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Cannot transition finding {finding_id} from "
                f"'{finding.status.value}' to '{new_status.value}'. "
                f"Allowed transitions: {[s.value for s in allowed]}"
            )

        # Store evidence in the appropriate field
        now = self._now_iso()
        if new_status == FindingStatus.VERIFIED:
            finding.verification_evidence = evidence
            finding.verified_at = now
        elif new_status in (FindingStatus.EXPLOITED,):
            finding.exploitation_evidence = evidence
            finding.exploited_at = now

        finding.status = new_status
        finding.updated_at = now
        logger.debug("Finding %s transitioned → %s", finding_id, new_status.value)
        return finding

    def mark_false_positive(self, finding_id: str, reason: str) -> Finding:
        """
        Mark a finding as a false positive.

        The finding can be in any non-terminal, non-remediated state.

        Args:
            finding_id: UUID of the finding.
            reason:     Reason for the false-positive classification.

        Returns:
            The updated ``Finding`` instance.
        """
        finding = self._get_or_raise(finding_id)

        if finding.status == FindingStatus.REMEDIATED:
            raise ValueError(
                f"Cannot mark a remediated finding ({finding_id}) as false positive."
            )
        if finding.status == FindingStatus.FALSE_POSITIVE:
            logger.debug("Finding %s is already marked as false positive", finding_id)
            return finding

        finding.status = FindingStatus.FALSE_POSITIVE
        finding.false_positive_reason = reason
        finding.updated_at = self._now_iso()
        logger.info("Finding %s marked as false positive: %s", finding_id, reason)
        return finding

    def mark_exploited(
        self,
        finding_id: str,
        exploitation_result: Optional[str] = None,
        real_impact: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """
        Mark a finding as exploited with an optional real-impact dict.

        Args:
            finding_id:          UUID of the finding.
            exploitation_result: Human-readable exploitation summary.
            real_impact:         Output from ``ImpactAnalyzer.analyze_impact()``.

        Returns:
            The updated ``Finding`` instance.
        """
        finding = self._get_or_raise(finding_id)

        # Allow transitioning from confirmed or verified directly to exploited
        if finding.status not in (FindingStatus.CONFIRMED, FindingStatus.VERIFIED):
            # Attempt a normal state transition first if in detected
            if finding.status == FindingStatus.DETECTED:
                self.update_status(finding_id, FindingStatus.VERIFIED)
                self.update_status(finding_id, FindingStatus.CONFIRMED)
            else:
                # Try normal path
                self.update_status(finding_id, FindingStatus.EXPLOITED, evidence=exploitation_result)
                finding = self._findings[finding_id]
                if real_impact is not None:
                    finding.real_impact = real_impact
                return finding

        self.update_status(finding_id, FindingStatus.EXPLOITED, evidence=exploitation_result)
        finding = self._findings[finding_id]
        if real_impact is not None:
            finding.real_impact = real_impact
        return finding

    def get_finding(self, finding_id: str) -> Finding:
        """Return the ``Finding`` with the given UUID."""
        return self._get_or_raise(finding_id)

    def get_findings_by_status(self, status: FindingStatus) -> List[Finding]:
        """Return all findings currently in *status*."""
        return [f for f in self._findings.values() if f.status == status]

    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Return aggregated counts by status and severity.

        Returns::

            {
                "total": int,
                "by_status": {"detected": int, ...},
                "by_severity": {"critical": int, ...},
            }
        """
        by_status: Dict[str, int] = {s.value: 0 for s in FindingStatus}
        by_severity: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }

        for finding in self._findings.values():
            by_status[finding.status.value] += 1
            sev = finding.severity.lower()
            if sev in by_severity:
                by_severity[sev] += 1

        return {
            "total": len(self._findings),
            "by_status": by_status,
            "by_severity": by_severity,
        }

    def link_to_tracker(
        self, finding_id: str, issue_id: str, issue_url: str
    ) -> Finding:
        """
        Associate a finding with an external tracker ticket.

        Args:
            finding_id: UUID of the finding.
            issue_id:   Tracker-native ticket ID.
            issue_url:  Direct URL to the ticket.

        Returns:
            The updated ``Finding`` instance.
        """
        finding = self._get_or_raise(finding_id)
        finding.tracker_issue_id = issue_id
        finding.tracker_issue_url = issue_url
        finding.updated_at = self._now_iso()
        return finding

    def export_findings(self, fmt: str = "json") -> str:
        """
        Export all findings.

        Args:
            fmt: Output format — currently only ``"json"`` is supported.

        Returns:
            Serialised findings string.
        """
        data = [f.to_dict() for f in self._findings.values()]
        if fmt == "json":
            return json.dumps(data, indent=2, default=str)
        raise ValueError(f"Unsupported export format: {fmt!r}")

    def add_chain(self, finding_id: str, chained_finding_id: str) -> None:
        """
        Record that two findings are part of a vulnerability chain.

        The link is added to *both* findings (bidirectional).

        Args:
            finding_id:         UUID of the first finding.
            chained_finding_id: UUID of the second finding.
        """
        finding = self._get_or_raise(finding_id)
        chained = self._get_or_raise(chained_finding_id)

        if chained_finding_id not in finding.chain_findings:
            finding.chain_findings.append(chained_finding_id)
        if finding_id not in chained.chain_findings:
            chained.chain_findings.append(finding_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_raise(self, finding_id: str) -> Finding:
        finding = self._findings.get(finding_id)
        if finding is None:
            raise KeyError(f"Finding not found: {finding_id}")
        return finding
