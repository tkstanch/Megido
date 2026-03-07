"""
Finding Prioritization Engine

Prioritises vulnerability findings by exploit path clarity, verification
status, CVSS severity, and estimated bug bounty reward.

Priority tiers
--------------
* ``critical_exploitable`` – CVSS 9.0+, confirmed exploitation evidence
* ``high_verified``        – CVSS 7.0–8.9, finding is verified/confirmed
* ``medium_likely``        – CVSS 4.0–6.9, likely valid but unconfirmed
* ``low_unverified``       – CVSS < 4.0 or unverified
* ``noise``                – Low confidence, informational, or FP-filtered

Usage::

    from scanner.finding_prioritizer import FindingPrioritizer

    prioritizer = FindingPrioritizer()
    ranked = prioritizer.rank(findings)  # list sorted high-to-low priority
"""

import logging
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PriorityTier(str, Enum):
    CRITICAL_EXPLOITABLE = "critical_exploitable"
    HIGH_VERIFIED = "high_verified"
    MEDIUM_LIKELY = "medium_likely"
    LOW_UNVERIFIED = "low_unverified"
    NOISE = "noise"


# Tier sort order (lower = higher priority)
_TIER_ORDER: Dict[PriorityTier, int] = {
    PriorityTier.CRITICAL_EXPLOITABLE: 0,
    PriorityTier.HIGH_VERIFIED: 1,
    PriorityTier.MEDIUM_LIKELY: 2,
    PriorityTier.LOW_UNVERIFIED: 3,
    PriorityTier.NOISE: 4,
}

# ---------------------------------------------------------------------------
# Bug bounty reward estimation tables (USD ranges)
# ---------------------------------------------------------------------------

# Base reward ranges by vulnerability type
_BASE_REWARDS: Dict[str, Tuple[int, int]] = {
    "sqli": (1500, 10000),
    "command_injection": (2000, 15000),
    "rce": (3000, 20000),
    "ssrf": (500, 5000),
    "xxe": (500, 4000),
    "xss": (100, 3000),
    "csrf": (100, 1000),
    "idor": (200, 5000),
    "open_redirect": (50, 500),
    "clickjacking": (50, 300),
    "cors": (200, 2000),
    "lfi": (300, 3000),
    "rfi": (500, 5000),
    "ssti": (1000, 8000),
    "jwt": (300, 3000),
    "graphql": (200, 2000),
    "default": (50, 500),
}

# Multipliers based on severity
_SEVERITY_MULTIPLIERS: Dict[str, float] = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5,
    "info": 0.1,
}

# ---------------------------------------------------------------------------
# CVSS score ranges for tier assignment
# ---------------------------------------------------------------------------

_CVSS_CRITICAL = 9.0
_CVSS_HIGH_MIN = 7.0
_CVSS_MEDIUM_MIN = 4.0


# ---------------------------------------------------------------------------
# ScoredFinding dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScoredFinding:
    """A finding enriched with priority scores."""

    finding: Dict[str, Any]

    # Composite priority score (higher = more important)
    priority_score: float = 0.0

    # Assigned tier
    tier: PriorityTier = PriorityTier.NOISE

    # Individual score components
    cvss_score: float = 0.0
    exploit_path_score: float = 0.0
    verification_score: float = 0.0

    # Estimated bounty range (USD)
    bounty_min: int = 0
    bounty_max: int = 0

    # Human-readable reason for tier assignment
    tier_reason: str = ""


# ---------------------------------------------------------------------------
# FindingPrioritizer
# ---------------------------------------------------------------------------

class FindingPrioritizer:
    """
    Rank and prioritise vulnerability findings.

    Parameters
    ----------
    cvss_weight:
        Weight of CVSS score component (0–1).
    exploit_weight:
        Weight of exploit path score component (0–1).
    verification_weight:
        Weight of verification status component (0–1).
    """

    def __init__(
        self,
        cvss_weight: float = 0.5,
        exploit_weight: float = 0.3,
        verification_weight: float = 0.2,
    ) -> None:
        self._cvss_w = cvss_weight
        self._exploit_w = exploit_weight
        self._verify_w = verification_weight

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, finding: Dict[str, Any]) -> ScoredFinding:
        """Compute a ``ScoredFinding`` for a single finding dict."""
        cvss_score = self._extract_cvss(finding)
        exploit_score = self._compute_exploit_path_score(finding)
        verify_score = self._compute_verification_score(finding)

        # Weighted composite score (0–10 scale)
        composite = (
            cvss_score * self._cvss_w
            + exploit_score * 10.0 * self._exploit_w
            + verify_score * 10.0 * self._verify_w
        )

        tier, reason = self._assign_tier(cvss_score, exploit_score, verify_score, finding)
        bounty_min, bounty_max = self._estimate_bounty(finding, cvss_score)

        return ScoredFinding(
            finding=finding,
            priority_score=composite,
            tier=tier,
            cvss_score=cvss_score,
            exploit_path_score=exploit_score,
            verification_score=verify_score,
            bounty_min=bounty_min,
            bounty_max=bounty_max,
            tier_reason=reason,
        )

    def rank(self, findings: List[Dict[str, Any]]) -> List[ScoredFinding]:
        """
        Score and sort *findings* from highest to lowest priority.

        Returns a list of ``ScoredFinding`` objects.
        """
        scored = [self.score(f) for f in findings]
        scored.sort(key=lambda sf: (_TIER_ORDER[sf.tier], -sf.priority_score))
        return scored

    def get_tier_summary(self, scored: List[ScoredFinding]) -> Dict[str, int]:
        """Return count per tier for a ranked list."""
        counts: Dict[str, int] = {t.value: 0 for t in PriorityTier}
        for sf in scored:
            counts[sf.tier.value] += 1
        return counts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_cvss(self, finding: Dict[str, Any]) -> float:
        """Extract CVSS base score from the finding (0–10)."""
        # Direct cvss_score field
        score = finding.get("cvss_score") or finding.get("cvss_base")
        if score is not None:
            try:
                return min(10.0, max(0.0, float(score)))
            except (TypeError, ValueError):
                pass

        # Fall back to severity string
        severity = (finding.get("severity") or "").lower()
        return {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 0.5,
            "informational": 0.5,
        }.get(severity, 5.0)

    def _compute_exploit_path_score(self, finding: Dict[str, Any]) -> float:
        """
        Return a 0-1 score for exploit path clarity.

        Higher when there is a PoC, exploitation evidence, or steps-to-reproduce.
        """
        score = 0.0

        if finding.get("proof_of_concept") or finding.get("poc_script"):
            score += 0.4
        if finding.get("exploitation_steps") or finding.get("steps_to_reproduce"):
            score += 0.2
        if finding.get("exploit_evidence") or finding.get("http_traffic"):
            score += 0.2
        if finding.get("exploited") is True:
            score += 0.2

        return min(1.0, score)

    def _compute_verification_score(self, finding: Dict[str, Any]) -> float:
        """Return a 0-1 score for verification status."""
        status = (finding.get("status") or finding.get("verification_status") or "").lower()
        verified_map = {
            "confirmed": 1.0,
            "exploited": 1.0,
            "verified": 0.9,
            "likely": 0.6,
            "unconfirmed": 0.3,
            "detected": 0.2,
            "false_positive": 0.0,
        }
        if status in verified_map:
            return verified_map[status]

        # Fall back to boolean is_verified field
        if finding.get("is_verified") is True:
            return 0.9
        return 0.3

    def _assign_tier(
        self,
        cvss: float,
        exploit: float,
        verify: float,
        finding: Dict[str, Any],
    ) -> Tuple[PriorityTier, str]:
        # Filter out noise first
        confidence = float(finding.get("confidence", 1.0))
        if confidence < 0.4 or finding.get("is_false_positive"):
            return PriorityTier.NOISE, "Low confidence or false positive"

        is_exploited = bool(finding.get("exploited") or finding.get("is_exploited"))

        if cvss >= _CVSS_CRITICAL and (is_exploited or exploit >= 0.4 or verify >= 0.8):
            return (
                PriorityTier.CRITICAL_EXPLOITABLE,
                f"Critical CVSS {cvss:.1f} with exploitation evidence",
            )

        if cvss >= _CVSS_HIGH_MIN and verify >= 0.6:
            return (
                PriorityTier.HIGH_VERIFIED,
                f"High CVSS {cvss:.1f} with verification",
            )

        if cvss >= _CVSS_MEDIUM_MIN:
            return (
                PriorityTier.MEDIUM_LIKELY,
                f"Medium CVSS {cvss:.1f}, likely valid",
            )

        if cvss > 0:
            return (
                PriorityTier.LOW_UNVERIFIED,
                f"Low CVSS {cvss:.1f} or unverified",
            )

        return PriorityTier.NOISE, "Insufficient scoring data"

    def _estimate_bounty(
        self,
        finding: Dict[str, Any],
        cvss_score: float,
    ) -> Tuple[int, int]:
        """Estimate min/max bug bounty reward in USD."""
        ptype = (
            finding.get("plugin_type")
            or finding.get("vuln_type")
            or finding.get("vulnerability_type")
            or "default"
        ).lower()

        base_min, base_max = _BASE_REWARDS.get(ptype, _BASE_REWARDS["default"])

        severity = (finding.get("severity") or "").lower()
        if not severity:
            if cvss_score >= 9.0:
                severity = "critical"
            elif cvss_score >= 7.0:
                severity = "high"
            elif cvss_score >= 4.0:
                severity = "medium"
            else:
                severity = "low"

        multiplier = _SEVERITY_MULTIPLIERS.get(severity, 1.0)
        return int(base_min * multiplier), int(base_max * multiplier)
