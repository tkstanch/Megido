"""
Finding Deduplication and Correlation Engine

Deduplicates findings across plugins and correlates related findings
to reduce noise in scan reports.

Deduplication strategy:
- Same URL + same parameter + same vulnerability type → deduplicate
- Same URL + same vulnerability type (no parameter) → deduplicate

Correlation rules:
- Multiple plugins detecting the same injection point → merge evidence
  and boost confidence.

Usage::

    from scanner.deduplication import deduplicate, correlate
    from scanner.scan_plugins import VulnerabilityFinding

    findings = engine.scan(url, config)
    clean = deduplicate(findings)
    final = correlate(clean)
"""

import hashlib
import logging
from typing import Dict, List, Optional

from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_key(finding: VulnerabilityFinding) -> str:
    """
    Generate a deduplication key for a finding.

    Two findings share a key when they have the same:
    - vulnerability type
    - URL (normalised)
    - parameter (if present)
    """
    url = (finding.url or '').rstrip('/')
    param = finding.parameter or ''
    raw = f"{finding.vulnerability_type}::{url}::{param}"
    return hashlib.sha1(raw.encode()).hexdigest()


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for a severity string (higher = more severe)."""
    return {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(
        severity.lower(), 0
    )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
    """
    Remove duplicate findings, keeping the highest-severity / highest-confidence
    representative.

    Args:
        findings: Raw list of findings from all plugins.

    Returns:
        Deduplicated list.
    """
    seen: Dict[str, VulnerabilityFinding] = {}

    for finding in findings:
        key = _finding_key(finding)

        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            # Prefer the higher-severity finding
            if _severity_rank(finding.severity) > _severity_rank(existing.severity):
                seen[key] = finding
            # Among equal severity, prefer higher confidence
            elif (
                _severity_rank(finding.severity) == _severity_rank(existing.severity)
                and finding.confidence > existing.confidence
            ):
                seen[key] = finding

    result = list(seen.values())
    removed = len(findings) - len(result)
    if removed:
        logger.info("Deduplication: removed %d duplicate finding(s)", removed)
    return result


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlate(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
    """
    Merge related findings and boost confidence when multiple plugins confirm
    the same vulnerability.

    Two findings are correlated when they share the same URL and parameter.
    The merged finding inherits the highest severity and accumulated evidence.

    Args:
        findings: List of (already deduplicated) findings.

    Returns:
        Correlated list with boosted confidence where applicable.
    """
    # Group by (url, parameter) — ignoring vulnerability_type intentionally
    # to catch multi-plugin confirmations of the same injection point.
    groups: Dict[str, List[VulnerabilityFinding]] = {}
    for finding in findings:
        url = (finding.url or '').rstrip('/')
        param = finding.parameter or ''
        group_key = f"{url}::{param}"
        groups.setdefault(group_key, []).append(finding)

    result: List[VulnerabilityFinding] = []

    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Multiple findings on the same injection point — merge
        best = max(group, key=lambda f: (_severity_rank(f.severity), f.confidence))
        all_evidence = '\n---\n'.join(
            f"[{f.vulnerability_type.upper()}] {f.evidence}"
            for f in group
            if f.evidence
        )
        all_payloads: List[str] = []
        for f in group:
            if f.successful_payloads:
                all_payloads.extend(f.successful_payloads)

        # Confidence boost: each additional confirmation adds 0.1 (capped at 1.0)
        boosted_confidence = min(best.confidence + 0.1 * (len(group) - 1), 1.0)

        merged = VulnerabilityFinding(
            vulnerability_type=best.vulnerability_type,
            severity=best.severity,
            url=best.url,
            description=best.description,
            evidence=all_evidence or best.evidence,
            remediation=best.remediation,
            parameter=best.parameter,
            confidence=boosted_confidence,
            cwe_id=best.cwe_id,
            verified=any(f.verified for f in group),
            successful_payloads=all_payloads or best.successful_payloads,
            repeater_requests=best.repeater_requests,
            http_traffic=best.http_traffic,
            vpoc=best.vpoc,
        )
        result.append(merged)
        logger.debug(
            "Correlated %d findings at %s (param=%s) → confidence %.2f",
            len(group),
            best.url,
            best.parameter or '<none>',
            boosted_confidence,
        )

    boosted = sum(1 for g in groups.values() if len(g) > 1)
    if boosted:
        logger.info(
            "Correlation: merged %d injection point(s) with multiple findings", boosted
        )

    return result


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def deduplicate_and_correlate(
    findings: List[VulnerabilityFinding],
) -> List[VulnerabilityFinding]:
    """
    Run deduplication followed by correlation in one call.

    Args:
        findings: Raw list of findings from all plugins.

    Returns:
        Clean, correlated list of findings.
    """
    deduped = deduplicate(findings)
    correlated = correlate(deduped)
    logger.info(
        "Deduplication+Correlation: %d → %d finding(s)",
        len(findings),
        len(correlated),
    )
    return correlated
