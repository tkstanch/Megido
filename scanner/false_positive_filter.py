"""
False Positive Filtering Engine

Centralised false positive filtering for all scanner plugin findings.

Features:
- Signature-based exclusion of known-safe response patterns
- Confidence threshold filtering per plugin type
- JSON-based false positive signature database
- Deduplication across multiple scan runs
- Categories: known_false_positive, low_confidence, duplicate, informational_only
"""

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FP category enum
# ---------------------------------------------------------------------------

class FPCategory(str, Enum):
    KNOWN_FALSE_POSITIVE = "known_false_positive"
    LOW_CONFIDENCE = "low_confidence"
    DUPLICATE = "duplicate"
    INFORMATIONAL_ONLY = "informational_only"
    VALID = "valid"


# ---------------------------------------------------------------------------
# Default confidence thresholds per plugin type
# ---------------------------------------------------------------------------

DEFAULT_CONFIDENCE_THRESHOLDS: Dict[str, float] = {
    "xss": 0.7,
    "sqli": 0.8,
    "ssrf": 0.75,
    "xxe": 0.75,
    "clickjacking": 0.6,
    "csrf": 0.65,
    "cors": 0.7,
    "lfi": 0.75,
    "rfi": 0.75,
    "open_redirect": 0.65,
    "idor": 0.7,
    "ssti": 0.8,
    "command_injection": 0.85,
    "default": 0.6,
}

# ---------------------------------------------------------------------------
# Built-in false positive signatures
# ---------------------------------------------------------------------------

BUILTIN_FP_SIGNATURES: Dict[str, List[Dict[str, Any]]] = {
    "xss": [
        {
            "id": "xss_fp_001",
            "description": "HTML entity encoded output - not exploitable",
            "pattern": r"&lt;script&gt;|&amp;lt;script&amp;gt;",
            "match_in": "response_body",
        },
        {
            "id": "xss_fp_002",
            "description": "Content-Security-Policy blocks execution",
            "pattern": r"Content-Security-Policy",
            "match_in": "response_headers",
        },
        {
            "id": "xss_fp_003",
            "description": "X-XSS-Protection header enabled",
            "pattern": r"X-XSS-Protection:\s*1",
            "match_in": "response_headers",
        },
    ],
    "sqli": [
        {
            "id": "sqli_fp_001",
            "description": "Generic database error page - not exploitable injection",
            "pattern": r"An error occurred while processing your request",
            "match_in": "response_body",
        },
        {
            "id": "sqli_fp_002",
            "description": "Error is from input validation, not SQL execution",
            "pattern": r"Invalid (input|parameter|value)",
            "match_in": "response_body",
        },
    ],
    "ssrf": [
        {
            "id": "ssrf_fp_001",
            "description": "URL is validated/sanitized before use",
            "pattern": r"(invalid|blocked|not allowed|denied).*(url|request|address)",
            "match_in": "response_body",
        },
    ],
    "clickjacking": [
        {
            "id": "clickjacking_fp_001",
            "description": "X-Frame-Options header present",
            "pattern": r"X-Frame-Options:\s*(DENY|SAMEORIGIN)",
            "match_in": "response_headers",
        },
        {
            "id": "clickjacking_fp_002",
            "description": "CSP frame-ancestors directive present",
            "pattern": r"frame-ancestors\s+(none|'self')",
            "match_in": "response_headers",
        },
    ],
    "csrf": [
        {
            "id": "csrf_fp_001",
            "description": "CSRF token present in response",
            "pattern": r"(csrf_token|_token|csrfmiddlewaretoken)",
            "match_in": "response_body",
        },
        {
            "id": "csrf_fp_002",
            "description": "SameSite cookie attribute blocks CSRF",
            "pattern": r"SameSite=(Strict|Lax)",
            "match_in": "response_headers",
        },
    ],
    "cors": [
        {
            "id": "cors_fp_001",
            "description": "Wildcard CORS with credentials=false - not exploitable",
            "pattern": r"Access-Control-Allow-Credentials:\s*false",
            "match_in": "response_headers",
        },
    ],
}

# Known-safe response patterns that indicate a finding is informational only
INFORMATIONAL_PATTERNS: List[str] = [
    r"404 not found",
    r"403 forbidden",
    r"this page intentionally left blank",
    r"under construction",
    r"coming soon",
]


# ---------------------------------------------------------------------------
# FilterResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    """Result of filtering a single finding."""

    finding_id: str
    is_false_positive: bool
    category: FPCategory
    reason: str
    confidence: float
    matched_signature_id: Optional[str] = None


# ---------------------------------------------------------------------------
# FalsePositiveFilter
# ---------------------------------------------------------------------------

class FalsePositiveFilter:
    """
    Centralised false positive filter for all scanner plugin findings.

    Parameters
    ----------
    db_path:
        Optional path to a JSON file containing custom FP signatures.
        If provided (and the file exists) the signatures are merged with
        the built-in ones.
    confidence_thresholds:
        Per-plugin confidence thresholds.  Defaults to
        ``DEFAULT_CONFIDENCE_THRESHOLDS``.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        confidence_thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        self._thresholds: Dict[str, float] = dict(DEFAULT_CONFIDENCE_THRESHOLDS)
        if confidence_thresholds:
            self._thresholds.update(confidence_thresholds)

        self._signatures: Dict[str, List[Dict[str, Any]]] = dict(BUILTIN_FP_SIGNATURES)
        self._db_path: Optional[Path] = Path(db_path) if db_path else None

        # Deduplication registry: finding_hash -> first seen timestamp
        self._seen_hashes: Dict[str, str] = {}

        # Pre-compiled regex cache: (plugin_type, pattern) -> compiled regex
        self._compiled_patterns: Dict[str, re.Pattern] = {}

        self._load_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def filter_finding(
        self,
        finding: Dict[str, Any],
        plugin_type: Optional[str] = None,
    ) -> FilterResult:
        """
        Evaluate a single finding and return a ``FilterResult``.

        Parameters
        ----------
        finding:
            Dictionary with at minimum the keys:
            - ``confidence`` (float 0-1)
            - ``plugin_type`` or ``vuln_type`` (str)
            - Optional: ``response_body``, ``response_headers``,
              ``url``, ``parameter``
        plugin_type:
            Override for the plugin type; falls back to
            ``finding.get('plugin_type') or finding.get('vuln_type')``.
        """
        ptype = (
            plugin_type
            or finding.get("plugin_type")
            or finding.get("vuln_type")
            or "default"
        ).lower()

        finding_id = finding.get("id") or finding.get("finding_id") or str(id(finding))

        # 1. Deduplication check
        dup_result = self._check_duplicate(finding, finding_id)
        if dup_result is not None:
            return dup_result

        # 2. Confidence threshold check
        confidence = float(finding.get("confidence", 1.0))
        threshold = self._thresholds.get(ptype, self._thresholds["default"])
        if confidence < threshold:
            return FilterResult(
                finding_id=finding_id,
                is_false_positive=True,
                category=FPCategory.LOW_CONFIDENCE,
                reason=f"Confidence {confidence:.2f} below threshold {threshold:.2f} for {ptype}",
                confidence=confidence,
            )

        # 3. Signature-based matching
        sig_result = self._check_signatures(finding, finding_id, ptype, confidence)
        if sig_result is not None:
            return sig_result

        # 4. Informational-only check
        info_result = self._check_informational(finding, finding_id, confidence)
        if info_result is not None:
            return info_result

        # 5. Valid finding
        self._register_seen(finding)
        return FilterResult(
            finding_id=finding_id,
            is_false_positive=False,
            category=FPCategory.VALID,
            reason="Passed all false positive checks",
            confidence=confidence,
        )

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        plugin_type: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], List[FilterResult]]:
        """
        Filter a list of findings.

        Returns
        -------
        valid_findings:
            Subset of *findings* that are not false positives.
        filter_results:
            ``FilterResult`` for every finding (including valid ones).
        """
        valid: List[Dict[str, Any]] = []
        results: List[FilterResult] = []

        for finding in findings:
            result = self.filter_finding(finding, plugin_type)
            results.append(result)
            if not result.is_false_positive:
                valid.append(finding)

        return valid, results

    def add_signature(
        self,
        plugin_type: str,
        signature: Dict[str, Any],
    ) -> None:
        """Add a custom FP signature at runtime."""
        self._signatures.setdefault(plugin_type, []).append(signature)
        # Invalidate any cached compiled pattern for this signature
        pattern = signature.get("pattern", "")
        if pattern in self._compiled_patterns:
            del self._compiled_patterns[pattern]
        self._save_db()

    def update_threshold(self, plugin_type: str, threshold: float) -> None:
        """Update the confidence threshold for a plugin type."""
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"Threshold must be between 0 and 1, got {threshold}")
        self._thresholds[plugin_type] = threshold

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics about the filter."""
        return {
            "seen_hashes": len(self._seen_hashes),
            "signature_counts": {k: len(v) for k, v in self._signatures.items()},
            "thresholds": dict(self._thresholds),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_duplicate(
        self,
        finding: Dict[str, Any],
        finding_id: str,
    ) -> Optional[FilterResult]:
        fhash = self._hash_finding(finding)
        if fhash in self._seen_hashes:
            return FilterResult(
                finding_id=finding_id,
                is_false_positive=True,
                category=FPCategory.DUPLICATE,
                reason=f"Duplicate of finding first seen at {self._seen_hashes[fhash]}",
                confidence=float(finding.get("confidence", 1.0)),
            )
        return None

    def _check_signatures(
        self,
        finding: Dict[str, Any],
        finding_id: str,
        ptype: str,
        confidence: float,
    ) -> Optional[FilterResult]:
        signatures = self._signatures.get(ptype, []) + self._signatures.get("all", [])
        for sig in signatures:
            pattern = sig.get("pattern", "")
            if not pattern:
                continue
            compiled = self._compiled_patterns.get(pattern)
            if compiled is None:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self._compiled_patterns[pattern] = compiled
                except re.error:
                    continue
            match_in = sig.get("match_in", "response_body")
            target_text = self._get_match_target(finding, match_in)
            if target_text and compiled.search(target_text):
                return FilterResult(
                    finding_id=finding_id,
                    is_false_positive=True,
                    category=FPCategory.KNOWN_FALSE_POSITIVE,
                    reason=f"Matched FP signature '{sig.get('id', 'unknown')}': {sig.get('description', '')}",
                    confidence=confidence,
                    matched_signature_id=sig.get("id"),
                )
        return None

    def _check_informational(
        self,
        finding: Dict[str, Any],
        finding_id: str,
        confidence: float,
    ) -> Optional[FilterResult]:
        body = finding.get("response_body", "")
        if not body:
            return None
        body_lower = body.lower()
        for pattern in INFORMATIONAL_PATTERNS:
            if re.search(pattern, body_lower):
                return FilterResult(
                    finding_id=finding_id,
                    is_false_positive=True,
                    category=FPCategory.INFORMATIONAL_ONLY,
                    reason=f"Response matches informational-only pattern: {pattern}",
                    confidence=confidence,
                )
        return None

    def _get_match_target(
        self,
        finding: Dict[str, Any],
        match_in: str,
    ) -> Optional[str]:
        if match_in == "response_body":
            return finding.get("response_body", "")
        if match_in == "response_headers":
            headers = finding.get("response_headers", {})
            if isinstance(headers, dict):
                return " ".join(f"{k}: {v}" for k, v in headers.items())
            return str(headers)
        return None

    def _hash_finding(self, finding: Dict[str, Any]) -> str:
        """Compute a stable hash for deduplication."""
        key_parts = [
            str(finding.get("url", "")),
            str(finding.get("parameter", "")),
            str(finding.get("plugin_type") or finding.get("vuln_type", "")),
            str(finding.get("payload", "")),
        ]
        return hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]

    def _register_seen(self, finding: Dict[str, Any]) -> None:
        fhash = self._hash_finding(finding)
        self._seen_hashes[fhash] = datetime.utcnow().isoformat()

    def _load_db(self) -> None:
        if not self._db_path or not self._db_path.exists():
            return
        try:
            with open(self._db_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # Merge custom signatures
            for ptype, sigs in data.get("signatures", {}).items():
                self._signatures.setdefault(ptype, []).extend(sigs)
            # Merge custom thresholds
            for ptype, thr in data.get("thresholds", {}).items():
                self._thresholds[ptype] = float(thr)
            logger.debug("Loaded FP database from %s", self._db_path)
        except Exception as exc:
            logger.warning("Could not load FP database from %s: %s", self._db_path, exc)

    def _save_db(self) -> None:
        if not self._db_path:
            return
        try:
            # Only save non-builtin signatures to avoid bloat
            custom_sigs: Dict[str, List[Dict[str, Any]]] = {}
            builtin_ids: Set[str] = {
                sig["id"]
                for sigs in BUILTIN_FP_SIGNATURES.values()
                for sig in sigs
            }
            for ptype, sigs in self._signatures.items():
                custom = [s for s in sigs if s.get("id") not in builtin_ids]
                if custom:
                    custom_sigs[ptype] = custom
            data = {"signatures": custom_sigs, "thresholds": {}}
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._db_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as exc:
            logger.warning("Could not save FP database to %s: %s", self._db_path, exc)


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

_default_filter: Optional[FalsePositiveFilter] = None


def get_default_filter() -> FalsePositiveFilter:
    """Return a module-level singleton ``FalsePositiveFilter``."""
    global _default_filter
    if _default_filter is None:
        _default_filter = FalsePositiveFilter()
    return _default_filter
