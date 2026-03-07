"""
Base Scan Plugin Interface

This module defines the base interface for vulnerability detection plugins.
Each plugin implements scanning logic for a specific vulnerability type or category.

Note: This is separate from ExploitPlugin which handles exploitation of known vulns.
      ScanPlugins focus on DETECTION, ExploitPlugins focus on EXPLOITATION.
"""

import logging
import time
import random
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

if TYPE_CHECKING:
    from scanner.scan_plugins.vpoc import VPoCEvidence

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from scanner.plugins.adaptive_payload_learner import AdaptivePayloadLearner
    _HAS_LEARNER = True
except ImportError:
    _HAS_LEARNER = False

_base_logger = logging.getLogger(__name__)


logger = _base_logger


class ScanSeverity(Enum):
    """Severity levels for discovered vulnerabilities"""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class VulnerabilityFinding:
    """
    Represents a vulnerability found during scanning.
    
    This standardized format ensures consistent reporting across all plugins.
    Enhanced with payload tracking and repeater-ready request/response data.
    """
    vulnerability_type: str  # e.g., 'xss', 'sqli', 'csrf', 'info_disclosure'
    severity: str  # 'low', 'medium', 'high', 'critical'
    url: str
    description: str
    evidence: str
    remediation: str
    parameter: Optional[str] = None
    confidence: float = 0.5  # 0.0 to 1.0
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    
    # Enhanced fields for verification and manual testing
    verified: bool = False  # True if exploit confirmed real-world impact
    successful_payloads: Optional[List[str]] = None  # Payloads that succeeded
    repeater_requests: Optional[List[Dict[str, Any]]] = None  # Copy-paste ready request data
    http_traffic: Optional[Dict[str, Any]] = None  # HTTP request/response traffic capture

    # Visual Proof of Concept evidence (populated by exploit-capable plugins)
    vpoc: Optional['VPoCEvidence'] = None

    # Bug-bounty quality fields
    # Flags findings that may be Self-XSS (requires manual console injection)
    self_xss_risk: bool = False
    # Indicates whether exploitability has been independently confirmed
    exploitability_confirmed: bool = False
    # Whether the admin/resource requires authentication to access
    requires_authentication: Optional[bool] = None
    # Human-readable note about potential false positive conditions
    false_positive_risk: Optional[str] = None
    # Notes about bounty eligibility
    bounty_notes: Optional[str] = None

    # CVSS and enrichment fields
    # CVSS v3.1 base score (0.0-10.0); None if not yet estimated
    cvss_score: Optional[float] = None
    # External references such as CVE IDs, CWE links, blog posts
    references: Optional[List[str]] = None
    # CVSS attack complexity ('low' or 'high'); None if not set
    attack_complexity: Optional[str] = None

    @property
    def risk_score(self) -> float:
        """
        Composite risk score (0–100) combining severity, confidence, and CVSS.

        The score weighs:
        - Severity bucket  (0-40 points)
        - Confidence       (0-30 points)
        - CVSS base score  (0-30 points, scaled from 0-10)

        Returns:
            float: Risk score between 0.0 and 100.0
        """
        severity_points = {
            'critical': 40.0,
            'high': 30.0,
            'medium': 20.0,
            'low': 10.0,
        }
        sev_pts = severity_points.get((self.severity or '').lower(), 0.0)
        conf_pts = float(self.confidence) * 30.0
        cvss_pts = (float(self.cvss_score) / 10.0) * 30.0 if self.cvss_score is not None else 0.0
        return round(min(100.0, sev_pts + conf_pts + cvss_pts), 2)

    @property
    def bounty_likelihood(self) -> str:
        """
        Map confidence score to expected bug-bounty acceptance likelihood.

        Returns:
            'high'          confidence >= 0.8
            'medium'        confidence 0.6–0.79
            'low'           confidence 0.4–0.59
            'informational' confidence < 0.4
        """
        if self.confidence >= 0.8:
            return 'high'
        if self.confidence >= 0.6:
            return 'medium'
        if self.confidence >= 0.4:
            return 'low'
        return 'informational'

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'url': self.url,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'parameter': self.parameter,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'verified': self.verified,
            'bounty_likelihood': self.bounty_likelihood,
        }

        # Include enhanced fields if present
        if self.successful_payloads:
            result['successful_payloads'] = self.successful_payloads

        if self.repeater_requests:
            result['repeater_requests'] = self.repeater_requests

        if self.http_traffic:
            result['http_traffic'] = self.http_traffic

        if self.vpoc is not None:
            result['vpoc'] = self.vpoc.to_dict()

        if self.self_xss_risk is not None:
            result['self_xss_risk'] = self.self_xss_risk

        if self.exploitability_confirmed is not None:
            result['exploitability_confirmed'] = self.exploitability_confirmed

        if self.requires_authentication is not None:
            result['requires_authentication'] = self.requires_authentication

        if self.false_positive_risk is not None:
            result['false_positive_risk'] = self.false_positive_risk

        if self.bounty_notes is not None:
            result['bounty_notes'] = self.bounty_notes

        if self.cvss_score is not None:
            result['cvss_score'] = self.cvss_score

        if self.references is not None:
            result['references'] = self.references

        if self.attack_complexity is not None:
            result['attack_complexity'] = self.attack_complexity

        result['risk_score'] = self.risk_score

        return result


class BaseScanPlugin(ABC):
    """
    Base interface for vulnerability scan plugins.
    
    All scan plugins must inherit from this class and implement the required methods.
    Plugins are automatically discovered by the ScanPluginRegistry.
    
    Attributes:
        plugin_id: Unique identifier for the plugin
        name: Human-readable name
        description: Brief description of what the plugin scans for
        version: Plugin version
    """
    
    def __init__(self):
        """Initialize the scan plugin."""
        if _HAS_LEARNER:
            self._adaptive_learner: Optional[AdaptivePayloadLearner] = AdaptivePayloadLearner()
        else:
            self._adaptive_learner = None
    
    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """
        Return a unique identifier for this plugin.
        
        Returns:
            str: Plugin identifier (e.g., 'xss_scanner', 'header_scanner')
        """
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the human-readable name of this plugin.
        
        Returns:
            str: Plugin name (e.g., 'XSS Vulnerability Scanner')
        """
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """
        Return a brief description of what this plugin scans for.
        
        Returns:
            str: Plugin description
        """
        pass
    
    @property
    def version(self) -> str:
        """
        Return the version of this plugin.
        
        Returns:
            str: Version string (default: '1.0.0')
        """
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        """
        Return list of vulnerability types this plugin can detect.
        
        Returns:
            List[str]: List of vulnerability type identifiers
        """
        return []
    
    @property
    def supports_async(self) -> bool:
        """
        Indicate if this plugin supports async scanning.
        
        TODO: Implement async support in future phase.
        
        Returns:
            bool: True if plugin supports async, False otherwise
        """
        return False
    
    @abstractmethod
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Perform vulnerability scan on the target URL.
        
        This is the main method that implements the scanning logic.
        It should be safe to call multiple times and should handle errors gracefully.
        
        Args:
            url: Target URL to scan
            config: Optional configuration dictionary:
                   - verify_ssl: bool (default: False)
                   - timeout: int (default: 10)
                   - custom_headers: dict
                   - max_depth: int (for crawling plugins)
                   - Any plugin-specific settings
        
        Returns:
            List[VulnerabilityFinding]: List of vulnerabilities found
        """
        pass
    
    # TODO: Add async_scan method in future phase
    # async def async_scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
    #     """Async version of scan method for non-blocking scans"""
    #     pass
    
    def _make_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
        max_retries: int = 2,
    ) -> Optional[Any]:
        """
        Make an HTTP request with optional stealth features and retry logic.

        When ``enable_stealth`` is truthy in *config*, this method:
        - Rotates User-Agent per request via :class:`~scanner.stealth_engine.StealthEngine`
        - Applies a timing jitter delay before sending
        - Merges randomised browser headers with any caller-supplied headers

        Connection errors are retried up to *max_retries* times with a short
        exponential back-off (0.5s, 1s, …). All request details are logged at
        DEBUG level only to avoid noisy INFO output.

        Args:
            url: Target URL.
            method: HTTP method (GET, POST, etc.).
            headers: Optional caller-supplied headers (merged with stealth headers).
            params: Optional URL query parameters.
            data: Optional request body (form-encoded).
            json: Optional request body (JSON).
            config: Plugin configuration dict (used to read ``enable_stealth``,
                    ``timeout``, ``verify_ssl``).
            max_retries: Number of retry attempts on connection error.

        Returns:
            ``requests.Response`` on success, ``None`` if all retries fail or
            ``requests`` is not available.
        """
        if not _HAS_REQUESTS:
            logger.debug("requests library not available; skipping _make_request")
            return None

        cfg = config or {}
        timeout = cfg.get('timeout', 10)
        verify_ssl = cfg.get('verify_ssl', False)
        enable_stealth = cfg.get('enable_stealth', False)

        # Build request headers
        req_headers: Dict[str, str] = {}
        if enable_stealth:
            try:
                from scanner.stealth_engine import StealthEngine
                _stealth = StealthEngine()
                req_headers = _stealth.get_randomized_headers()
                # 0.1–0.5s jitter is intentionally small: it is applied per
                # individual request (not per plugin run) to add subtle timing
                # variation without noticeably slowing down the scan.  The
                # heavier inter-plugin delays are controlled by StealthEngine
                # and the engine-level _apply_stealth_delay() method.
                jitter = random.uniform(0.1, 0.5)
                time.sleep(jitter)
            except Exception as exc:
                logger.debug("Stealth header generation failed: %s", exc)

        # Caller-supplied headers take precedence
        if headers:
            req_headers.update(headers)

        attempt = 0
        delay = 0.5
        while attempt <= max_retries:
            try:
                logger.debug(
                    "_make_request: %s %s (attempt %d/%d)",
                    method.upper(), url, attempt + 1, max_retries + 1,
                )
                response = _requests.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers if req_headers else None,
                    params=params,
                    data=data,
                    json=json,
                    timeout=timeout,
                    verify=verify_ssl,
                )
                return response
            except Exception as exc:
                logger.debug(
                    "_make_request: error on attempt %d for %s: %s",
                    attempt + 1, url, exc,
                )
                attempt += 1
                if attempt <= max_retries:
                    time.sleep(delay)
                    delay *= 2
        return None

    def learn_from_failure(
        self,
        payload: str,
        response: Any,
        failure_type: Optional[str] = None,
        target_url: Optional[str] = None,
    ) -> List[str]:
        """
        Analyse a detection failure (payload didn't trigger a detection signature)
        and return mutated payloads that may bypass the target's input filtering.

        Detection plugins should call this when a payload returns without evidence
        of the vulnerability, to get alternative payloads worth trying next.

        Args:
            payload:      The payload that was tried and did not produce a detection.
            response:     The HTTP response object (or None).  Needs ``.status_code``
                          and ``.text`` attributes if present.
            failure_type: Optional hint about the failure type
                          ('waf', 'filter', 'encoding', 'length', …).
            target_url:   Target URL (used as knowledge-base key). Defaults to the
                          plugin's ``plugin_id`` if not provided.

        Returns:
            List of adapted payload strings to try next.
        """
        if self._adaptive_learner is None:
            return []

        key = target_url or getattr(self, 'plugin_id', 'unknown')
        vuln_types = getattr(self, 'vulnerability_types', [])
        vuln_type = vuln_types[0] if vuln_types else 'unknown'

        status_code: Optional[int] = None
        response_body: Optional[str] = None
        if response is not None:
            status_code = getattr(response, 'status_code', None)
            try:
                response_body = response.text[:500]
            except Exception:
                pass

        return self._adaptive_learner.record_and_adapt(
            target_url=key,
            vuln_type=str(vuln_type),
            failed_payload=payload,
            status_code=status_code,
            response_body=response_body,
            failure_reason=failure_type,
        )

    def get_default_config(self) -> Dict[str, Any]:
        """
        Return default configuration for this plugin.
        
        Returns:
            Dict[str, Any]: Default configuration values
        """
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate plugin configuration.
        
        Args:
            config: Configuration to validate
        
        Returns:
            bool: True if valid, False otherwise
        """
        return True
    
    def get_required_config_keys(self) -> List[str]:
        """
        Return list of required configuration keys.
        
        Returns:
            List[str]: List of required keys
        """
        return []


def create_repeater_request(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a repeater-ready request dictionary for manual testing.
    
    This formats HTTP request data in a copy-paste ready format compatible
    with Megido's repeater app for manual verification.
    
    Args:
        url: Full URL of the request
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: Dictionary of HTTP headers
        body: Request body (for POST/PUT requests)
        description: Optional description of what this request does
    
    Returns:
        Dict containing repeater-compatible request data
    """
    request_data = {
        'url': url,
        'method': method.upper(),
        'headers': headers or {},
        'body': body or '',
    }
    
    if description:
        request_data['description'] = description
    
    return request_data
