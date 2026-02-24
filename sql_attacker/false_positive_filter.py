"""
False Positive Reduction Module for SQL Injection Detection

Implements various techniques to reduce false positives:
- Response similarity analysis
- Baseline comparison (single-sample and multi-sample)
- Multiple payload confirmation
- Content-length variance analysis
- Confidence scoring
- Jitter-aware timing comparisons via BaselineSampler
"""

import hashlib
import re
import difflib
import statistics
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response normalisation helpers (for comparison purposes only)
# ---------------------------------------------------------------------------

_VOLATILE_PATTERNS_FP = [
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'),
    re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    re.compile(r'\b[0-9a-fA-F]{16,}\b'),
    re.compile(r'\b\d{10,13}\b'),
]


def _normalize_for_fp(text: str) -> str:
    """Strip volatile tokens (timestamps, UUIDs, hex blobs) before comparison."""
    for pattern in _VOLATILE_PATTERNS_FP:
        text = pattern.sub('', text)
    return text


# ---------------------------------------------------------------------------
# BaselineSampler
# ---------------------------------------------------------------------------


class BaselineSampler:
    """Multi-sample baseline collector for jitter-aware false-positive reduction.

    Collects 2–3 baseline responses and records timing distribution (mean and
    standard deviation) plus a stable content fingerprint.  The resulting
    statistics are used by :class:`FalsePositiveFilter` to distinguish genuine
    injection signals from normal dynamic-content variation.

    Usage::

        sampler = BaselineSampler(n_samples=3)
        for resp, t in baseline_observations:
            sampler.add_sample(resp.text, t)

        fp_filter = FalsePositiveFilter()
        fp_filter.set_baseline(last_baseline_response, sampler=sampler)

        # Later, when evaluating a probe:
        if fp_filter.is_timing_anomaly(probe_time):
            ...
    """

    def __init__(self, n_samples: int = 3) -> None:
        self._n_samples = max(2, n_samples)
        self._times: List[float] = []
        self._bodies: List[str] = []

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------

    def add_sample(self, response_text: str, response_time: float) -> None:
        """Add one baseline observation.

        Args:
            response_text: Raw HTTP response body text.
            response_time: Elapsed time for this response in seconds.
        """
        self._times.append(response_time)
        self._bodies.append(response_text)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def sample_count(self) -> int:
        """Number of samples collected so far."""
        return len(self._times)

    @property
    def timing_mean(self) -> Optional[float]:
        """Mean of baseline response times, or None if no samples."""
        if not self._times:
            return None
        return statistics.mean(self._times)

    @property
    def timing_stddev(self) -> Optional[float]:
        """Sample standard deviation of baseline response times, or None if < 2 samples."""
        if len(self._times) < 2:
            return None
        return statistics.stdev(self._times)

    @property
    def body_fingerprint(self) -> Optional[str]:
        """16-char SHA-256 hex digest of the most representative normalised body.

        Returns None if no samples have been collected.
        """
        if not self._bodies:
            return None
        normalised = [_normalize_for_fp(b) for b in self._bodies]
        # Use the most common body (or the first if all differ)
        from collections import Counter
        most_common = Counter(normalised).most_common(1)[0][0]
        return hashlib.sha256(most_common.encode('utf-8', errors='replace')).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Jitter-aware checks
    # ------------------------------------------------------------------

    def is_timing_anomaly(self, test_time: float, stddev_multiplier: float = 2.5) -> bool:
        """Return True when *test_time* exceeds the baseline by more than expected jitter.

        The threshold is ``mean + stddev_multiplier * stddev``.  When fewer
        than 2 samples exist (no stddev), falls back to a fixed 4-second
        headroom above the mean.

        Args:
            test_time: Observed response time to evaluate (seconds).
            stddev_multiplier: Number of standard deviations above the mean
                               that constitutes an anomaly.  Default: 2.5.

        Returns:
            True when the timing looks like a genuine time-based delay.
        """
        mean = self.timing_mean
        if mean is None:
            return False
        stddev = self.timing_stddev
        if stddev is None or stddev < 0.05:
            return test_time > (mean + 4.0)
        threshold = mean + stddev_multiplier * stddev
        return test_time > threshold

    def is_content_anomaly(self, test_body: str, similarity_threshold: float = 0.95) -> bool:
        """Return True when *test_body* is substantially different from baseline bodies.

        Uses SequenceMatcher similarity on normalised (volatile-token-stripped)
        bodies.  A result below *similarity_threshold* indicates a meaningful
        content change.

        Args:
            test_body: Response body to evaluate.
            similarity_threshold: Responses more similar than this are considered
                                  unchanged.  Default: 0.95.

        Returns:
            True when the content change is likely significant.
        """
        if not self._bodies:
            return False
        # Use the longest body as the most representative baseline
        baseline_text = max(self._bodies, key=len)
        ratio = difflib.SequenceMatcher(
            None,
            _normalize_for_fp(baseline_text),
            _normalize_for_fp(test_body),
        ).ratio()
        return ratio < similarity_threshold


# ---------------------------------------------------------------------------
# FalsePositiveFilter
# ---------------------------------------------------------------------------


class FalsePositiveFilter:
    """Filter to reduce false positives in SQL injection detection"""
    
    def __init__(self):
        self.baseline_response = None
        self.baseline_length = 0
        self.baseline_status = 0
        self.baseline_headers = {}
        self._sampler: Optional[BaselineSampler] = None

        # Common false positive patterns
        self.false_positive_patterns = [
            r"404.*Not Found",
            r"403.*Forbidden",
            r"400.*Bad Request",
            r"500.*Internal Server Error",
            r"Service Unavailable",
            r"Temporarily Unavailable",
            r"Rate limit exceeded",
            r"Too many requests",
            r"Blocked by.*WAF",
            r"CloudFlare",
            r"Access Denied",
        ]
    
    def set_baseline(self, response, sampler: Optional[BaselineSampler] = None):
        """Set baseline response for comparison.

        Args:
            response: HTTP response object used as the single-sample baseline.
            sampler: Optional :class:`BaselineSampler` containing multi-sample
                     statistics.  When provided, its jitter-aware timing and
                     content-fingerprint data take precedence over single-sample
                     comparisons.
        """
        if response:
            self.baseline_response = response.text
            self.baseline_length = len(response.text)
            self.baseline_status = response.status_code
            self.baseline_headers = dict(response.headers)
            self._sampler = sampler
            logger.info(f"Baseline set: status={self.baseline_status}, length={self.baseline_length}")
    
    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two text responses"""
        if not text1 or not text2:
            return 0.0
        
        # Use difflib's SequenceMatcher for similarity
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()
    
    def is_likely_false_positive(self, response, payload: str) -> bool:
        """
        Determine if a response is likely a false positive
        
        Args:
            response: HTTP response object
            payload: The payload that was used
            
        Returns:
            True if likely false positive, False otherwise
        """
        if not response:
            return True
        
        # Check for common false positive patterns
        for pattern in self.false_positive_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                logger.debug(f"False positive pattern matched: {pattern}")
                return True
        
        # Check if response is too similar to baseline (no change).
        # When a multi-sample BaselineSampler is available, use its normalised
        # content fingerprint for a more jitter-tolerant comparison.
        if self._sampler and self._sampler.sample_count >= 2:
            if not self._sampler.is_content_anomaly(response.text, similarity_threshold=0.95):
                logger.debug("Response not a content anomaly per baseline sampler")
                return True
        elif self.baseline_response:
            similarity = self.calculate_similarity(response.text, self.baseline_response)
            if similarity > 0.95:  # 95% similar = likely not vulnerable
                logger.debug(f"Response too similar to baseline: {similarity:.2%}")
                return True
        
        # Check for WAF block pages
        if self._is_waf_block(response):
            logger.debug("WAF block page detected")
            return True
        
        # Check for generic error pages
        if self._is_generic_error(response):
            logger.debug("Generic error page detected")
            return True
        
        return False
    
    def _is_waf_block(self, response) -> bool:
        """Check if response is a WAF block page"""
        waf_signatures = [
            'cloudflare',
            'incapsula',
            'imperva',
            'sucuri',
            'akamai',
            'blocked by',
            'security policy',
            'access denied',
            'request rejected',
        ]
        
        response_text_lower = response.text.lower()
        for sig in waf_signatures:
            if sig in response_text_lower:
                return True
        
        # Check headers
        waf_headers = ['x-sucuri-id', 'x-cdn', 'x-iinfo', 'server: cloudflare']
        for header, value in response.headers.items():
            header_value = f"{header}: {value}".lower()
            for waf_h in waf_headers:
                if waf_h in header_value:
                    return True
        
        return False
    
    def _is_generic_error(self, response) -> bool:
        """Check if response is a generic error page"""
        # Short responses are often generic errors
        if len(response.text) < 200:
            return True
        
        # Check for generic error status codes without SQL errors
        if response.status_code in [400, 403, 404, 500, 502, 503]:
            # Only consider it generic if it doesn't contain SQL errors
            sql_keywords = ['sql', 'mysql', 'postgres', 'oracle', 'syntax', 'query']
            has_sql_keywords = any(kw in response.text.lower() for kw in sql_keywords)
            if not has_sql_keywords:
                return True
        
        return False
    
    def calculate_confidence_score(self, 
                                   response,
                                   payload: str,
                                   detection_evidence: str,
                                   multiple_payloads_confirmed: bool = False) -> float:
        """
        Calculate confidence score for a SQL injection detection
        
        Args:
            response: HTTP response object
            payload: The payload used
            detection_evidence: Evidence string (e.g., error pattern matched)
            multiple_payloads_confirmed: Whether multiple payloads confirmed the vuln
            
        Returns:
            Confidence score from 0.0 to 1.0
        """
        score = 0.0
        
        # Base score for detection
        score += 0.3
        
        # Bonus for SQL error keywords
        sql_error_keywords = [
            'sql', 'mysql', 'syntax', 'query', 'database',
            'postgres', 'oracle', 'sqlstate', 'warning'
        ]
        keyword_count = sum(1 for kw in sql_error_keywords if kw in response.text.lower())
        score += min(0.2, keyword_count * 0.05)  # Up to 0.2 bonus
        
        # Bonus for specific error patterns
        if 'syntax' in detection_evidence.lower() or 'error' in detection_evidence.lower():
            score += 0.15
        
        # Bonus for database-specific errors
        db_patterns = ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']
        if any(db in response.text.lower() for db in db_patterns):
            score += 0.15
        
        # Major bonus for multiple payload confirmation
        if multiple_payloads_confirmed:
            score += 0.20
        
        # Check response differs significantly from baseline
        if self.baseline_response:
            similarity = self.calculate_similarity(response.text, self.baseline_response)
            if similarity < 0.8:  # Significant difference
                score += 0.10
        
        # Penalty for WAF blocks
        if self._is_waf_block(response):
            score -= 0.3
        
        # Penalty for generic errors
        if self._is_generic_error(response):
            score -= 0.2
        
        # Ensure score is between 0 and 1
        return max(0.0, min(1.0, score))
    
    def confirm_with_multiple_payloads(self, 
                                      test_func,
                                      payloads: List[str],
                                      threshold: int = 2) -> Tuple[bool, List[Dict]]:
        """
        Confirm vulnerability by testing multiple payloads
        
        Args:
            test_func: Function that tests a payload and returns result dict or None
            payloads: List of payloads to test
            threshold: Minimum number of successful payloads to confirm
            
        Returns:
            Tuple of (confirmed, list of successful results)
        """
        successful_results = []
        
        for payload in payloads:
            result = test_func(payload)
            if result and not self.is_likely_false_positive(result.get('response'), payload):
                successful_results.append(result)
                
                # Early exit if threshold reached
                if len(successful_results) >= threshold:
                    break
        
        confirmed = len(successful_results) >= threshold
        logger.info(f"Multi-payload confirmation: {len(successful_results)}/{len(payloads)} successful (threshold={threshold})")
        
        return confirmed, successful_results
    
    def analyze_timing_variance(self, 
                                response_times: List[float], 
                                expected_delay: float = 5.0) -> bool:
        """
        Analyze timing variance to confirm time-based SQLi
        
        Args:
            response_times: List of response times
            expected_delay: Expected delay in seconds
            
        Returns:
            True if timing indicates SQLi, False otherwise
        """
        if not response_times or len(response_times) < 2:
            return False
        
        # Calculate average and standard deviation
        avg_time = sum(response_times) / len(response_times)
        
        # Check if average is close to expected delay
        # Allow 20% variance
        lower_bound = expected_delay * 0.8
        upper_bound = expected_delay * 1.5  # Some overhead is normal
        
        if lower_bound <= avg_time <= upper_bound:
            logger.info(f"Timing analysis: avg={avg_time:.2f}s, expected={expected_delay}s - CONFIRMED")
            return True
        
        logger.info(f"Timing analysis: avg={avg_time:.2f}s, expected={expected_delay}s - NOT CONFIRMED")
        return False
    
    def analyze_content_length_variance(self,
                                       responses: List,
                                       baseline_length: int = None) -> Dict[str, Any]:
        """
        Analyze content length variance across responses
        
        Args:
            responses: List of response objects
            baseline_length: Baseline content length
            
        Returns:
            Dict with analysis results
        """
        if not responses:
            return {'variance_detected': False, 'analysis': 'No responses to analyze'}
        
        lengths = [len(r.text) if r else 0 for r in responses]
        
        if baseline_length is None:
            baseline_length = self.baseline_length
        
        # Calculate variance from baseline
        variances = [abs(l - baseline_length) for l in lengths]
        avg_variance = sum(variances) / len(variances) if variances else 0
        
        # Significant variance = likely vulnerable
        significant_variance = avg_variance > (baseline_length * 0.1)  # 10% variance
        
        return {
            'variance_detected': significant_variance,
            'average_variance': avg_variance,
            'baseline_length': baseline_length,
            'response_lengths': lengths,
            'analysis': f'Average variance: {avg_variance:.0f} bytes from baseline {baseline_length}'
        }

    def is_timing_anomaly(self, test_time: float, expected_delay: float = 5.0) -> bool:
        """Evaluate whether *test_time* represents a genuine time-based injection signal.

        When a :class:`BaselineSampler` with at least 2 samples has been
        attached via :meth:`set_baseline`, the sampler's jitter-aware
        statistics (mean ± 2.5 σ) are used.  Otherwise, falls back to the
        legacy ``analyze_timing_variance`` logic.

        Args:
            test_time: Observed response time in seconds.
            expected_delay: Expected injected delay in seconds (legacy fallback).

        Returns:
            True when the timing is anomalously long.
        """
        if self._sampler and self._sampler.sample_count >= 2:
            return self._sampler.is_timing_anomaly(test_time)
        # Legacy fallback
        return self.analyze_timing_variance([test_time], expected_delay)
