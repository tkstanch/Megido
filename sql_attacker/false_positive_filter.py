"""
False Positive Reduction Module for SQL Injection Detection

Implements various techniques to reduce false positives:
- Response similarity analysis
- Baseline comparison
- Multiple payload confirmation
- Content-length variance analysis
- Confidence scoring
"""

import re
import difflib
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class FalsePositiveFilter:
    """Filter to reduce false positives in SQL injection detection"""
    
    def __init__(self):
        self.baseline_response = None
        self.baseline_length = 0
        self.baseline_status = 0
        self.baseline_headers = {}
        
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
    
    def set_baseline(self, response):
        """Set baseline response for comparison"""
        if response:
            self.baseline_response = response.text
            self.baseline_length = len(response.text)
            self.baseline_status = response.status_code
            self.baseline_headers = dict(response.headers)
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
        
        # Check if response is too similar to baseline (no change)
        if self.baseline_response:
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
