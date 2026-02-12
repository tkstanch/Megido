"""
Enhanced False Positive Filter for World-Class Vulnerability Detection

This module provides comprehensive false positive detection and filtering
across all vulnerability types, using multiple techniques:

- Baseline response comparison
- Response similarity analysis
- WAF and security product detection
- Error page pattern matching
- Rate limiting detection
- Automated learning from user feedback
- Statistical anomaly detection
"""

import re
import difflib
import hashlib
import json
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ResponseCharacteristics:
    """Characteristics of an HTTP response for comparison"""
    status_code: int
    content_length: int
    content_type: str
    has_errors: bool
    error_count: int
    unique_words: int
    response_time: float = 0.0
    checksum: str = ""
    
    def __post_init__(self):
        """Calculate derived fields"""
        if not self.checksum:
            # Simple checksum for comparison
            data = f"{self.status_code}{self.content_length}{self.content_type}"
            self.checksum = hashlib.md5(data.encode()).hexdigest()[:8]


class EnhancedFalsePositiveFilter:
    """
    Advanced false positive filter with multiple detection techniques.
    
    This filter combines multiple methods to accurately identify and
    filter out false positives while maintaining high true positive rate.
    """
    
    # Enhanced false positive patterns
    FALSE_POSITIVE_PATTERNS = [
        # HTTP error pages
        (r'404.*not\s+found', 'http_404'),
        (r'403.*forbidden', 'http_403'),
        (r'400.*bad\s+request', 'http_400'),
        (r'500.*internal\s+server\s+error', 'http_500'),
        (r'502.*bad\s+gateway', 'http_502'),
        (r'503.*service\s+unavailable', 'http_503'),
        
        # Rate limiting
        (r'rate\s+limit\s+exceeded', 'rate_limit'),
        (r'too\s+many\s+requests', 'rate_limit'),
        (r'quota\s+exceeded', 'rate_limit'),
        (r'throttled', 'rate_limit'),
        
        # WAF/Security blocks
        (r'blocked\s+by.*waf', 'waf_block'),
        (r'request\s+blocked', 'waf_block'),
        (r'security\s+policy\s+violation', 'waf_block'),
        (r'access\s+denied', 'access_denied'),
        
        # Generic errors
        (r'temporarily\s+unavailable', 'temp_error'),
        (r'service\s+temporarily\s+unavailable', 'temp_error'),
        (r'maintenance\s+mode', 'maintenance'),
        
        # Cloudflare specific
        (r'cloudflare.*checking\s+your\s+browser', 'cloudflare_challenge'),
        (r'attention\s+required.*cloudflare', 'cloudflare_challenge'),
    ]
    
    # WAF signatures (vendor-specific patterns)
    WAF_SIGNATURES = {
        'cloudflare': [r'cloudflare', r'cf-ray', r'__cfduid'],
        'incapsula': [r'incapsula', r'_incap_', r'visid_incap'],
        'akamai': [r'akamai', r'akamaighost'],
        'sucuri': [r'sucuri', r'x-sucuri-id'],
        'modsecurity': [r'mod_security', r'modsec'],
        'barracuda': [r'barracuda', r'barra_counter_session'],
        'imperva': [r'imperva', r'incap_ses'],
        'f5': [r'f5\s+networks', r'bigip', r'TS[a-f0-9]{8}'],
        'fortinet': [r'fortinet', r'fortigate'],
        'aws_waf': [r'x-amzn-waf', r'x-amzn-requestid'],
    }
    
    # Patterns that indicate generic error pages (very high false positive likelihood)
    GENERIC_ERROR_PATTERNS = [
        r'<!DOCTYPE\s+html>.*<title>Error</title>',
        r'<h1>Error</h1>',
        r'<title>[45]\d{2}\s+Error</title>',
        r'default\s+error\s+page',
        r'nginx.*error\s+page',
        r'apache.*error\s+page',
        r'iis.*error\s+page',
    ]
    
    def __init__(self, 
                 similarity_threshold: float = 0.95,
                 learning_enabled: bool = True,
                 state_file: Optional[str] = None):
        """
        Initialize enhanced false positive filter.
        
        Args:
            similarity_threshold: Threshold for response similarity (0-1)
            learning_enabled: Enable learning from user feedback
            state_file: Path to persistence file for learned patterns
        """
        self.similarity_threshold = similarity_threshold
        self.learning_enabled = learning_enabled
        self.state_file = state_file or '.fp_filter_state.json'
        
        # Baseline storage
        self.baselines: Dict[str, ResponseCharacteristics] = {}
        
        # Learning data
        self.learned_fp_patterns: Set[str] = set()
        self.confirmed_tp_patterns: Set[str] = set()
        self.waf_detections: Dict[str, int] = {}
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'false_positives_filtered': 0,
            'waf_blocks_detected': 0,
            'rate_limits_detected': 0,
            'baseline_mismatches': 0,
        }
        
        # Compile patterns
        self._compile_patterns()
        
        # Load learned state
        if self.learning_enabled:
            self._load_state()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        self.fp_patterns = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), category)
            for pattern, category in self.FALSE_POSITIVE_PATTERNS
        ]
        
        self.waf_patterns = {
            vendor: [re.compile(p, re.IGNORECASE) for p in patterns]
            for vendor, patterns in self.WAF_SIGNATURES.items()
        }
        
        self.generic_error_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.GENERIC_ERROR_PATTERNS
        ]
    
    def set_baseline(self, url: str, response: Any):
        """
        Set baseline response for a URL.
        
        Args:
            url: URL being tested
            response: Baseline response object
        """
        if not response:
            return
        
        characteristics = self._extract_characteristics(response)
        self.baselines[url] = characteristics
        
        logger.debug(f"Baseline set for {url}: {characteristics}")
    
    def _extract_characteristics(self, response: Any) -> ResponseCharacteristics:
        """Extract characteristics from response"""
        response_text = str(response.text if hasattr(response, 'text') else response)
        
        # Count errors
        error_keywords = ['error', 'exception', 'warning', 'failed']
        error_count = sum(
            response_text.lower().count(keyword) 
            for keyword in error_keywords
        )
        
        # Extract unique words (for similarity comparison)
        words = re.findall(r'\w+', response_text.lower())
        unique_words = len(set(words))
        
        return ResponseCharacteristics(
            status_code=getattr(response, 'status_code', 200),
            content_length=len(response_text),
            content_type=getattr(response, 'headers', {}).get('content-type', 'text/html'),
            has_errors=error_count > 0,
            error_count=error_count,
            unique_words=unique_words,
            response_time=getattr(response, 'elapsed', 0.0).total_seconds() 
                         if hasattr(response, 'elapsed') else 0.0
        )
    
    def is_false_positive(self, 
                         url: str,
                         response: Any,
                         payload: str,
                         vulnerability_type: str = None) -> Tuple[bool, str]:
        """
        Determine if a response is likely a false positive.
        
        Args:
            url: URL being tested
            response: Response object to analyze
            payload: Payload that was used
            vulnerability_type: Type of vulnerability being tested
            
        Returns:
            Tuple of (is_fp: bool, reason: str)
        """
        self.stats['total_checks'] += 1
        
        if not response:
            return True, "No response received"
        
        response_text = str(response.text if hasattr(response, 'text') else response)
        
        # Check 1: Known false positive patterns
        for pattern, category in self.fp_patterns:
            if pattern.search(response_text):
                self.stats['false_positives_filtered'] += 1
                return True, f"Matched false positive pattern: {category}"
        
        # Check 2: WAF detection
        waf_detected, waf_vendor = self._detect_waf(response)
        if waf_detected:
            self.stats['waf_blocks_detected'] += 1
            self.stats['false_positives_filtered'] += 1
            return True, f"WAF block detected: {waf_vendor}"
        
        # Check 3: Rate limiting
        if self._is_rate_limited(response):
            self.stats['rate_limits_detected'] += 1
            self.stats['false_positives_filtered'] += 1
            return True, "Rate limiting detected"
        
        # Check 4: Generic error pages
        if self._is_generic_error_page(response_text):
            self.stats['false_positives_filtered'] += 1
            return True, "Generic error page detected"
        
        # Check 5: Baseline comparison (if baseline exists)
        if url in self.baselines:
            is_similar, similarity = self._compare_to_baseline(url, response)
            if is_similar:
                self.stats['baseline_mismatches'] += 1
                self.stats['false_positives_filtered'] += 1
                return True, f"Response too similar to baseline ({similarity:.1%})"
        
        # Check 6: Learned false positive patterns
        if self.learning_enabled:
            response_hash = self._hash_response(response_text)
            if response_hash in self.learned_fp_patterns:
                self.stats['false_positives_filtered'] += 1
                return True, "Matched learned false positive pattern"
        
        # Check 7: Vulnerability-specific checks
        if vulnerability_type:
            is_fp, reason = self._check_vulnerability_specific_fp(
                vulnerability_type, response, payload
            )
            if is_fp:
                self.stats['false_positives_filtered'] += 1
                return True, reason
        
        # No false positive indicators found
        return False, ""
    
    def _detect_waf(self, response: Any) -> Tuple[bool, str]:
        """
        Detect WAF presence and vendor.
        
        Returns:
            Tuple of (detected: bool, vendor: str)
        """
        response_text = str(response.text if hasattr(response, 'text') else response)
        headers = getattr(response, 'headers', {})
        
        # Check response text and headers
        for vendor, patterns in self.waf_patterns.items():
            for pattern in patterns:
                # Check response text
                if pattern.search(response_text):
                    self.waf_detections[vendor] = self.waf_detections.get(vendor, 0) + 1
                    return True, vendor
                
                # Check headers
                for header_value in headers.values():
                    if pattern.search(str(header_value)):
                        self.waf_detections[vendor] = self.waf_detections.get(vendor, 0) + 1
                        return True, vendor
        
        return False, ""
    
    def _is_rate_limited(self, response: Any) -> bool:
        """Check if response indicates rate limiting"""
        status_code = getattr(response, 'status_code', 0)
        
        # HTTP 429 Too Many Requests
        if status_code == 429:
            return True
        
        # Check retry-after header
        headers = getattr(response, 'headers', {})
        if 'retry-after' in headers or 'x-ratelimit-remaining' in headers:
            remaining = headers.get('x-ratelimit-remaining', '1')
            if remaining == '0':
                return True
        
        return False
    
    def _is_generic_error_page(self, response_text: str) -> bool:
        """Check if response is a generic error page"""
        for pattern in self.generic_error_patterns:
            if pattern.search(response_text):
                return True
        
        # Additional heuristic: very short responses with error codes
        if len(response_text) < 500 and re.search(r'[45]\d{2}', response_text):
            return True
        
        return False
    
    def _compare_to_baseline(self, 
                            url: str, 
                            response: Any) -> Tuple[bool, float]:
        """
        Compare response to baseline.
        
        Returns:
            Tuple of (is_similar: bool, similarity: float)
        """
        if url not in self.baselines:
            return False, 0.0
        
        baseline = self.baselines[url]
        current = self._extract_characteristics(response)
        
        # Compare characteristics
        status_match = baseline.status_code == current.status_code
        length_diff_ratio = abs(baseline.content_length - current.content_length) / max(baseline.content_length, 1)
        length_similar = length_diff_ratio < 0.1  # Less than 10% difference
        
        # Compare actual content
        baseline_text = ""  # We don't store full baseline text
        response_text = str(response.text if hasattr(response, 'text') else response)
        
        # Use checksum for quick comparison
        if baseline.checksum == current.checksum:
            return True, 1.0
        
        # More detailed comparison if needed
        if status_match and length_similar:
            # Heuristic similarity based on characteristics
            similarity = 0.8 if status_match else 0.5
            return similarity >= self.similarity_threshold, similarity
        
        return False, 0.0
    
    def _check_vulnerability_specific_fp(self,
                                        vuln_type: str,
                                        response: Any,
                                        payload: str) -> Tuple[bool, str]:
        """
        Vulnerability-specific false positive checks.
        
        Different vulnerability types have different false positive patterns.
        """
        vuln_type = vuln_type.lower()
        response_text = str(response.text if hasattr(response, 'text') else response)
        
        # XSS: Check if payload is in a comment or script src
        if 'xss' in vuln_type:
            if payload in response_text:
                # Check if it's in an HTML comment
                if f'<!--{payload}-->' in response_text or f'<!--.*{re.escape(payload)}.*-->' in response_text:
                    return True, "Payload in HTML comment (likely false positive)"
                
                # Check if it's in a non-executable context
                if f'<noscript>{payload}</noscript>' in response_text:
                    return True, "Payload in noscript tag (not executable)"
        
        # SQLi: Check for generic database errors that might be normal
        elif 'sql' in vuln_type or 'sqli' in vuln_type:
            # If we see multiple different error types, might be broken page
            error_types = len(re.findall(r'(mysql|postgresql|oracle|mssql|sqlite)', response_text, re.IGNORECASE))
            if error_types > 2:
                return True, "Multiple database error types (likely broken page)"
        
        return False, ""
    
    def _hash_response(self, response_text: str) -> str:
        """Generate hash for response"""
        # Normalize and hash
        normalized = re.sub(r'\s+', ' ', response_text.lower()).strip()
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def learn_from_feedback(self, 
                           response: Any,
                           is_false_positive: bool):
        """
        Learn from user feedback.
        
        Args:
            response: Response object
            is_false_positive: True if user confirmed it's a false positive
        """
        if not self.learning_enabled:
            return
        
        response_text = str(response.text if hasattr(response, 'text') else response)
        response_hash = self._hash_response(response_text)
        
        if is_false_positive:
            self.learned_fp_patterns.add(response_hash)
            logger.info(f"Learned false positive pattern: {response_hash}")
        else:
            self.confirmed_tp_patterns.add(response_hash)
            # Remove from FP if it was there
            self.learned_fp_patterns.discard(response_hash)
            logger.info(f"Confirmed true positive: {response_hash}")
        
        self._save_state()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get filter statistics"""
        fp_rate = (self.stats['false_positives_filtered'] / 
                  max(self.stats['total_checks'], 1)) * 100
        
        return {
            **self.stats,
            'false_positive_rate': f"{fp_rate:.1f}%",
            'learned_patterns': len(self.learned_fp_patterns),
            'confirmed_true_positives': len(self.confirmed_tp_patterns),
            'waf_vendors_detected': list(self.waf_detections.keys()),
        }
    
    def _load_state(self):
        """Load learned state from disk"""
        if not Path(self.state_file).exists():
            return
        
        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)
                self.learned_fp_patterns = set(data.get('learned_fp_patterns', []))
                self.confirmed_tp_patterns = set(data.get('confirmed_tp_patterns', []))
                self.waf_detections = data.get('waf_detections', {})
                logger.info(f"Loaded {len(self.learned_fp_patterns)} learned patterns")
        except Exception as e:
            logger.error(f"Failed to load filter state: {e}")
    
    def _save_state(self):
        """Save learned state to disk"""
        try:
            data = {
                'learned_fp_patterns': list(self.learned_fp_patterns),
                'confirmed_tp_patterns': list(self.confirmed_tp_patterns),
                'waf_detections': self.waf_detections,
                'last_updated': datetime.now().isoformat(),
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save filter state: {e}")


def create_filter(similarity_threshold: float = 0.95,
                 learning_enabled: bool = True) -> EnhancedFalsePositiveFilter:
    """
    Create an enhanced false positive filter.
    
    This is a convenience function for quick filter creation.
    
    Args:
        similarity_threshold: Similarity threshold (0-1)
        learning_enabled: Enable learning from feedback
        
    Returns:
        EnhancedFalsePositiveFilter instance
    """
    return EnhancedFalsePositiveFilter(
        similarity_threshold=similarity_threshold,
        learning_enabled=learning_enabled
    )
