"""
World-Class Confidence Scoring Engine for Vulnerability Detection

This module implements a sophisticated multi-factor confidence scoring system
to reduce false positives and improve detection accuracy across all scanner types.

Features:
- Multi-factor confidence calculation
- Payload validation strength scoring
- Response analysis confidence
- Verification attempt success rate
- Anomaly detection scoring
- Contextual confidence adjustment
"""

import re
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """Confidence level classifications"""
    VERY_HIGH = (90, 100, "Very High")  # Verified exploitation
    HIGH = (75, 89, "High")  # Strong evidence
    MEDIUM = (50, 74, "Medium")  # Probable
    LOW = (25, 49, "Low")  # Possible
    VERY_LOW = (0, 24, "Very Low")  # Unlikely
    
    def __init__(self, min_score, max_score, label):
        self.min_score = min_score
        self.max_score = max_score
        self.label = label
    
    @classmethod
    def from_score(cls, score: float) -> 'ConfidenceLevel':
        """Get confidence level from score"""
        for level in cls:
            if level.min_score <= score <= level.max_score:
                return level
        return cls.VERY_LOW


@dataclass
class ConfidenceFactors:
    """Individual confidence factors for a finding"""
    payload_effectiveness: float = 0.0  # 0-1: How well payload performed
    response_anomaly: float = 0.0  # 0-1: Response differs from baseline
    verification_success: float = 0.0  # 0-1: Verification attempts succeeded
    pattern_specificity: float = 0.0  # 0-1: How specific the detection pattern is
    context_relevance: float = 0.0  # 0-1: Context supports vulnerability
    error_signature: float = 0.0  # 0-1: Error signatures match expected
    timing_analysis: float = 0.0  # 0-1: Timing-based confirmation
    consistency_check: float = 0.0  # 0-1: Multiple checks consistent
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary"""
        return {
            'payload_effectiveness': self.payload_effectiveness,
            'response_anomaly': self.response_anomaly,
            'verification_success': self.verification_success,
            'pattern_specificity': self.pattern_specificity,
            'context_relevance': self.context_relevance,
            'error_signature': self.error_signature,
            'timing_analysis': self.timing_analysis,
            'consistency_check': self.consistency_check,
        }


@dataclass
class ConfidenceScore:
    """Complete confidence score for a finding"""
    raw_score: float  # 0-100
    normalized_score: float  # 0-100
    confidence_level: ConfidenceLevel
    factors: ConfidenceFactors
    adjustments: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self):
        return f"{self.confidence_level.label} ({self.normalized_score:.1f}/100)"


class ConfidenceEngine:
    """
    Engine for calculating multi-factor confidence scores.
    
    This engine uses weighted factors to calculate an overall confidence
    score that indicates the likelihood that a finding is a true positive.
    """
    
    # Default weights for confidence factors
    DEFAULT_WEIGHTS = {
        'payload_effectiveness': 0.25,
        'response_anomaly': 0.20,
        'verification_success': 0.20,
        'pattern_specificity': 0.10,
        'context_relevance': 0.10,
        'error_signature': 0.05,
        'timing_analysis': 0.05,
        'consistency_check': 0.05,
    }
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize confidence engine.
        
        Args:
            weights: Custom weights for factors (optional)
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._normalize_weights()
    
    def _normalize_weights(self):
        """Ensure weights sum to 1.0"""
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}
    
    def calculate_confidence(self, 
                            factors: ConfidenceFactors,
                            vulnerability_type: str = None,
                            metadata: Dict[str, Any] = None) -> ConfidenceScore:
        """
        Calculate overall confidence score from factors.
        
        Args:
            factors: Individual confidence factors
            vulnerability_type: Type of vulnerability (for type-specific adjustments)
            metadata: Additional metadata for contextual adjustments
            
        Returns:
            ConfidenceScore with calculated confidence
        """
        metadata = metadata or {}
        
        # Calculate weighted score
        raw_score = 0.0
        factor_dict = factors.to_dict()
        
        for factor_name, factor_value in factor_dict.items():
            weight = self.weights.get(factor_name, 0.0)
            raw_score += factor_value * weight * 100
        
        # Apply vulnerability-specific adjustments
        adjustments = {}
        adjusted_score = raw_score
        
        if vulnerability_type:
            adjustment = self._get_type_adjustment(vulnerability_type, factors, metadata)
            adjustments['type_specific'] = adjustment
            adjusted_score += adjustment
        
        # Apply contextual adjustments
        context_adj = self._get_context_adjustment(factors, metadata)
        if context_adj != 0:
            adjustments['contextual'] = context_adj
            adjusted_score += context_adj
        
        # Normalize to 0-100 range
        normalized_score = max(0.0, min(100.0, adjusted_score))
        
        # Determine confidence level
        confidence_level = ConfidenceLevel.from_score(normalized_score)
        
        return ConfidenceScore(
            raw_score=raw_score,
            normalized_score=normalized_score,
            confidence_level=confidence_level,
            factors=factors,
            adjustments=adjustments,
            metadata=metadata
        )
    
    def _get_type_adjustment(self, 
                            vuln_type: str,
                            factors: ConfidenceFactors,
                            metadata: Dict[str, Any]) -> float:
        """
        Get vulnerability type-specific confidence adjustment.
        
        Different vulnerability types have different characteristics
        that affect confidence scoring.
        """
        vuln_type = vuln_type.lower()
        
        # XSS: High payload effectiveness + verification = high confidence boost
        if 'xss' in vuln_type:
            if factors.payload_effectiveness > 0.8 and factors.verification_success > 0.8:
                return 10.0
            elif factors.payload_effectiveness > 0.6:
                return 5.0
        
        # SQL Injection: Error signatures are very indicative
        elif 'sql' in vuln_type or 'sqli' in vuln_type:
            if factors.error_signature > 0.8:
                return 10.0
            elif factors.error_signature > 0.5:
                return 5.0
        
        # Command Injection: Timing analysis is crucial
        elif 'command' in vuln_type or 'rce' in vuln_type:
            if factors.timing_analysis > 0.8:
                return 10.0
        
        # SSRF: Context relevance is important
        elif 'ssrf' in vuln_type:
            if factors.context_relevance > 0.7:
                return 7.0
        
        return 0.0
    
    def _get_context_adjustment(self,
                               factors: ConfidenceFactors,
                               metadata: Dict[str, Any]) -> float:
        """
        Get contextual confidence adjustments.
        
        Various contextual factors can increase or decrease confidence.
        """
        adjustment = 0.0
        
        # If verified through actual exploitation, big boost
        if metadata.get('verified', False):
            adjustment += 15.0
        
        # If WAF detected, reduce confidence (may be blocking)
        if metadata.get('waf_detected', False):
            adjustment -= 10.0
        
        # If rate limited, reduce confidence
        if metadata.get('rate_limited', False):
            adjustment -= 15.0
        
        # If multiple payloads succeeded, increase confidence
        successful_payloads = metadata.get('successful_payloads', 0)
        if successful_payloads > 3:
            adjustment += 5.0
        elif successful_payloads > 1:
            adjustment += 2.0
        
        # If response time anomaly detected
        if metadata.get('timing_anomaly', False):
            adjustment += 3.0
        
        # If similar to known false positive patterns
        if metadata.get('matches_fp_pattern', False):
            adjustment -= 20.0
        
        return adjustment
    
    def calculate_payload_effectiveness(self,
                                       payload: str,
                                       response: Any,
                                       expected_indicators: List[str]) -> float:
        """
        Calculate how effective a payload was.
        
        Args:
            payload: The payload that was used
            response: Response object or text
            expected_indicators: Expected indicators of success
            
        Returns:
            Effectiveness score (0-1)
        """
        if not response:
            return 0.0
        
        # Get response text
        response_text = str(response.text if hasattr(response, 'text') else response)
        
        # Check for payload reflection
        payload_reflected = payload in response_text
        
        # Check for expected indicators
        indicators_found = sum(1 for ind in expected_indicators 
                              if ind.lower() in response_text.lower())
        indicator_ratio = indicators_found / len(expected_indicators) if expected_indicators else 0.0
        
        # Check for error messages
        error_patterns = [
            r'error', r'exception', r'warning', r'failed',
            r'syntax', r'unexpected', r'invalid'
        ]
        errors_found = sum(1 for pattern in error_patterns 
                          if re.search(pattern, response_text, re.IGNORECASE))
        error_score = min(errors_found / 3.0, 1.0)
        
        # Combine scores
        effectiveness = 0.0
        if payload_reflected:
            effectiveness += 0.3
        effectiveness += indicator_ratio * 0.5
        effectiveness += error_score * 0.2
        
        return min(1.0, effectiveness)
    
    def calculate_response_anomaly(self,
                                   baseline_response: Any,
                                   test_response: Any) -> float:
        """
        Calculate how anomalous a response is compared to baseline.
        
        Args:
            baseline_response: Baseline/normal response
            test_response: Response to test
            
        Returns:
            Anomaly score (0-1), higher means more different
        """
        if not baseline_response or not test_response:
            return 0.0
        
        baseline_text = str(baseline_response.text if hasattr(baseline_response, 'text') 
                           else baseline_response)
        test_text = str(test_response.text if hasattr(test_response, 'text') 
                       else test_response)
        
        # Length difference
        length_diff = abs(len(test_text) - len(baseline_text)) / max(len(baseline_text), 1)
        length_score = min(length_diff, 1.0)
        
        # Status code difference
        baseline_status = getattr(baseline_response, 'status_code', 200)
        test_status = getattr(test_response, 'status_code', 200)
        status_different = 1.0 if baseline_status != test_status else 0.0
        
        # Content similarity (simple approach)
        # More sophisticated: use difflib or Levenshtein distance
        common_chars = len(set(baseline_text) & set(test_text))
        total_chars = len(set(baseline_text) | set(test_text))
        similarity = common_chars / total_chars if total_chars > 0 else 1.0
        difference_score = 1.0 - similarity
        
        # Combine scores
        anomaly = (length_score * 0.3 + status_different * 0.4 + difference_score * 0.3)
        
        return min(1.0, anomaly)
    
    def calculate_pattern_specificity(self, pattern: str) -> float:
        """
        Calculate how specific a detection pattern is.
        
        More specific patterns have higher confidence.
        
        Args:
            pattern: Detection pattern (regex or string)
            
        Returns:
            Specificity score (0-1)
        """
        if not pattern:
            return 0.0
        
        # Longer patterns are generally more specific
        length_score = min(len(pattern) / 100.0, 0.5)
        
        # Patterns with special characters are more specific
        special_chars = sum(1 for c in pattern if not c.isalnum() and c != ' ')
        special_score = min(special_chars / 20.0, 0.3)
        
        # Patterns with word boundaries are more specific
        word_boundaries = pattern.count(r'\b')
        boundary_score = min(word_boundaries / 4.0, 0.2)
        
        specificity = length_score + special_score + boundary_score
        
        return min(1.0, specificity)


class ResponseAnalyzer:
    """
    Analyzer for determining if responses indicate vulnerabilities.
    """
    
    # Common false positive indicators
    FALSE_POSITIVE_PATTERNS = [
        r'404.*not\s+found',
        r'403.*forbidden',
        r'400.*bad\s+request',
        r'500.*internal\s+server\s+error',
        r'503.*service\s+unavailable',
        r'rate\s+limit\s+exceeded',
        r'too\s+many\s+requests',
        r'blocked\s+by.*waf',
        r'cloudflare',
        r'access\s+denied',
        r'temporarily\s+unavailable',
    ]
    
    # WAF/Security product signatures
    WAF_SIGNATURES = [
        r'cloudflare', r'incapsula', r'akamai', r'sucuri',
        r'mod_security', r'barracuda', r'imperva',
        r'f5\s+networks', r'fortinet', r'palo\s+alto'
    ]
    
    def __init__(self):
        """Initialize response analyzer"""
        self.false_positive_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.FALSE_POSITIVE_PATTERNS
        ]
        self.waf_signatures = [
            re.compile(s, re.IGNORECASE) for s in self.WAF_SIGNATURES
        ]
    
    def is_likely_false_positive(self, response: Any) -> bool:
        """
        Check if response indicates a false positive.
        
        Args:
            response: Response object or text
            
        Returns:
            True if likely false positive
        """
        if not response:
            return True
        
        response_text = str(response.text if hasattr(response, 'text') else response)
        
        # Check false positive patterns
        for pattern in self.false_positive_patterns:
            if pattern.search(response_text):
                logger.debug(f"False positive pattern matched: {pattern.pattern}")
                return True
        
        return False
    
    def detect_waf(self, response: Any) -> bool:
        """
        Detect if a WAF is present in the response.
        
        Args:
            response: Response object or text
            
        Returns:
            True if WAF detected
        """
        if not response:
            return False
        
        response_text = str(response.text if hasattr(response, 'text') else response)
        headers = getattr(response, 'headers', {})
        
        # Check response text
        for signature in self.waf_signatures:
            if signature.search(response_text):
                return True
        
        # Check headers
        waf_headers = ['x-waf', 'x-cdn', 'server', 'x-sucuri-id', 'x-firewall']
        for header in waf_headers:
            if header in headers:
                for signature in self.waf_signatures:
                    if signature.search(str(headers[header])):
                        return True
        
        return False
    
    def detect_rate_limiting(self, response: Any) -> bool:
        """
        Detect if response indicates rate limiting.
        
        Args:
            response: Response object or text
            
        Returns:
            True if rate limited
        """
        if not response:
            return False
        
        status_code = getattr(response, 'status_code', 0)
        
        # Check status code
        if status_code == 429:  # Too Many Requests
            return True
        
        response_text = str(response.text if hasattr(response, 'text') else response)
        
        # Check response text
        rate_limit_patterns = [
            r'rate\s+limit',
            r'too\s+many\s+requests',
            r'throttled',
            r'quota\s+exceeded'
        ]
        
        for pattern in rate_limit_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False


# Helper function for easy integration
def calculate_finding_confidence(finding: Dict[str, Any],
                                 engine: Optional[ConfidenceEngine] = None) -> ConfidenceScore:
    """
    Calculate confidence score for a finding.
    
    This is a convenience function that extracts factors from a finding
    dictionary and calculates the confidence score.
    
    Args:
        finding: Finding dictionary
        engine: Optional ConfidenceEngine instance
        
    Returns:
        ConfidenceScore object
    """
    if engine is None:
        engine = ConfidenceEngine()
    
    # Extract or calculate factors from finding
    factors = ConfidenceFactors(
        payload_effectiveness=finding.get('payload_effectiveness', 0.5),
        response_anomaly=finding.get('response_anomaly', 0.5),
        verification_success=1.0 if finding.get('verified', False) else 0.0,
        pattern_specificity=finding.get('pattern_specificity', 0.5),
        context_relevance=finding.get('context_relevance', 0.5),
        error_signature=finding.get('error_signature', 0.0),
        timing_analysis=finding.get('timing_analysis', 0.0),
        consistency_check=finding.get('consistency_check', 0.5),
    )
    
    # Extract metadata
    metadata = {
        'verified': finding.get('verified', False),
        'waf_detected': finding.get('waf_detected', False),
        'rate_limited': finding.get('rate_limited', False),
        'successful_payloads': finding.get('successful_payloads', 0),
        'timing_anomaly': finding.get('timing_anomaly', False),
        'matches_fp_pattern': finding.get('matches_fp_pattern', False),
    }
    
    return engine.calculate_confidence(
        factors=factors,
        vulnerability_type=finding.get('type', finding.get('vulnerability_type')),
        metadata=metadata
    )
