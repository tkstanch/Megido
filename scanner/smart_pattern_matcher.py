"""
Smart Pattern Matching Engine for Accurate Vulnerability Detection

This module provides intelligent pattern matching that reduces false positives:
- Entropy analysis for secrets (detect real vs example keys)
- Negative lookaheads to exclude common false positives
- Validation algorithms (Luhn for credit cards, checksums, etc.)
- Context-aware pattern matching
- Domain whitelisting for SSRF/redirect detection

Author: Megido Team
Version: 1.0.0
"""

import re
import math
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass
from collections import Counter

logger = logging.getLogger(__name__)


class EntropyAnalyzer:
    """
    Analyze entropy of strings to distinguish real secrets from examples.
    
    Real secrets typically have high entropy (random-looking).
    Example/placeholder secrets have low entropy (patterns like "aaaaa", "12345").
    """
    
    # Common placeholder patterns (low entropy)
    PLACEHOLDER_PATTERNS = [
        r'^[a-z]+$',  # All same char: aaaaa
        r'^[0-9]+$',  # Sequential: 12345
        r'^(test|demo|example|sample|fake|dummy)',  # Test data
        r'(YOUR_|MY_|SAMPLE_)',  # Placeholder markers
        r'^x+$',  # xxx...
    ]
    
    MIN_ENTROPY_THRESHOLD = 3.5  # Minimum entropy for real secrets
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """
        Calculate Shannon entropy of string.
        
        Args:
            data: String to analyze
            
        Returns:
            Entropy value (higher = more random)
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        freq = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    @classmethod
    def is_likely_real_secret(cls, value: str) -> Tuple[bool, str]:
        """
        Determine if value is likely a real secret vs placeholder.
        
        Args:
            value: Value to analyze
            
        Returns:
            Tuple of (is_real, reason)
        """
        if len(value) < 8:
            return False, "Too short to be a valid secret"
        
        # Check for placeholder patterns
        for pattern in cls.PLACEHOLDER_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                return False, f"Matches placeholder pattern: {pattern}"
        
        # Calculate entropy
        entropy = cls.calculate_entropy(value)
        
        if entropy < cls.MIN_ENTROPY_THRESHOLD:
            return False, f"Low entropy: {entropy:.2f} (threshold: {cls.MIN_ENTROPY_THRESHOLD})"
        
        # Check for repeating patterns
        if len(set(value)) < len(value) * 0.5:  # Less than 50% unique characters
            return False, "Too many repeated characters"
        
        return True, f"High entropy: {entropy:.2f}"


class LuhnValidator:
    """
    Validate credit card numbers using Luhn algorithm.
    
    This significantly reduces false positives for credit card detection.
    """
    
    @staticmethod
    def validate(card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        
        Args:
            card_number: Card number string (digits only)
            
        Returns:
            True if valid Luhn checksum
        """
        # Remove non-digits
        digits = re.sub(r'\D', '', card_number)
        
        if len(digits) < 13 or len(digits) > 19:
            return False
        
        # Luhn algorithm
        total = 0
        reverse_digits = digits[::-1]
        
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            
            if i % 2 == 1:  # Every second digit
                n = n * 2
                if n > 9:
                    n = n - 9
            
            total += n
        
        return total % 10 == 0


class SmartPatternMatcher:
    """
    Intelligent pattern matching with validation and context awareness.
    """
    
    # Known safe domains for SSRF/redirect checks
    SAFE_DOMAINS = {
        # CDNs
        'cloudflare.com', 'cloudfront.net', 'fastly.net', 'akamai.net',
        'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
        
        # APIs
        'googleapis.com', 'api.github.com', 'graph.microsoft.com',
        
        # Social media
        'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
        
        # Common embeds
        'youtube.com', 'youtu.be', 'vimeo.com', 'soundcloud.com',
        
        # Payment processors
        'stripe.com', 'paypal.com', 'square.com',
        
        # Maps
        'maps.google.com', 'maps.googleapis.com', 'openstreetmap.org',
    }
    
    # Enhanced patterns with negative lookaheads
    ENHANCED_PATTERNS = {
        'api_key': {
            'pattern': r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']?([a-z0-9_\-]{20,})',
            'exclude': [r'YOUR_API_KEY', r'SAMPLE', r'EXAMPLE', r'TEST'],
            'min_entropy': 3.5,
            'validate_func': None,
        },
        'aws_access_key': {
            'pattern': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'exclude': [r'AKIAIOSFODNN7EXAMPLE'],  # AWS example key
            'min_entropy': 4.0,
            'validate_func': lambda x: x.startswith(('AKIA', 'ASIA', 'AGPA')),
        },
        'credit_card': {
            'pattern': r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
            'exclude': [r'0000', r'1111', r'1234', r'4444'],
            'min_entropy': 2.0,
            'validate_func': LuhnValidator.validate,
        },
        'jwt_token': {
            'pattern': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'exclude': [r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'],  # Example JWT
            'min_entropy': 4.0,
            'validate_func': lambda x: len(x.split('.')) == 3,
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            'exclude': [r'EXAMPLE', r'SAMPLE'],
            'min_entropy': 0,  # Don't check entropy for PEM headers
            'validate_func': None,
        },
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize smart pattern matcher.
        
        Args:
            config: Configuration dictionary
        """
        config = config or {}
        
        self.entropy_analyzer = EntropyAnalyzer()
        self.luhn_validator = LuhnValidator()
        
        # Configuration
        self.enable_entropy_check = config.get('enable_entropy_check', True)
        self.enable_validation = config.get('enable_validation', True)
        self.custom_safe_domains = set(config.get('safe_domains', []))
        self.all_safe_domains = self.SAFE_DOMAINS | self.custom_safe_domains
        
        # Statistics
        self.matches_found = 0
        self.false_positives_filtered = 0
        self.validations_performed = 0
        
        logger.info("Smart pattern matcher initialized")
    
    def match_pattern(self, content: str, pattern_name: str, 
                     custom_pattern: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Match pattern with intelligent filtering.
        
        Args:
            content: Content to search
            pattern_name: Name of pattern to use
            custom_pattern: Optional custom regex pattern
            
        Returns:
            List of validated matches with metadata
        """
        results = []
        
        # Get pattern config
        if custom_pattern:
            pattern_config = {
                'pattern': custom_pattern,
                'exclude': [],
                'min_entropy': 3.0,
                'validate_func': None,
            }
        elif pattern_name in self.ENHANCED_PATTERNS:
            pattern_config = self.ENHANCED_PATTERNS[pattern_name]
        else:
            logger.warning(f"Unknown pattern: {pattern_name}")
            return results
        
        # Find all matches
        pattern = pattern_config['pattern']
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        
        for match in matches:
            self.matches_found += 1
            
            # Get matched value
            if match.groups():
                value = match.group(1)
            else:
                value = match.group(0)
            
            # Check exclusion patterns
            is_excluded = False
            for exclude_pattern in pattern_config.get('exclude', []):
                if re.search(exclude_pattern, value, re.IGNORECASE):
                    is_excluded = True
                    self.false_positives_filtered += 1
                    logger.debug(f"Filtered by exclusion pattern: {value[:20]}...")
                    break
            
            if is_excluded:
                continue
            
            # Check entropy
            if self.enable_entropy_check and pattern_config.get('min_entropy', 0) > 0:
                is_real, reason = self.entropy_analyzer.is_likely_real_secret(value)
                if not is_real:
                    self.false_positives_filtered += 1
                    logger.debug(f"Filtered by entropy: {value[:20]}... ({reason})")
                    continue
            
            # Run validation function
            if self.enable_validation and pattern_config.get('validate_func'):
                self.validations_performed += 1
                try:
                    is_valid = pattern_config['validate_func'](value)
                    if not is_valid:
                        self.false_positives_filtered += 1
                        logger.debug(f"Filtered by validation: {value[:20]}...")
                        continue
                except Exception as e:
                    logger.warning(f"Validation error: {e}")
            
            # Valid match!
            results.append({
                'pattern_name': pattern_name,
                'value': value,
                'start': match.start(),
                'end': match.end(),
                'context': content[max(0, match.start()-50):min(len(content), match.end()+50)],
                'validated': self.enable_validation,
            })
            
            logger.debug(f"Valid match for {pattern_name}: {value[:20]}...")
        
        return results
    
    def is_safe_domain(self, url: str) -> bool:
        """
        Check if domain is in safe list.
        
        Args:
            url: URL or domain to check
            
        Returns:
            True if domain is safe
        """
        url_lower = url.lower()
        
        for safe_domain in self.all_safe_domains:
            if safe_domain in url_lower:
                return True
        
        return False
    
    def validate_ssrf_target(self, url: str) -> Tuple[bool, str]:
        """
        Validate SSRF target to reduce false positives.
        
        Args:
            url: Target URL
            
        Returns:
            Tuple of (is_suspicious, reason)
        """
        url_lower = url.lower()
        
        # Check for safe domains
        if self.is_safe_domain(url):
            return False, "Safe domain (CDN, well-known API, etc.)"
        
        # Check for internal/private IP ranges
        internal_patterns = [
            r'(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.',  # Private IPs
            r'localhost',
            r'169\.254\.',  # Link-local
            r'0\.0\.0\.0',
            r'::1',  # IPv6 localhost
        ]
        
        for pattern in internal_patterns:
            if re.search(pattern, url_lower):
                return True, f"Internal/private IP or localhost"
        
        # Check for cloud metadata endpoints
        metadata_patterns = [
            r'169\.254\.169\.254',  # AWS, GCP, Azure
            r'metadata\.google\.internal',
            r'metadata\.azure',
        ]
        
        for pattern in metadata_patterns:
            if re.search(pattern, url_lower):
                return True, "Cloud metadata endpoint"
        
        return False, "External URL (not obviously suspicious)"
    
    def validate_open_redirect(self, url: str, referrer: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate open redirect to reduce false positives.
        
        Args:
            url: Redirect target URL
            referrer: Optional referrer URL
            
        Returns:
            Tuple of (is_suspicious, reason)
        """
        # Check if it's a safe domain
        if self.is_safe_domain(url):
            return False, "Redirect to safe domain"
        
        # Check if redirect is to same domain as referrer
        if referrer:
            try:
                referrer_domain = re.search(r'://([^/]+)', referrer)
                url_domain = re.search(r'://([^/]+)', url)
                
                if referrer_domain and url_domain:
                    if referrer_domain.group(1) == url_domain.group(1):
                        return False, "Redirect within same domain"
            except:
                pass
        
        # Check for common legitimate redirect patterns
        if any(pattern in url.lower() for pattern in ['/login', '/auth', '/oauth', '/sso']):
            return False, "Redirect to authentication page"
        
        return True, "Redirect to external domain"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pattern matching statistics"""
        total_matches = self.matches_found
        valid_matches = total_matches - self.false_positives_filtered
        filter_rate = (self.false_positives_filtered / total_matches * 100) if total_matches > 0 else 0
        
        return {
            'total_matches': total_matches,
            'valid_matches': valid_matches,
            'false_positives_filtered': self.false_positives_filtered,
            'filter_rate': f"{filter_rate:.1f}%",
            'validations_performed': self.validations_performed,
            'safe_domains': len(self.all_safe_domains),
        }


class ContextualValidator:
    """
    Validate findings based on context to reduce false positives.
    """
    
    def __init__(self):
        self.pattern_matcher = SmartPatternMatcher()
    
    def validate_sql_injection(self, response: str, payload: str, 
                              baseline_response: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate SQL injection finding.
        
        Args:
            response: Response content
            payload: Payload used
            baseline_response: Optional baseline response for comparison
            
        Returns:
            Tuple of (is_valid, reason)
        """
        response_lower = response.lower()
        
        # Strong indicators (high confidence)
        strong_indicators = [
            'sql syntax',
            'mysql',
            'ora-[0-9]+',
            'pg_query',
            'sqlite_',
            'sqlstate',
            'jdbc',
            'odbc',
        ]
        
        strong_match = any(re.search(ind, response_lower) for ind in strong_indicators)
        if strong_match:
            return True, "Strong SQL error indicators present"
        
        # Weak indicators (need more context)
        weak_indicators = ['error', 'warning', 'syntax', 'query']
        weak_matches = sum(1 for ind in weak_indicators if ind in response_lower)
        
        if weak_matches >= 2:
            # Check if this is different from baseline
            if baseline_response and response != baseline_response:
                return True, "Multiple weak indicators with response change"
        
        # Check if payload was reflected (might be XSS, not SQLi)
        if payload in response:
            return False, "Payload reflected but no SQL errors"
        
        return False, "Insufficient evidence for SQL injection"
    
    def validate_xss(self, response: str, payload: str, 
                    content_type: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate XSS finding.
        
        Args:
            response: Response content
            payload: Payload used
            content_type: Optional content type
            
        Returns:
            Tuple of (is_valid, reason)
        """
        # Check if payload was reflected
        if payload not in response:
            return False, "Payload not reflected in response"
        
        # Check content type
        if content_type:
            # XSS in JSON is less impactful
            if 'json' in content_type.lower():
                return True, "Reflected in JSON (lower impact)"
            
            # XSS in HTML is high impact
            if 'html' in content_type.lower():
                # Check if payload is in executable context
                payload_index = response.find(payload)
                context = response[max(0, payload_index-100):min(len(response), payload_index+100)]
                
                # Check if inside script tag
                if '<script' in context and '</script>' in context:
                    return True, "Reflected inside script tag (high impact)"
                
                # Check if as attribute value
                if re.search(r'<[^>]+\s+\w+=["\']?[^"\']*' + re.escape(payload[:10]), response):
                    return True, "Reflected in HTML attribute (medium impact)"
                
                return True, "Reflected in HTML context"
        
        return True, "Payload reflected (context unknown)"
    
    def validate_command_injection(self, response: str, payload: str,
                                  response_time: float = 0.0) -> Tuple[bool, str]:
        """
        Validate command injection finding.
        
        Args:
            response: Response content
            payload: Payload used
            response_time: Response time in seconds
            
        Returns:
            Tuple of (is_valid, reason)
        """
        # Time-based detection
        if 'sleep' in payload.lower() or 'timeout' in payload.lower():
            if response_time > 5.0:  # Significant delay
                return True, f"Significant delay ({response_time:.1f}s) after sleep command"
        
        # Output-based detection
        command_outputs = ['uid=', 'gid=', 'root:', 'bash', 'sh-']
        if any(output in response.lower() for output in command_outputs):
            return True, "Command output detected in response"
        
        # Error-based detection
        command_errors = ['command not found', 'permission denied', 'cannot execute']
        if any(error in response.lower() for error in command_errors):
            return True, "Command execution errors detected"
        
        return False, "No clear evidence of command execution"


# Global instance
_global_pattern_matcher: Optional[SmartPatternMatcher] = None


def get_pattern_matcher(config: Optional[Dict[str, Any]] = None) -> SmartPatternMatcher:
    """Get or create global pattern matcher instance"""
    global _global_pattern_matcher
    
    if _global_pattern_matcher is None:
        _global_pattern_matcher = SmartPatternMatcher(config)
    return _global_pattern_matcher


def reset_pattern_matcher():
    """Reset global pattern matcher (mainly for testing)"""
    global _global_pattern_matcher
    _global_pattern_matcher = None
