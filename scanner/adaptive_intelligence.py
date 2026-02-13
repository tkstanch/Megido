"""
Adaptive Intelligence Engine for Megido Scanner

This module provides intelligent, context-aware scanning capabilities:
- Context-aware detection (HTTP method, content type, response analysis)
- Technology fingerprinting and adaptive payload selection
- WAF/Protection detection and evasion
- Behavioral analysis and anomaly detection
- Progressive disclosure scanning

Author: Megido Team
Version: 1.0.0
"""

import re
import logging
import statistics
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter, defaultdict

logger = logging.getLogger(__name__)


class TechnologyStack(Enum):
    """Detected technology stacks"""
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    NODEJS = "nodejs"
    DOTNET = "dotnet"
    RUBY = "ruby"
    GO = "go"
    UNKNOWN = "unknown"


class ProtectionType(Enum):
    """Types of detected protections"""
    WAF = "waf"
    IPS = "ips"
    RATE_LIMIT = "rate_limit"
    HONEYPOT = "honeypot"
    NONE = "none"


@dataclass
class RequestContext:
    """Context information for a request"""
    url: str
    method: str = "GET"
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    response_time: float = 0.0
    response_size: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    
    def is_json(self) -> bool:
        """Check if response is JSON"""
        return self.content_type and 'json' in self.content_type.lower()
    
    def is_xml(self) -> bool:
        """Check if response is XML"""
        return self.content_type and 'xml' in self.content_type.lower()
    
    def is_html(self) -> bool:
        """Check if response is HTML"""
        return self.content_type and 'html' in self.content_type.lower()
    
    def is_success(self) -> bool:
        """Check if response indicates success"""
        return self.status_code and 200 <= self.status_code < 300
    
    def is_redirect(self) -> bool:
        """Check if response is a redirect"""
        return self.status_code and 300 <= self.status_code < 400
    
    def is_error(self) -> bool:
        """Check if response is an error"""
        return self.status_code and self.status_code >= 400


@dataclass
class TargetProfile:
    """Profile of the target being scanned"""
    url: str
    technology_stack: TechnologyStack = TechnologyStack.UNKNOWN
    protection_type: ProtectionType = ProtectionType.NONE
    protection_vendor: Optional[str] = None
    server_headers: Dict[str, str] = field(default_factory=dict)
    response_patterns: List[str] = field(default_factory=list)
    average_response_time: float = 0.0
    baseline_established: bool = False
    
    # Behavioral patterns
    typical_response_size: int = 0
    error_patterns: Set[str] = field(default_factory=set)
    rate_limit_threshold: Optional[int] = None


class TechnologyFingerprinter:
    """
    Fingerprint technology stack based on various indicators.
    """
    
    # Technology indicators
    TECH_PATTERNS = {
        TechnologyStack.PHP: {
            'headers': ['X-Powered-By: PHP', 'Server: PHP'],
            'cookies': ['PHPSESSID'],
            'extensions': ['.php'],
            'content': ['<?php', '<?='],
        },
        TechnologyStack.PYTHON: {
            'headers': ['Server: gunicorn', 'Server: uwsgi', 'X-Powered-By: Django', 'X-Powered-By: Flask'],
            'cookies': ['sessionid', 'csrftoken'],
            'errors': ['Traceback (most recent call last)', 'Django', 'Flask'],
        },
        TechnologyStack.JAVA: {
            'headers': ['X-Powered-By: JSP', 'X-Powered-By: Servlet'],
            'cookies': ['JSESSIONID'],
            'extensions': ['.jsp', '.do', '.action'],
            'errors': ['java.lang', 'org.apache', 'javax.servlet'],
        },
        TechnologyStack.NODEJS: {
            'headers': ['X-Powered-By: Express', 'Server: Node.js'],
            'cookies': ['connect.sid'],
            'errors': ['at Object.', 'at Function.'],
        },
        TechnologyStack.DOTNET: {
            'headers': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
            'cookies': ['ASP.NET_SessionId', '.ASPXAUTH'],
            'extensions': ['.aspx', '.asmx', '.ashx'],
            'errors': ['System.', 'Microsoft.'],
        },
        TechnologyStack.RUBY: {
            'headers': ['X-Powered-By: Phusion Passenger', 'Server: Puma'],
            'cookies': ['_session_id'],
            'errors': ['ruby', 'rails'],
        },
        TechnologyStack.GO: {
            'headers': ['Server: Go', 'X-Powered-By: Go'],
            'errors': ['panic:', 'goroutine'],
        },
    }
    
    def fingerprint(self, response_data: Dict[str, Any]) -> TechnologyStack:
        """
        Fingerprint technology from response data.
        
        Args:
            response_data: Dictionary with 'headers', 'cookies', 'content', 'url'
            
        Returns:
            Detected technology stack
        """
        scores = Counter()
        
        headers = response_data.get('headers', {})
        cookies = response_data.get('cookies', {})
        content = response_data.get('content', '')
        url = response_data.get('url', '')
        
        # Check each technology
        for tech, patterns in self.TECH_PATTERNS.items():
            score = 0
            
            # Check headers
            for header_pattern in patterns.get('headers', []):
                for header_key, header_value in headers.items():
                    if header_pattern.lower() in f"{header_key}: {header_value}".lower():
                        score += 3
            
            # Check cookies
            for cookie_pattern in patterns.get('cookies', []):
                if cookie_pattern in cookies or any(cookie_pattern in c for c in cookies.keys()):
                    score += 2
            
            # Check URL extensions
            for ext in patterns.get('extensions', []):
                if ext in url.lower():
                    score += 2
            
            # Check content patterns
            for content_pattern in patterns.get('content', []):
                if content_pattern in content:
                    score += 1
            
            # Check error patterns
            for error_pattern in patterns.get('errors', []):
                if error_pattern in content:
                    score += 2
            
            if score > 0:
                scores[tech] = score
        
        # Return technology with highest score
        if scores:
            tech = scores.most_common(1)[0][0]
            logger.info(f"Technology fingerprinted: {tech.value} (confidence: {scores[tech]})")
            return tech
        
        return TechnologyStack.UNKNOWN


class ProtectionDetector:
    """
    Detect WAF, IPS, rate limiting, and honeypots.
    """
    
    # WAF signatures
    WAF_SIGNATURES = {
        'cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
        'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id'],
        'akamai': ['akamai', 'x-akamai'],
        'imperva': ['incap_ses', 'visid_incap'],
        'f5': ['x-wa-info', 'f5'],
        'modsecurity': ['mod_security', 'modsec'],
        'sucuri': ['x-sucuri-id', 'sucuri'],
        'wordfence': ['wordfence'],
    }
    
    # WAF block indicators
    BLOCK_INDICATORS = [
        'blocked', 'forbidden', 'not acceptable', 'access denied',
        'security policy', 'firewall', 'threat detected',
        'malicious', 'suspicious', 'attack detected',
        'request rejected', 'unauthorized', 'waf',
    ]
    
    # Rate limit indicators
    RATE_LIMIT_INDICATORS = [
        'rate limit', 'too many requests', '429', 'retry-after',
        'throttle', 'quota exceeded', 'slow down',
    ]
    
    # Honeypot indicators
    HONEYPOT_INDICATORS = [
        'honeypot', 'canary', 'trap', 'decoy',
        # Suspiciously easy vulnerabilities
        'admin/admin', 'test/test', 'root/root',
    ]
    
    def detect_protection(self, response_data: Dict[str, Any], 
                         baseline: Optional[Dict[str, Any]] = None) -> Tuple[ProtectionType, Optional[str]]:
        """
        Detect protection mechanisms.
        
        Args:
            response_data: Response data with 'headers', 'content', 'status_code'
            baseline: Optional baseline response for comparison
            
        Returns:
            Tuple of (protection_type, vendor)
        """
        headers = response_data.get('headers', {})
        content = response_data.get('content', '').lower()
        status_code = response_data.get('status_code', 200)
        
        # Check for WAF
        for vendor, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                # Check headers
                for header_key, header_value in headers.items():
                    if sig in header_key.lower() or sig in str(header_value).lower():
                        logger.warning(f"WAF detected: {vendor}")
                        return ProtectionType.WAF, vendor
                
                # Check content
                if sig in content:
                    logger.warning(f"WAF detected: {vendor} (content signature)")
                    return ProtectionType.WAF, vendor
        
        # Check for generic WAF blocks
        if status_code in [403, 406]:
            for indicator in self.BLOCK_INDICATORS:
                if indicator in content:
                    logger.warning(f"WAF block detected: {indicator}")
                    return ProtectionType.WAF, "generic"
        
        # Check for rate limiting
        if status_code == 429 or 'retry-after' in headers:
            logger.warning("Rate limiting detected")
            return ProtectionType.RATE_LIMIT, None
        
        for indicator in self.RATE_LIMIT_INDICATORS:
            if indicator in content:
                logger.warning(f"Rate limiting detected: {indicator}")
                return ProtectionType.RATE_LIMIT, None
        
        # Check for honeypot (heuristic - suspiciously easy access)
        if baseline and status_code == 200:
            # If we get 200 on something that should be protected
            for indicator in self.HONEYPOT_INDICATORS:
                if indicator in content:
                    logger.warning(f"Possible honeypot detected: {indicator}")
                    return ProtectionType.HONEYPOT, None
        
        return ProtectionType.NONE, None


class BehaviorAnalyzer:
    """
    Analyze target behavior for anomaly detection.
    """
    
    def __init__(self):
        self.baseline_responses: List[Dict[str, Any]] = []
        self.baseline_established = False
        
        # Statistics
        self.response_times: List[float] = []
        self.response_sizes: List[int] = []
        self.status_codes: Counter = Counter()
        
    def add_baseline_response(self, response_data: Dict[str, Any]):
        """Add a response to baseline"""
        self.baseline_responses.append(response_data)
        
        # Update statistics
        if 'response_time' in response_data:
            self.response_times.append(response_data['response_time'])
        if 'size' in response_data:
            self.response_sizes.append(response_data['size'])
        if 'status_code' in response_data:
            self.status_codes[response_data['status_code']] += 1
        
        # Establish baseline after enough samples
        if len(self.baseline_responses) >= 5:
            self.baseline_established = True
            logger.info("Baseline behavior established")
    
    def detect_anomaly(self, response_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Detect if response is anomalous compared to baseline.
        
        Args:
            response_data: Response to analyze
            
        Returns:
            Tuple of (is_anomalous, reasons)
        """
        if not self.baseline_established:
            return False, []
        
        reasons = []
        
        # Check response time anomaly
        if self.response_times and 'response_time' in response_data:
            avg_time = statistics.mean(self.response_times)
            std_time = statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
            
            current_time = response_data['response_time']
            
            # Anomaly if > 3 standard deviations from mean
            if std_time > 0 and abs(current_time - avg_time) > 3 * std_time:
                reasons.append(f"Response time anomaly: {current_time:.3f}s vs avg {avg_time:.3f}s")
        
        # Check response size anomaly
        if self.response_sizes and 'size' in response_data:
            avg_size = statistics.mean(self.response_sizes)
            std_size = statistics.stdev(self.response_sizes) if len(self.response_sizes) > 1 else 0
            
            current_size = response_data['size']
            
            if std_size > 0 and abs(current_size - avg_size) > 3 * std_size:
                reasons.append(f"Response size anomaly: {current_size} bytes vs avg {avg_size:.0f} bytes")
        
        # Check status code anomaly
        if 'status_code' in response_data:
            current_code = response_data['status_code']
            most_common_code = self.status_codes.most_common(1)[0][0]
            
            if current_code != most_common_code and current_code >= 400:
                reasons.append(f"Status code anomaly: {current_code} (expected {most_common_code})")
        
        is_anomalous = len(reasons) > 0
        if is_anomalous:
            logger.info(f"Anomaly detected: {', '.join(reasons)}")
        
        return is_anomalous, reasons


class ContextAwareDetector:
    """
    Context-aware detection that adapts to target characteristics.
    """
    
    def __init__(self):
        self.fingerprinter = TechnologyFingerprinter()
        self.protection_detector = ProtectionDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        
    def should_use_payload(self, payload: str, context: RequestContext, 
                          target_profile: TargetProfile) -> Tuple[bool, str]:
        """
        Determine if payload is appropriate for context.
        
        Args:
            payload: Payload to test
            context: Request context
            target_profile: Target profile
            
        Returns:
            Tuple of (should_use, reason)
        """
        # Don't test if WAF is detected and payload is obvious
        if target_profile.protection_type == ProtectionType.WAF:
            # Skip obvious attack patterns
            obvious_patterns = ["<script>", "' OR '1'='1", "../../../etc/passwd", "';DROP TABLE"]
            if any(pattern in payload for pattern in obvious_patterns):
                return False, "Skipping obvious payload - WAF detected"
        
        # Match payload to content type
        if context.is_json():
            # Prefer JSON-based payloads for JSON endpoints
            if not ('{' in payload or '[' in payload):
                return False, "Non-JSON payload for JSON endpoint"
        
        if context.is_xml():
            # Prefer XML-based payloads for XML endpoints
            if not ('<' in payload and '>' in payload):
                return False, "Non-XML payload for XML endpoint"
        
        # Match payload to technology
        if target_profile.technology_stack == TechnologyStack.PHP:
            # PHP-specific optimizations
            pass  # All payloads OK for PHP
        elif target_profile.technology_stack == TechnologyStack.JAVA:
            # Java doesn't use eval() like JavaScript
            if "eval(" in payload and "<script>" not in payload:
                return False, "JavaScript eval() not applicable to Java"
        
        return True, "Payload appropriate for context"
    
    def adjust_confidence(self, base_confidence: float, context: RequestContext,
                         target_profile: TargetProfile, evidence: List[str]) -> float:
        """
        Adjust confidence score based on context.
        
        Args:
            base_confidence: Initial confidence score (0-1)
            context: Request context
            target_profile: Target profile
            evidence: Evidence list
            
        Returns:
            Adjusted confidence score (0-1)
        """
        adjusted = base_confidence
        
        # Reduce confidence if WAF is present
        if target_profile.protection_type == ProtectionType.WAF:
            adjusted *= 0.7
            logger.debug("Reduced confidence due to WAF presence")
        
        # Increase confidence if anomaly detected
        is_anomaly, reasons = self.behavior_analyzer.detect_anomaly({
            'response_time': context.response_time,
            'size': context.response_size,
            'status_code': context.status_code,
        })
        
        if is_anomaly:
            adjusted = min(1.0, adjusted * 1.2)
            logger.debug(f"Increased confidence due to anomaly: {reasons}")
        
        # Increase confidence for technology-specific evidence
        tech_specific_patterns = {
            TechnologyStack.PHP: ['mysql_', 'pg_', 'mysqli_'],
            TechnologyStack.PYTHON: ['Traceback', 'Django', 'Flask'],
            TechnologyStack.JAVA: ['java.lang', 'SQLException'],
        }
        
        if target_profile.technology_stack in tech_specific_patterns:
            patterns = tech_specific_patterns[target_profile.technology_stack]
            if any(pattern in ' '.join(evidence) for pattern in patterns):
                adjusted = min(1.0, adjusted * 1.15)
                logger.debug(f"Increased confidence for {target_profile.technology_stack.value}-specific evidence")
        
        # Reduce confidence if response indicates error but not vulnerability-related
        if context.is_error() and not any(kw in ' '.join(evidence).lower() for kw in ['sql', 'syntax', 'injection', 'xss']):
            adjusted *= 0.8
            logger.debug("Reduced confidence - generic error response")
        
        return max(0.0, min(1.0, adjusted))


class AdaptiveScanner:
    """
    Main adaptive scanning coordinator.
    
    Combines all adaptive intelligence:
    - Technology fingerprinting
    - Protection detection
    - Behavior analysis
    - Context-aware detection
    - Progressive disclosure
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize adaptive scanner.
        
        Args:
            config: Configuration dictionary
        """
        config = config or {}
        
        self.context_detector = ContextAwareDetector()
        self.progressive_enabled = config.get('progressive_scanning', True)
        self.min_confidence_for_deep_scan = config.get('deep_scan_threshold', 0.7)
        
        # Target profiles (keyed by URL)
        self.target_profiles: Dict[str, TargetProfile] = {}
        
        logger.info("Adaptive scanner initialized")
    
    def get_or_create_profile(self, url: str) -> TargetProfile:
        """Get or create target profile"""
        if url not in self.target_profiles:
            self.target_profiles[url] = TargetProfile(url=url)
        return self.target_profiles[url]
    
    def update_profile(self, url: str, response_data: Dict[str, Any]):
        """Update target profile with response data"""
        profile = self.get_or_create_profile(url)
        
        # Fingerprint technology if not done
        if profile.technology_stack == TechnologyStack.UNKNOWN:
            profile.technology_stack = self.context_detector.fingerprinter.fingerprint(response_data)
        
        # Detect protection
        if profile.protection_type == ProtectionType.NONE:
            protection, vendor = self.context_detector.protection_detector.detect_protection(response_data)
            profile.protection_type = protection
            profile.protection_vendor = vendor
        
        # Add to behavior baseline
        if not profile.baseline_established:
            self.context_detector.behavior_analyzer.add_baseline_response(response_data)
            profile.baseline_established = self.context_detector.behavior_analyzer.baseline_established
    
    def should_deep_scan(self, url: str, initial_confidence: float) -> bool:
        """
        Determine if deep scanning should be performed.
        
        Args:
            url: Target URL
            initial_confidence: Confidence from initial scan
            
        Returns:
            True if deep scan recommended
        """
        if not self.progressive_enabled:
            return True
        
        profile = self.get_or_create_profile(url)
        
        # Always deep scan if no protection detected
        if profile.protection_type == ProtectionType.NONE:
            return True
        
        # Deep scan if initial confidence is high enough
        if initial_confidence >= self.min_confidence_for_deep_scan:
            logger.info(f"Deep scan recommended (confidence: {initial_confidence:.2f})")
            return True
        
        # Skip deep scan if WAF/protection detected and low confidence
        if profile.protection_type in [ProtectionType.WAF, ProtectionType.IPS]:
            logger.info(f"Skipping deep scan - {profile.protection_type.value} detected and low confidence")
            return False
        
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get adaptive scanner statistics"""
        return {
            'profiles_created': len(self.target_profiles),
            'technologies_detected': {
                url: profile.technology_stack.value
                for url, profile in self.target_profiles.items()
                if profile.technology_stack != TechnologyStack.UNKNOWN
            },
            'protections_detected': {
                url: f"{profile.protection_type.value} ({profile.protection_vendor or 'generic'})"
                for url, profile in self.target_profiles.items()
                if profile.protection_type != ProtectionType.NONE
            },
        }


# Global instance
_global_adaptive_scanner: Optional[AdaptiveScanner] = None


def get_adaptive_scanner(config: Optional[Dict[str, Any]] = None) -> AdaptiveScanner:
    """Get or create global adaptive scanner instance"""
    global _global_adaptive_scanner
    
    if _global_adaptive_scanner is None:
        _global_adaptive_scanner = AdaptiveScanner(config)
    return _global_adaptive_scanner


def reset_adaptive_scanner():
    """Reset global adaptive scanner (mainly for testing)"""
    global _global_adaptive_scanner
    _global_adaptive_scanner = None
