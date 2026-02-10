"""
Enhanced Sensitive Information Scanner Module

This module provides advanced detection capabilities for sensitive information including:
- Pluggable pattern providers
- Hybrid scanning (static files + dynamic URLs)
- Heuristic detection with entropy analysis
- ML integration template
- External signature fetching
- Result caching and performance optimization
- Context awareness
- Configurable logging

SECURITY NOTE: SSL verification is disabled (verify=False) to facilitate 
security testing. This should only be used in controlled testing environments.
"""

import re
import requests
import os
import json
import math
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import logging
import urllib3

# Disable SSL warnings since we're intentionally bypassing SSL verification for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PatternProvider(ABC):
    """
    Abstract base class for pattern providers.
    Allows pluggable pattern sources (built-in, external, ML-based, etc.)
    """
    
    @abstractmethod
    def get_patterns(self) -> Dict[str, str]:
        """
        Returns patterns as a dictionary with pattern names and regex.
        
        Returns:
            Dictionary mapping pattern names to regex patterns
        """
        pass
    
    @abstractmethod
    def get_pattern_severity(self, pattern_name: str) -> str:
        """
        Returns the severity level for a pattern.
        
        Args:
            pattern_name: Name of the pattern
            
        Returns:
            Severity level: 'critical', 'high', 'medium', 'low'
        """
        pass


class SensitivePatterns(PatternProvider):
    """
    Built-in sensitive pattern provider with severity classification.
    """
    
    # API Keys
    AWS_KEY = r'AKIA[0-9A-Z]{16}'
    GITHUB_TOKEN = r'ghp_[0-9a-zA-Z]{36}'
    GITHUB_OAUTH = r'gho_[0-9a-zA-Z]{36}'
    SLACK_TOKEN = r'xox[baprs]-[0-9a-zA-Z]{10,48}'
    SLACK_WEBHOOK = r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+'
    STRIPE_KEY = r'sk_live_[0-9a-zA-Z]{24,}'
    GOOGLE_API = r'AIza[0-9A-Za-z\-_]{35}'
    
    # Tokens and Secrets
    GENERIC_SECRET = r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    GENERIC_API_KEY = r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    BEARER_TOKEN = r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*'
    
    # Private Keys and Certificates
    PRIVATE_KEY = r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
    SSH_PRIVATE_KEY = r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
    PGP_PRIVATE_KEY = r'-----BEGIN PGP PRIVATE KEY BLOCK-----'
    
    # Database Connection Strings
    MYSQL_CONN = r'mysql://[^:]+:[^@]+@[^/]+/\w+'
    POSTGRES_CONN = r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+'
    MONGODB_CONN = r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+'
    
    # Passwords and Credentials
    PASSWORD_FIELD = r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{3,})["\']'
    USERNAME_PASSWORD = r'(?:user|username|login)["\']?\s*[:=]\s*["\']([^"\']+)["\'].*?password["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    
    # Email Addresses
    EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # IP Addresses (Private)
    PRIVATE_IP = r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
    
    # JWT Tokens
    JWT_TOKEN = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
    
    # Credit Card Numbers (basic pattern)
    CREDIT_CARD = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    
    # Social Security Numbers (US)
    SSN = r'\b\d{3}-\d{2}-\d{4}\b'
    
    # Pattern severity mapping
    SEVERITY_MAP = {
        'AWS Access Key': 'critical',
        'GitHub Personal Access Token': 'critical',
        'GitHub OAuth Token': 'critical',
        'Slack Token': 'high',
        'Slack Webhook': 'high',
        'Stripe API Key': 'critical',
        'Google API Key': 'high',
        'Generic Secret': 'medium',
        'Generic API Key': 'high',
        'Bearer Token': 'high',
        'Private Key': 'critical',
        'SSH Private Key': 'critical',
        'PGP Private Key': 'critical',
        'MySQL Connection String': 'critical',
        'PostgreSQL Connection String': 'critical',
        'MongoDB Connection String': 'critical',
        'Password Field': 'high',
        'Username/Password Combo': 'critical',
        'Email Address': 'low',
        'Private IP Address': 'low',
        'JWT Token': 'high',
        'Credit Card Number': 'critical',
        'Social Security Number': 'critical',
    }
    
    def get_patterns(self) -> Dict[str, str]:
        """Returns all patterns as a dictionary with pattern names and regex."""
        return {
            'AWS Access Key': self.AWS_KEY,
            'GitHub Personal Access Token': self.GITHUB_TOKEN,
            'GitHub OAuth Token': self.GITHUB_OAUTH,
            'Slack Token': self.SLACK_TOKEN,
            'Slack Webhook': self.SLACK_WEBHOOK,
            'Stripe API Key': self.STRIPE_KEY,
            'Google API Key': self.GOOGLE_API,
            'Generic Secret': self.GENERIC_SECRET,
            'Generic API Key': self.GENERIC_API_KEY,
            'Bearer Token': self.BEARER_TOKEN,
            'Private Key': self.PRIVATE_KEY,
            'SSH Private Key': self.SSH_PRIVATE_KEY,
            'PGP Private Key': self.PGP_PRIVATE_KEY,
            'MySQL Connection String': self.MYSQL_CONN,
            'PostgreSQL Connection String': self.POSTGRES_CONN,
            'MongoDB Connection String': self.MONGODB_CONN,
            'Password Field': self.PASSWORD_FIELD,
            'Username/Password Combo': self.USERNAME_PASSWORD,
            'Email Address': self.EMAIL,
            'Private IP Address': self.PRIVATE_IP,
            'JWT Token': self.JWT_TOKEN,
            'Credit Card Number': self.CREDIT_CARD,
            'Social Security Number': self.SSN,
        }
    
    def get_pattern_severity(self, pattern_name: str) -> str:
        """Returns the severity level for a pattern."""
        return self.SEVERITY_MAP.get(pattern_name, 'medium')
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, str]:
        """Legacy method for backward compatibility."""
        instance = cls()
        return instance.get_patterns()


class ExternalPatternProvider(PatternProvider):
    """
    Pattern provider that fetches patterns from external sources.
    Supports loading from URLs or local JSON files.
    """
    
    def __init__(self, source_url: Optional[str] = None, source_file: Optional[str] = None,
                 cache_ttl: int = 3600):
        """
        Initialize external pattern provider.
        
        Args:
            source_url: URL to fetch patterns from
            source_file: Local file path to load patterns from
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
        """
        self.source_url = source_url
        self.source_file = source_file
        self.cache_ttl = cache_ttl
        self._patterns_cache: Optional[Dict[str, str]] = None
        self._severity_cache: Optional[Dict[str, str]] = None
        self._cache_time: Optional[datetime] = None
    
    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid."""
        if self._cache_time is None:
            return False
        return (datetime.now() - self._cache_time).seconds < self.cache_ttl
    
    def _fetch_from_url(self) -> Dict[str, Any]:
        """Fetch patterns from URL."""
        try:
            response = requests.get(self.source_url, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logging.error(f"Error fetching patterns from URL: {e}")
            return {}
    
    def _load_from_file(self) -> Dict[str, Any]:
        """Load patterns from local file."""
        try:
            with open(self.source_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading patterns from file: {e}")
            return {}
    
    def _update_cache(self):
        """Update pattern cache from source."""
        data = {}
        
        if self.source_url:
            data = self._fetch_from_url()
        elif self.source_file:
            data = self._load_from_file()
        
        if data:
            self._patterns_cache = data.get('patterns', {})
            self._severity_cache = data.get('severity', {})
            self._cache_time = datetime.now()
    
    def get_patterns(self) -> Dict[str, str]:
        """Returns patterns from external source with caching."""
        if not self._is_cache_valid():
            self._update_cache()
        
        return self._patterns_cache or {}
    
    def get_pattern_severity(self, pattern_name: str) -> str:
        """Returns the severity level for a pattern from external source."""
        if not self._is_cache_valid():
            self._update_cache()
        
        return (self._severity_cache or {}).get(pattern_name, 'medium')


class HeuristicScanner:
    """
    Heuristic-based scanner for detecting suspicious patterns using entropy analysis
    and other statistical methods.
    """
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Args:
            data: String to analyze
            
        Returns:
            Entropy value (higher = more random/suspicious)
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    @staticmethod
    def detect_high_entropy_strings(content: str, min_length: int = 20,
                                   entropy_threshold: float = 4.5) -> List[Dict[str, Any]]:
        """
        Detect high-entropy strings that may be tokens or secrets.
        
        Args:
            content: Content to scan
            min_length: Minimum string length to consider
            entropy_threshold: Minimum entropy to flag (default: 4.5)
            
        Returns:
            List of suspicious high-entropy findings
        """
        findings = []
        
        # Find potential token-like strings (alphanumeric sequences)
        pattern = r'[A-Za-z0-9_\-\.]{' + str(min_length) + ',}'
        matches = re.finditer(pattern, content)
        
        for match in matches:
            value = match.group(0)
            entropy = HeuristicScanner.calculate_entropy(value)
            
            if entropy >= entropy_threshold:
                # Extract context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end]
                
                findings.append({
                    'type': 'High Entropy String (Heuristic)',
                    'value': value,
                    'entropy': round(entropy, 2),
                    'context': context,
                    'position': match.start(),
                    'severity': 'medium'
                })
        
        return findings
    
    @staticmethod
    def detect_suspicious_assignments(content: str) -> List[Dict[str, Any]]:
        """
        Detect suspicious variable assignments that might contain secrets.
        
        Args:
            content: Content to scan
            
        Returns:
            List of suspicious assignment findings
        """
        findings = []
        
        # Pattern for suspicious keywords in assignments
        suspicious_keywords = [
            'token', 'key', 'secret', 'password', 'credential',
            'auth', 'access', 'private', 'api'
        ]
        
        pattern = r'(' + '|'.join(suspicious_keywords) + r')["\']?\s*[:=]\s*["\']([^"\']{8,})["\']'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        
        for match in matches:
            keyword = match.group(1)
            value = match.group(2)
            
            # Skip if value looks like a placeholder
            if any(placeholder in value.lower() for placeholder in 
                   ['example', 'placeholder', 'your_', 'xxx', 'test']):
                continue
            
            # Extract context
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end]
            
            findings.append({
                'type': f'Suspicious {keyword.capitalize()} Assignment (Heuristic)',
                'value': value,
                'context': context,
                'position': match.start(),
                'severity': 'medium'
            })
        
        return findings


class MLIntegrationTemplate:
    """
    Template class for integrating machine learning models for pattern detection.
    This is a stub that can be extended with actual ML models (sklearn, TensorFlow, etc.)
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize ML integration.
        
        Args:
            model_path: Path to trained model file
        """
        self.model_path = model_path
        self.model = None
        
        if model_path:
            self._load_model()
    
    def _load_model(self):
        """
        Load trained ML model.
        Stub method - implement with actual ML library (sklearn, TensorFlow, etc.)
        """
        # Example implementation would be:
        # import joblib
        # self.model = joblib.load(self.model_path)
        pass
    
    def predict_sensitive(self, text: str) -> Tuple[bool, float]:
        """
        Predict if text contains sensitive information using ML model.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (is_sensitive: bool, confidence: float)
        """
        if self.model is None:
            return False, 0.0
        
        # Stub implementation - replace with actual model prediction
        # Example:
        # features = self._extract_features(text)
        # prediction = self.model.predict_proba([features])[0]
        # return prediction[1] > 0.5, prediction[1]
        
        return False, 0.0
    
    def _extract_features(self, text: str) -> List[float]:
        """
        Extract features from text for ML model.
        Stub method - implement feature engineering based on model requirements.
        
        Args:
            text: Text to extract features from
            
        Returns:
            Feature vector
        """
        # Example features could include:
        # - Text length
        # - Entropy
        # - Character distribution
        # - Presence of special patterns
        # - N-gram features
        
        return []


class ContextAnalyzer:
    """
    Analyzes context around findings to provide additional intelligence.
    Correlates with environment variables, config files, etc.
    """
    
    @staticmethod
    def check_environment_correlation(finding_value: str) -> Dict[str, Any]:
        """
        Check if finding correlates with environment variables.
        
        Args:
            finding_value: The sensitive value found
            
        Returns:
            Correlation information
        """
        correlations = []
        
        for env_var, env_value in os.environ.items():
            if env_value and finding_value in env_value:
                correlations.append({
                    'type': 'environment_variable',
                    'name': env_var,
                    'match': 'exact' if env_value == finding_value else 'partial'
                })
        
        return {
            'has_correlation': len(correlations) > 0,
            'correlations': correlations
        }
    
    @staticmethod
    def detect_config_file_context(file_path: str) -> Dict[str, Any]:
        """
        Detect if the scanned file is a configuration file.
        
        Args:
            file_path: Path to the file being scanned
            
        Returns:
            Configuration file context information
        """
        config_patterns = [
            r'\.env', r'\.config', r'\.yaml', r'\.yml',
            r'\.json', r'\.ini', r'\.conf', r'\.properties'
        ]
        
        is_config = any(re.search(pattern, file_path, re.IGNORECASE) 
                       for pattern in config_patterns)
        
        return {
            'is_config_file': is_config,
            'file_type': Path(file_path).suffix if is_config else None,
            'risk_level': 'high' if is_config else 'medium'
        }


class ScanResultCache:
    """
    Cache for scan results to avoid redundant scanning.
    """
    
    def __init__(self, ttl: int = 3600):
        """
        Initialize result cache.
        
        Args:
            ttl: Time-to-live for cache entries in seconds (default: 1 hour)
        """
        self.ttl = ttl
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
    
    def _generate_key(self, target: str) -> str:
        """Generate cache key from target."""
        return hashlib.md5(target.encode()).hexdigest()
    
    def get(self, target: str) -> Optional[Any]:
        """
        Get cached result for target.
        
        Args:
            target: URL or file path
            
        Returns:
            Cached result or None if not found/expired
        """
        key = self._generate_key(target)
        
        if key in self._cache:
            result, timestamp = self._cache[key]
            if (datetime.now() - timestamp).seconds < self.ttl:
                return result
            else:
                del self._cache[key]
        
        return None
    
    def set(self, target: str, result: Any):
        """
        Store result in cache.
        
        Args:
            target: URL or file path
            result: Scan result to cache
        """
        key = self._generate_key(target)
        self._cache[key] = (result, datetime.now())
    
    def clear(self):
        """Clear all cache entries."""
        self._cache.clear()


class EnhancedSensitiveInfoScanner:
    """
    Enhanced scanner with pluggable patterns, hybrid scanning, heuristics,
    caching, and advanced detection capabilities.
    """
    
    def __init__(self, 
                 pattern_providers: Optional[List[PatternProvider]] = None,
                 timeout: int = 10,
                 max_workers: int = 5,
                 enable_heuristics: bool = True,
                 enable_ml: bool = False,
                 ml_model_path: Optional[str] = None,
                 cache_ttl: int = 3600,
                 log_level: str = 'INFO'):
        """
        Initialize the enhanced scanner.
        
        Args:
            pattern_providers: List of pattern providers (default: SensitivePatterns)
            timeout: Request timeout in seconds (default: 10)
            max_workers: Maximum number of concurrent workers (default: 5)
            enable_heuristics: Enable heuristic detection (default: True)
            enable_ml: Enable ML-based detection (default: False)
            ml_model_path: Path to ML model file
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
            log_level: Logging level (default: 'INFO')
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.enable_heuristics = enable_heuristics
        self.enable_ml = enable_ml
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Initialize pattern providers
        if pattern_providers is None:
            self.pattern_providers = [SensitivePatterns()]
        else:
            self.pattern_providers = pattern_providers
        
        # Combine patterns from all providers
        self.patterns = {}
        self.pattern_severity = {}
        for provider in self.pattern_providers:
            self.patterns.update(provider.get_patterns())
            for pattern_name in provider.get_patterns().keys():
                self.pattern_severity[pattern_name] = provider.get_pattern_severity(pattern_name)
        
        # Initialize components
        self.heuristic_scanner = HeuristicScanner() if enable_heuristics else None
        self.ml_detector = MLIntegrationTemplate(ml_model_path) if enable_ml else None
        self.cache = ScanResultCache(ttl=cache_ttl)
        self.context_analyzer = ContextAnalyzer()
    
    @staticmethod
    def luhn_check(card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm (mod 10 check).
        
        Args:
            card_number: The card number to validate (digits only)
            
        Returns:
            True if valid, False otherwise
        """
        card_number = ''.join(filter(str.isdigit, card_number))
        
        if not card_number:
            return False
        
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        
        return checksum % 10 == 0
    
    @staticmethod
    def verify_context_not_numeric_field(context: str, value: str) -> bool:
        """
        Check if the context suggests this is part of a JSON numeric field,
        currency value, or other non-credit-card number.
        
        Args:
            context: The surrounding text
            value: The matched value
            
        Returns:
            True if context looks safe (not a false positive), False otherwise
        """
        context_lower = context.lower()
        
        false_positive_indicators = [
            'usd', 'price', 'amount', 'total', 'cost', 
            'volume', 'sales', '":', '":"', 'native',
            'balance', 'revenue', '€', '$', '£'
        ]
        
        for indicator in false_positive_indicators:
            if indicator in context_lower:
                return False
        
        return True
    
    def fetch_url_content(self, url: str) -> str:
        """
        Fetch content from a URL with timeout and error handling.
        
        Args:
            url: The URL to fetch
            
        Returns:
            The content of the URL as a string, or empty string on error
        """
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/2.0)'}
            )
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            self.logger.warning(f"Timeout fetching {url}")
            return ""
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Error fetching {url}: {e}")
            return ""
        except Exception as e:
            self.logger.error(f"Unexpected error fetching {url}: {e}")
            return ""
    
    def read_file_content(self, file_path: str) -> str:
        """
        Read content from a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File content as string, or empty string on error
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return ""
    
    def scan_content_for_sensitive_data(self, content: str, source: str,
                                       source_type: str = 'url') -> List[Dict[str, Any]]:
        """
        Scan content using regex patterns and heuristics to find sensitive information.
        
        Args:
            content: The content to scan
            source: The source being scanned (URL or file path)
            source_type: Type of source ('url' or 'file')
            
        Returns:
            List of findings with details including severity
        """
        findings = []
        seen_findings = set()
        
        # Pattern-based scanning
        for pattern_name, pattern in self.patterns.items():
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    value = match.group(0)
                    
                    finding_key = (pattern_name, value.lower())
                    if finding_key in seen_findings:
                        continue
                    seen_findings.add(finding_key)
                    
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    
                    # Special validation for credit cards
                    if pattern_name == 'Credit Card Number':
                        if not self.luhn_check(value):
                            continue
                        if not self.verify_context_not_numeric_field(context, value):
                            continue
                    
                    finding = {
                        'type': pattern_name,
                        'value': value,
                        'context': context,
                        'position': match.start(),
                        'source': source,
                        'source_type': source_type,
                        'severity': self.pattern_severity.get(pattern_name, 'medium'),
                        'detection_method': 'pattern'
                    }
                    
                    # Add context analysis for files
                    if source_type == 'file':
                        file_context = self.context_analyzer.detect_config_file_context(source)
                        finding['file_context'] = file_context
                        if file_context['is_config_file']:
                            finding['severity'] = 'critical'
                    
                    findings.append(finding)
                    
            except Exception as e:
                self.logger.error(f"Error scanning for {pattern_name}: {e}")
                continue
        
        # Heuristic-based scanning
        if self.enable_heuristics and self.heuristic_scanner:
            try:
                heuristic_findings = self.heuristic_scanner.detect_high_entropy_strings(content)
                heuristic_findings.extend(self.heuristic_scanner.detect_suspicious_assignments(content))
                
                for finding in heuristic_findings:
                    finding['source'] = source
                    finding['source_type'] = source_type
                    finding['detection_method'] = 'heuristic'
                    findings.append(finding)
                    
            except Exception as e:
                self.logger.error(f"Error in heuristic scanning: {e}")
        
        # ML-based detection (if enabled)
        if self.enable_ml and self.ml_detector:
            try:
                is_sensitive, confidence = self.ml_detector.predict_sensitive(content)
                if is_sensitive and confidence > 0.7:
                    findings.append({
                        'type': 'ML Detected Sensitive Content',
                        'value': f'Confidence: {confidence:.2f}',
                        'context': content[:100],
                        'source': source,
                        'source_type': source_type,
                        'severity': 'medium',
                        'detection_method': 'ml',
                        'confidence': confidence
                    })
            except Exception as e:
                self.logger.error(f"Error in ML detection: {e}")
        
        return findings
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan a single URL and return findings.
        
        Args:
            url: The URL to scan
            
        Returns:
            Dictionary with URL and findings
        """
        # Check cache first
        cached_result = self.cache.get(url)
        if cached_result is not None:
            self.logger.debug(f"Using cached result for {url}")
            return cached_result
        
        content = self.fetch_url_content(url)
        
        if not content:
            result = {
                'source': url,
                'source_type': 'url',
                'success': False,
                'findings': []
            }
            self.cache.set(url, result)
            return result
        
        findings = self.scan_content_for_sensitive_data(content, url, 'url')
        
        result = {
            'source': url,
            'source_type': 'url',
            'success': True,
            'findings': findings
        }
        
        self.cache.set(url, result)
        return result
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file and return findings.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with file path and findings
        """
        # Check cache first
        cached_result = self.cache.get(file_path)
        if cached_result is not None:
            self.logger.debug(f"Using cached result for {file_path}")
            return cached_result
        
        content = self.read_file_content(file_path)
        
        if not content:
            result = {
                'source': file_path,
                'source_type': 'file',
                'success': False,
                'findings': []
            }
            self.cache.set(file_path, result)
            return result
        
        findings = self.scan_content_for_sensitive_data(content, file_path, 'file')
        
        result = {
            'source': file_path,
            'source_type': 'file',
            'success': True,
            'findings': findings
        }
        
        self.cache.set(file_path, result)
        return result
    
    def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple URLs concurrently using ThreadPoolExecutor.
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of scan results
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning {url}: {e}")
                    results.append({
                        'source': url,
                        'source_type': 'url',
                        'success': False,
                        'findings': [],
                        'error': str(e)
                    })
        
        return results
    
    def scan_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple files concurrently using ThreadPoolExecutor.
        
        Args:
            file_paths: List of file paths to scan
            
        Returns:
            List of scan results
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(self.scan_file, path): path for path in file_paths}
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {e}")
                    results.append({
                        'source': file_path,
                        'source_type': 'file',
                        'success': False,
                        'findings': [],
                        'error': str(e)
                    })
        
        return results
    
    def scan_directory(self, directory: str, recursive: bool = True,
                      file_patterns: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan all files in a directory.
        
        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories (default: True)
            file_patterns: List of file patterns to match (e.g., ['*.py', '*.js'])
            
        Returns:
            List of scan results
        """
        files_to_scan = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_patterns:
                        if any(Path(file).match(pattern) for pattern in file_patterns):
                            files_to_scan.append(file_path)
                    else:
                        files_to_scan.append(file_path)
        else:
            for item in os.listdir(directory):
                file_path = os.path.join(directory, item)
                if os.path.isfile(file_path):
                    if file_patterns:
                        if any(Path(item).match(pattern) for pattern in file_patterns):
                            files_to_scan.append(file_path)
                    else:
                        files_to_scan.append(file_path)
        
        self.logger.info(f"Scanning {len(files_to_scan)} files in {directory}")
        return self.scan_files(files_to_scan)


def scan_discovered_urls_enhanced(urls: List[str], max_urls: int = 50,
                                 enable_heuristics: bool = True,
                                 log_level: str = 'INFO') -> Dict[str, Any]:
    """
    Enhanced version of scan_discovered_urls with additional features.
    Maintains backward compatibility while providing enhanced capabilities.
    
    Args:
        urls: List of URLs to scan
        max_urls: Maximum number of URLs to scan (default: 50)
        enable_heuristics: Enable heuristic detection (default: True)
        log_level: Logging level (default: 'INFO')
        
    Returns:
        Dictionary with aggregated findings and statistics
    """
    urls_to_scan = urls[:max_urls]
    
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.info(f"Starting enhanced sensitive scan for {len(urls_to_scan)} URLs")
    
    scanner = EnhancedSensitiveInfoScanner(
        timeout=10,
        max_workers=5,
        enable_heuristics=enable_heuristics,
        log_level=log_level
    )
    
    scan_results = scanner.scan_urls(urls_to_scan)
    
    # Aggregate findings by type and severity
    findings_by_type = {}
    findings_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
    all_findings = []
    seen_findings_global = set()
    
    for result in scan_results:
        if result['success'] and result['findings']:
            for finding in result['findings']:
                finding_key = (finding['source'], finding['type'], finding['value'].lower())
                
                if finding_key in seen_findings_global:
                    continue
                
                seen_findings_global.add(finding_key)
                
                finding_type = finding['type']
                finding_severity = finding.get('severity', 'medium')
                
                if finding_type not in findings_by_type:
                    findings_by_type[finding_type] = []
                
                findings_by_type[finding_type].append(finding)
                findings_by_severity[finding_severity].append(finding)
                all_findings.append(finding)
    
    total_findings = len(all_findings)
    total_scanned = len([r for r in scan_results if r['success']])
    total_failed = len([r for r in scan_results if not r['success']])
    
    return {
        'success': True,
        'total_urls_scanned': total_scanned,
        'total_urls_failed': total_failed,
        'total_findings': total_findings,
        'findings_by_type': findings_by_type,
        'findings_by_severity': findings_by_severity,
        'all_findings': all_findings,
        'scan_results': scan_results
    }
