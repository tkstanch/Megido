"""
RCE (Remote Code Execution) Detection Plugin

This plugin detects Remote Code Execution vulnerabilities including:
- Command injection (OS command execution)
- Server-Side Template Injection (SSTI)
- Code evaluation vulnerabilities
- Expression language injection
"""

import logging
import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, parse_qs, urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class RCEDetectorPlugin(BaseScanPlugin):
    """
    RCE vulnerability detection plugin.
    
    Detects Remote Code Execution vulnerabilities through:
    - Command injection testing (time-based and output-based)
    - Server-Side Template Injection (SSTI) detection
    - Expression language injection testing
    - Code execution pattern analysis
    """
    
    # Timing threshold for detecting time-based attacks (seconds)
    TIMING_THRESHOLD_SECONDS = 4.0  # Allow 1 second margin for 5-second sleep
    
    # Command injection payloads with time delays
    TIME_BASED_PAYLOADS = [
        "; sleep 5",
        "| sleep 5",
        "& sleep 5 &",
        "&& sleep 5",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
        "`sleep 5`",
        "$(sleep 5)",
    ]
    
    # Command injection payloads with output
    OUTPUT_BASED_PAYLOADS = [
        "; whoami",
        "| whoami",
        "& whoami",
        "&& whoami",
        "; id",
        "| id", 
        "$(whoami)",
        "`whoami`",
        "; echo RCE_TEST_STRING",
        "| echo RCE_TEST_STRING",
        "$(echo RCE_TEST_STRING)",
    ]
    
    # Template injection payloads for various engines
    SSTI_PAYLOADS = [
        # Jinja2/Twig
        "{{7*7}}",
        "{{7*'7'}}",
        "{{config}}",
        "{{self}}",
        
        # Freemarker
        "${7*7}",
        "#{7*7}",
        
        # Velocity
        "#set($x=7*7)$x",
        
        # Thymeleaf
        "[[7*7]]",
        "[(7*7)]",
        
        # Smarty
        "{7*7}",
        "{$smarty.version}",
    ]
    
    # Expected outputs for SSTI detection
    SSTI_OUTPUTS = {
        "{{7*7}}": "49",
        "{{7*'7'}}": "7777777",
        "${7*7}": "49",
        "#{7*7}": "49",
        "{7*7}": "49",
        "[[7*7]]": "49",
        "[(7*7)]": "49",
    }
    
    # Expression language injection payloads
    EL_INJECTION_PAYLOADS = [
        "${7*7}",
        "#{7*7}",
        "${applicationScope}",
        "#{applicationScope}",
    ]
    
    @property
    def plugin_id(self) -> str:
        return 'rce_detector'
    
    @property
    def name(self) -> str:
        return 'RCE Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects Remote Code Execution (RCE) vulnerabilities including command injection, SSTI, and code evaluation'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['rce']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for RCE vulnerabilities.
        
        Args:
            url: Target URL to scan
            config: Configuration dictionary
        
        Returns:
            List of vulnerability findings
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            # Test for command injection
            if config.get('test_command_injection', True):
                cmd_findings = self._test_command_injection(url, verify_ssl, timeout)
                findings.extend(cmd_findings)
            
            # Test for SSTI
            if config.get('test_template_injection', True):
                ssti_findings = self._test_ssti(url, verify_ssl, timeout)
                findings.extend(ssti_findings)
            
            # Test for expression language injection
            if config.get('test_el_injection', True):
                el_findings = self._test_el_injection(url, verify_ssl, timeout)
                findings.extend(el_findings)
            
            logger.info(f"RCE scan of {url} found {len(findings)} potential vulnerability(ies)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for RCE: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during RCE scan of {url}: {e}")
        
        return findings
    
    def _test_command_injection(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for command injection vulnerabilities."""
        findings = []
        
        try:
            # Get baseline response
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            baseline_time = response.elapsed.total_seconds()
            
            # Parse URL to find parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                # No parameters to test
                return findings
            
            # Test time-based command injection
            for param_name in params.keys():
                for payload in self.TIME_BASED_PAYLOADS:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                        start_time = time.time()
                        test_response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout + 10,
                            verify=verify_ssl
                        )
                        response_time = time.time() - start_time
                        
                        # Check if response was delayed (indicating command executed)
                        # Using TIMING_THRESHOLD_SECONDS to allow for network latency
                        if response_time > baseline_time + self.TIMING_THRESHOLD_SECONDS:
                            finding = VulnerabilityFinding(
                                vulnerability_type='rce',
                                severity='critical',
                                url=url,
                                description=f'Time-based command injection detected in parameter "{param_name}"',
                                evidence=f'Payload: {payload}, Response time: {response_time:.2f}s (baseline: {baseline_time:.2f}s)',
                                remediation='Never execute user input as system commands. Use safe APIs, input validation, and whitelist allowed operations.',
                                parameter=param_name,
                                confidence=0.85,
                                cwe_id='CWE-78'  # OS Command Injection
                            )
                            findings.append(finding)
                            logger.info(f"Found time-based command injection in {param_name}")
                            break  # Found vulnerability, move to next parameter
                    except requests.Timeout:
                        # Timeout might indicate successful injection
                        finding = VulnerabilityFinding(
                            vulnerability_type='rce',
                            severity='critical',
                            url=url,
                            description=f'Possible command injection (timeout) in parameter "{param_name}"',
                            evidence=f'Payload: {payload}, Request timed out',
                            remediation='Never execute user input as system commands. Use safe APIs, input validation, and whitelist allowed operations.',
                            parameter=param_name,
                            confidence=0.7,
                            cwe_id='CWE-78'
                        )
                        findings.append(finding)
                        break
                    except Exception as e:
                        logger.debug(f"Error testing command injection: {e}")
            
            # Test output-based command injection
            for param_name in params.keys():
                for payload in self.OUTPUT_BASED_PAYLOADS[:3]:  # Test a few
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                        test_response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        # Check for command output in response
                        response_text = test_response.text.lower()
                        if ('root:' in response_text or 'uid=' in response_text or 
                            'rce_test_string' in response_text):
                            finding = VulnerabilityFinding(
                                vulnerability_type='rce',
                                severity='critical',
                                url=url,
                                description=f'Output-based command injection detected in parameter "{param_name}"',
                                evidence=f'Payload: {payload}, Command output detected in response',
                                remediation='Never execute user input as system commands. Use safe APIs, input validation, and whitelist allowed operations.',
                                parameter=param_name,
                                confidence=0.9,
                                cwe_id='CWE-78'
                            )
                            findings.append(finding)
                            logger.info(f"Found output-based command injection in {param_name}")
                            break
                    except Exception as e:
                        logger.debug(f"Error testing output-based injection: {e}")
        
        except Exception as e:
            logger.error(f"Error in command injection testing: {e}")
        
        return findings
    
    def _test_ssti(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for Server-Side Template Injection."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            for param_name in params.keys():
                for payload, expected_output in self.SSTI_OUTPUTS.items():
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                        test_response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        # Check if expected output is in response
                        if expected_output in test_response.text:
                            finding = VulnerabilityFinding(
                                vulnerability_type='rce',
                                severity='critical',
                                url=url,
                                description=f'Server-Side Template Injection (SSTI) detected in parameter "{param_name}"',
                                evidence=f'Payload: {payload}, Expected: {expected_output}, Found in response',
                                remediation='Use sandboxed template engines, disable dangerous functions, and validate all user input before template processing.',
                                parameter=param_name,
                                confidence=0.95,
                                cwe_id='CWE-94'  # Code Injection
                            )
                            findings.append(finding)
                            logger.info(f"Found SSTI in {param_name}")
                            break
                    except Exception as e:
                        logger.debug(f"Error testing SSTI: {e}")
        
        except Exception as e:
            logger.error(f"Error in SSTI testing: {e}")
        
        return findings
    
    def _test_el_injection(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for Expression Language injection."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            for param_name in params.keys():
                for payload in self.EL_INJECTION_PAYLOADS:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                        test_response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        # Check for EL evaluation (49 from 7*7)
                        # Use regex to avoid false positives from status codes, etc.
                        if (re.search(r'\b49\b', test_response.text) or 
                            'applicationScope' in test_response.text):
                            finding = VulnerabilityFinding(
                                vulnerability_type='rce',
                                severity='high',
                                url=url,
                                description=f'Expression Language injection detected in parameter "{param_name}"',
                                evidence=f'Payload: {payload}, Expression evaluated in response',
                                remediation='Sanitize all user input before EL evaluation, use safe EL resolvers, and avoid evaluating user-controlled expressions.',
                                parameter=param_name,
                                confidence=0.8,
                                cwe_id='CWE-94'
                            )
                            findings.append(finding)
                            logger.info(f"Found EL injection in {param_name}")
                            break
                    except Exception as e:
                        logger.debug(f"Error testing EL injection: {e}")
        
        except Exception as e:
            logger.error(f"Error in EL injection testing: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for RCE scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_command_injection': True,
            'test_template_injection': True,
            'test_el_injection': True,
        }
