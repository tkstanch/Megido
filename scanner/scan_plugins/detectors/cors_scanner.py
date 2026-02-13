"""
CORS Policy Scanner Plugin

This plugin performs comprehensive CORS (Cross-Origin Resource Sharing) security analysis:
- CORS header analysis
- Wildcard origin detection
- Credentials exposure via CORS
- Preflight request testing
- Allowed methods and headers validation
"""

import logging
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class CORSScannerPlugin(BaseScanPlugin):
    """
    CORS policy scanner plugin.
    
    Analyzes Cross-Origin Resource Sharing (CORS) configuration:
    - Access-Control-Allow-Origin validation
    - Wildcard origin detection
    - Credentials exposure
    - Preflight request analysis
    - Allowed methods and headers
    """
    
    # Test origins to check CORS reflection
    TEST_ORIGINS = [
        'https://evil.com',
        'https://attacker.com',
        'http://malicious.example',
        'null',
    ]
    
    # Dangerous HTTP methods
    DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
    
    @property
    def plugin_id(self) -> str:
        return 'cors_scanner'
    
    @property
    def name(self) -> str:
        return 'CORS Policy Scanner'
    
    @property
    def description(self) -> str:
        return 'Comprehensive CORS security analysis including origin validation and credentials exposure'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['security_misconfiguration', 'cors_misconfiguration']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for CORS misconfigurations.
        
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
            
            # Check basic CORS headers
            basic_findings = self._check_basic_cors(url, verify_ssl, timeout)
            findings.extend(basic_findings)
            
            # Test origin reflection
            reflection_findings = self._test_origin_reflection(url, verify_ssl, timeout)
            findings.extend(reflection_findings)
            
            # Test preflight requests
            if config.get('test_preflight', True):
                preflight_findings = self._test_preflight(url, verify_ssl, timeout)
                findings.extend(preflight_findings)
            
            logger.info(f"CORS scan of {url} found {len(findings)} issue(s)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for CORS issues: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during CORS scan of {url}: {e}")
        
        return findings
    
    def _check_basic_cors(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Check basic CORS headers."""
        findings = []
        
        try:
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            headers = response.headers
            
            # Check for wildcard origin
            allow_origin = headers.get('Access-Control-Allow-Origin', '')
            allow_credentials = headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if allow_origin == '*':
                severity = 'high' if allow_credentials == 'true' else 'medium'
                finding = VulnerabilityFinding(
                    vulnerability_type='cors_misconfiguration',
                    severity=severity,
                    url=url,
                    description='CORS allows all origins (wildcard)',
                    evidence=f'Access-Control-Allow-Origin: *',
                    remediation='Specify explicit allowed origins instead of using wildcard (*)',
                    confidence=0.95,
                    cwe_id='CWE-942'  # Permissive Cross-domain Policy
                )
                findings.append(finding)
                
                # Wildcard with credentials is especially dangerous
                if allow_credentials == 'true':
                    finding = VulnerabilityFinding(
                        vulnerability_type='cors_misconfiguration',
                        severity='critical',
                        url=url,
                        description='CORS wildcard origin with credentials enabled',
                        evidence='Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
                        remediation='Never use wildcard origin with credentials. Specify explicit trusted origins.',
                        confidence=0.98,
                        cwe_id='CWE-942'
                    )
                    findings.append(finding)
            
            # Check for null origin
            if allow_origin == 'null':
                finding = VulnerabilityFinding(
                    vulnerability_type='cors_misconfiguration',
                    severity='high',
                    url=url,
                    description='CORS allows null origin',
                    evidence='Access-Control-Allow-Origin: null',
                    remediation='Do not allow null origin as it can be exploited via sandboxed iframes',
                    confidence=0.9,
                    cwe_id='CWE-942'
                )
                findings.append(finding)
            
            # Check for overly permissive methods
            allow_methods = headers.get('Access-Control-Allow-Methods', '')
            if allow_methods:
                for dangerous_method in self.DANGEROUS_METHODS:
                    if dangerous_method in allow_methods.upper():
                        finding = VulnerabilityFinding(
                            vulnerability_type='cors_misconfiguration',
                            severity='medium',
                            url=url,
                            description=f'CORS allows dangerous HTTP method: {dangerous_method}',
                            evidence=f'Access-Control-Allow-Methods: {allow_methods}',
                            remediation=f'Remove {dangerous_method} from allowed methods if not required',
                            confidence=0.8,
                            cwe_id='CWE-942'
                        )
                        findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error checking basic CORS: {e}")
        
        return findings
    
    def _test_origin_reflection(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test if server reflects arbitrary origins."""
        findings = []
        
        for test_origin in self.TEST_ORIGINS[:2]:  # Test first 2 origins
            try:
                headers = {'Origin': test_origin}
                response = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl)
                
                allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
                allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                # Check if server reflects our test origin
                if allow_origin == test_origin:
                    severity = 'high' if allow_credentials == 'true' else 'medium'
                    finding = VulnerabilityFinding(
                        vulnerability_type='cors_misconfiguration',
                        severity=severity,
                        url=url,
                        description='CORS reflects arbitrary origins',
                        evidence=f'Server reflects Origin: {test_origin}',
                        remediation='Implement proper origin validation against a whitelist of trusted domains',
                        confidence=0.95,
                        cwe_id='CWE-942'
                    )
                    findings.append(finding)
                    
                    # With credentials is critical
                    if allow_credentials == 'true':
                        finding = VulnerabilityFinding(
                            vulnerability_type='cors_misconfiguration',
                            severity='critical',
                            url=url,
                            description='CORS reflects arbitrary origins with credentials enabled',
                            evidence=f'Server reflects {test_origin} with Access-Control-Allow-Credentials: true',
                            remediation='This is a critical vulnerability. Implement strict origin validation.',
                            confidence=0.98,
                            cwe_id='CWE-942'
                        )
                        findings.append(finding)
                    
                    break  # No need to test more if reflection is found
            
            except Exception as e:
                logger.debug(f"Error testing origin reflection: {e}")
        
        return findings
    
    def _test_preflight(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test CORS preflight (OPTIONS) requests."""
        findings = []
        
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'PUT',
                'Access-Control-Request-Headers': 'X-Custom-Header',
            }
            
            response = requests.options(url, headers=headers, timeout=timeout, verify=verify_ssl)
            
            # Check if preflight is allowed
            allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
            allow_methods = response.headers.get('Access-Control-Allow-Methods', '')
            
            if allow_origin and allow_methods:
                # Check for overly permissive preflight
                if '*' in allow_methods or 'PUT' in allow_methods.upper():
                    finding = VulnerabilityFinding(
                        vulnerability_type='cors_misconfiguration',
                        severity='medium',
                        url=url,
                        description='CORS preflight allows potentially dangerous operations',
                        evidence=f'OPTIONS request allowed with methods: {allow_methods}',
                        remediation='Restrict allowed methods in preflight responses to minimum required',
                        confidence=0.7,
                        cwe_id='CWE-942'
                    )
                    findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error testing preflight: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for CORS scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_preflight': True,
            'test_origin_reflection': True,
        }
