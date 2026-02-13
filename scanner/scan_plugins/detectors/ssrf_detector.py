"""
SSRF (Server-Side Request Forgery) Detection Plugin

This plugin detects Server-Side Request Forgery vulnerabilities where attackers can
force the server to make requests to internal or external resources.
"""

import logging
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, parse_qs, urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class SSRFDetectorPlugin(BaseScanPlugin):
    """
    SSRF vulnerability detection plugin.
    
    Detects Server-Side Request Forgery vulnerabilities through:
    - Internal network access testing
    - Cloud metadata endpoint detection
    - localhost/127.0.0.1 access testing
    - Port scanning via SSRF
    """
    
    # Response timing threshold for SSRF detection (seconds)
    TIMING_THRESHOLD_SECONDS = 2.0
    
    # Internal/private network targets
    INTERNAL_TARGETS = [
        'localhost',
        '127.0.0.1',
        '127.1',
        '0.0.0.0',
        '::1',
        '169.254.169.254',  # AWS metadata
        '169.254.170.2',    # AWS ECS metadata
        'metadata.google.internal',  # GCP metadata
        '10.0.0.1',
        '172.16.0.1',
        '192.168.0.1',
        '192.168.1.1',
    ]
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'aws': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata/computeMetadata/v1/',
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        ]
    }
    
    @property
    def plugin_id(self) -> str:
        return 'ssrf_detector'
    
    @property
    def name(self) -> str:
        return 'SSRF Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects Server-Side Request Forgery (SSRF) vulnerabilities'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['ssrf']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for SSRF vulnerabilities.
        
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
            
            # Test for internal network access
            if config.get('test_internal_network', True):
                internal_findings = self._test_internal_access(url, verify_ssl, timeout)
                findings.extend(internal_findings)
            
            # Test for cloud metadata access
            if config.get('test_cloud_metadata', True):
                cloud_findings = self._test_cloud_metadata(url, verify_ssl, timeout)
                findings.extend(cloud_findings)
            
            logger.info(f"SSRF scan of {url} found {len(findings)} potential vulnerability(ies)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for SSRF: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during SSRF scan of {url}: {e}")
        
        return findings
    
    def _test_internal_access(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for internal network access via SSRF."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            # Get baseline response time
            try:
                baseline_response = requests.get(url, timeout=timeout, verify=verify_ssl)
                baseline_time = baseline_response.elapsed.total_seconds()
            except:
                baseline_time = 1.0
            
            for param_name in params.keys():
                for target in self.INTERNAL_TARGETS[:5]:  # Test first 5
                    test_params = params.copy()
                    test_params[param_name] = [f'http://{target}/']
                    
                    try:
                        start_time = time.time()
                        test_response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout + 5,
                            verify=verify_ssl
                        )
                        response_time = time.time() - start_time
                        
                        # Check response for signs of SSRF
                        # Different response or timing might indicate internal access
                        if (response_time > baseline_time + self.TIMING_THRESHOLD_SECONDS or 
                            len(test_response.text) != len(baseline_response.text)):
                            
                            # Additional checks for metadata or internal content
                            response_lower = test_response.text.lower()
                            if any(indicator in response_lower for indicator in 
                                  ['ami-id', 'instance-id', 'metadata', 'internal', 'private']):
                                finding = VulnerabilityFinding(
                                    vulnerability_type='ssrf',
                                    severity='high',
                                    url=url,
                                    description=f'SSRF vulnerability detected in parameter "{param_name}" - internal network access',
                                    evidence=f'Accessed internal target: {target}, Response indicates internal content',
                                    remediation='Implement URL whitelisting, disable unused protocols, block internal IP ranges, use DNS rebinding protection.',
                                    parameter=param_name,
                                    confidence=0.85,
                                    cwe_id='CWE-918'  # SSRF
                                )
                                findings.append(finding)
                                logger.info(f"Found SSRF in {param_name}")
                                return findings
                    
                    except requests.Timeout:
                        # Timeout might indicate internal port scanning
                        finding = VulnerabilityFinding(
                            vulnerability_type='ssrf',
                            severity='medium',
                            url=url,
                            description=f'Possible SSRF in parameter "{param_name}" (timeout on internal target)',
                            evidence=f'Request to {target} timed out, may indicate port scanning capability',
                            remediation='Implement URL whitelisting and block internal IP ranges.',
                            parameter=param_name,
                            confidence=0.6,
                            cwe_id='CWE-918'
                        )
                        findings.append(finding)
                        return findings
                    except Exception as e:
                        logger.debug(f"Error testing SSRF with {target}: {e}")
        
        except Exception as e:
            logger.error(f"Error in internal access testing: {e}")
        
        return findings
    
    def _test_cloud_metadata(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for cloud metadata access via SSRF."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            for param_name in params.keys():
                # Test AWS metadata
                for metadata_url in self.CLOUD_METADATA['aws'][:2]:
                    test_params = params.copy()
                    test_params[param_name] = [metadata_url]
                    
                    try:
                        test_response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        # Check for AWS metadata indicators
                        response_text = test_response.text.lower()
                        if any(indicator in response_text for indicator in 
                              ['ami-', 'instance-id', 'iam', 'security-credentials']):
                            finding = VulnerabilityFinding(
                                vulnerability_type='ssrf',
                                severity='critical',
                                url=url,
                                description=f'SSRF vulnerability with cloud metadata access in parameter "{param_name}"',
                                evidence=f'Successfully accessed AWS metadata endpoint: {metadata_url}',
                                remediation='Block access to 169.254.169.254, implement strict URL validation, use IMDSv2 on AWS.',
                                parameter=param_name,
                                confidence=0.95,
                                cwe_id='CWE-918'
                            )
                            findings.append(finding)
                            logger.info(f"Found SSRF with metadata access in {param_name}")
                            return findings
                    except Exception as e:
                        logger.debug(f"Error testing metadata endpoint: {e}")
        
        except Exception as e:
            logger.error(f"Error in cloud metadata testing: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for SSRF scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_internal_network': True,
            'test_cloud_metadata': True,
            'internal_targets': ['localhost', '127.0.0.1', '169.254.169.254'],
        }
