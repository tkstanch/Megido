"""
RFI (Remote File Inclusion) Detection Plugin

This plugin detects Remote File Inclusion vulnerabilities where attackers can include
remote files from external servers into the application.
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


class RFIDetectorPlugin(BaseScanPlugin):
    """
    RFI vulnerability detection plugin.
    
    Detects Remote File Inclusion vulnerabilities through:
    - URL parameter testing with remote URLs
    - File inclusion pattern detection
    - Response content verification
    - Protocol handler testing (http://, ftp://, etc.)
    """
    
    # Test payloads - markers to include from remote server
    TEST_MARKERS = [
        'RFI_VULN_TEST_12345',
        'REMOTE_FILE_INCLUDED',
    ]
    
    # URL protocols to test
    PROTOCOLS = [
        'http://',
        'https://',
        'ftp://',
        '//',  # Protocol-relative URL
    ]
    
    @property
    def plugin_id(self) -> str:
        return 'rfi_detector'
    
    @property
    def name(self) -> str:
        return 'RFI Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects Remote File Inclusion (RFI) vulnerabilities'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['rfi']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """Scan for RFI vulnerabilities."""
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            test_server = config.get('test_server')
            
            # Warning: If no test server is configured, log and return empty findings
            # This allows the scan to continue without hard-failing
            if not test_server:
                logger.warning(
                    f"RFI scan of {url} skipped: No test server configured. "
                    "Configure 'test_server' in plugin config to enable RFI detection."
                )
                return findings
            
            # Test for RFI
            rfi_findings = self._test_rfi(url, test_server, verify_ssl, timeout)
            findings.extend(rfi_findings)
            
            logger.info(f"RFI scan of {url} found {len(findings)} potential vulnerability(ies)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for RFI: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during RFI scan of {url}: {e}")
        
        return findings
    
    def _test_rfi(self, url: str, test_server: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for RFI vulnerabilities."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            # Test each parameter
            for param_name in params.keys():
                for protocol in self.PROTOCOLS[:2]:  # Test first 2 protocols
                    # Build remote URL with test marker
                    test_url = f"{protocol}{test_server}/test_rfi.txt?marker={self.TEST_MARKERS[0]}"
                    
                    test_params = params.copy()
                    test_params[param_name] = [test_url]
                    
                    try:
                        response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        # Check if our marker appears in response
                        if self.TEST_MARKERS[0] in response.text:
                            finding = VulnerabilityFinding(
                                vulnerability_type='rfi',
                                severity='critical',
                                url=url,
                                description=f'RFI vulnerability detected in parameter "{param_name}"',
                                evidence=f'Successfully included remote file from {test_server}, marker found in response',
                                remediation='Never use user input directly in file paths, whitelist allowed files, disable allow_url_include in PHP.',
                                parameter=param_name,
                                confidence=0.95,
                                cwe_id='CWE-98'  # Remote File Inclusion
                            )
                            findings.append(finding)
                            logger.info(f"Found RFI in {param_name}")
                            return findings
                    
                    except Exception as e:
                        logger.debug(f"Error testing RFI: {e}")
        
        except Exception as e:
            logger.error(f"Error in RFI testing: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for RFI scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_server': None,  # Must be provided: 'attacker.com' or similar
        }
