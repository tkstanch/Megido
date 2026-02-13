"""
Open Redirect Detection Plugin

This plugin detects Open Redirect vulnerabilities where attackers can redirect users
to malicious external sites.
"""

import logging
from typing import Dict, List, Any, Optional
from urllib.parse import parse_qs, urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class OpenRedirectDetectorPlugin(BaseScanPlugin):
    """Open Redirect vulnerability detection plugin."""
    
    # Test redirect targets
    TEST_DOMAINS = [
        'http://evil.com',
        'https://attacker.com',
        '//evil.com',
        'javascript:alert(1)',
    ]
    
    @property
    def plugin_id(self) -> str:
        return 'open_redirect_detector'
    
    @property
    def name(self) -> str:
        return 'Open Redirect Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects Open Redirect vulnerabilities'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['open_redirect']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """Scan for Open Redirect vulnerabilities."""
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            findings = self._test_open_redirect(url, verify_ssl, timeout)
            logger.info(f"Open Redirect scan of {url} found {len(findings)} vulnerability(ies)")
            
        except Exception as e:
            logger.error(f"Error during Open Redirect scan: {e}")
        
        return findings
    
    def _test_open_redirect(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for open redirect vulnerabilities."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            for param_name in params.keys():
                for test_domain in self.TEST_DOMAINS[:2]:
                    test_params = params.copy()
                    test_params[param_name] = [test_domain]
                    
                    try:
                        response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl,
                            allow_redirects=False
                        )
                        
                        # Check for redirect
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if test_domain in location or 'evil.com' in location or 'attacker.com' in location:
                                finding = VulnerabilityFinding(
                                    vulnerability_type='open_redirect',
                                    severity='medium',
                                    url=url,
                                    description=f'Open Redirect vulnerability in parameter "{param_name}"',
                                    evidence=f'Redirect to external domain: {location}',
                                    remediation='Validate redirect URLs against whitelist, use relative URLs, implement redirect token validation.',
                                    parameter=param_name,
                                    confidence=0.9,
                                    cwe_id='CWE-601'
                                )
                                findings.append(finding)
                                return findings
                    
                    except Exception as e:
                        logger.debug(f"Error testing open redirect: {e}")
        
        except Exception as e:
            logger.error(f"Error in open redirect testing: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
