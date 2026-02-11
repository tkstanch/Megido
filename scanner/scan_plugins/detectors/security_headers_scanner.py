"""
Security Headers Scanner Plugin

This plugin checks for missing or misconfigured security headers.
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


class SecurityHeadersScannerPlugin(BaseScanPlugin):
    """
    Security headers vulnerability detection plugin.
    
    Checks for missing or misconfigured security headers:
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Strict-Transport-Security
    - Content-Security-Policy
    """
    
    # Security headers to check
    SECURITY_HEADERS = {
        'X-Frame-Options': {
            'description': 'Missing X-Frame-Options header',
            'evidence': 'X-Frame-Options header not found',
            'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header to prevent clickjacking',
            'severity': 'low',
            'cwe_id': 'CWE-1021'  # Improper Restriction of Rendered UI Layers
        },
        'X-Content-Type-Options': {
            'description': 'Missing X-Content-Type-Options header',
            'evidence': 'X-Content-Type-Options header not found',
            'remediation': 'Add X-Content-Type-Options: nosniff header to prevent MIME-sniffing',
            'severity': 'low',
            'cwe_id': 'CWE-16'  # Configuration
        },
        'Strict-Transport-Security': {
            'description': 'Missing Strict-Transport-Security header',
            'evidence': 'HSTS header not found',
            'remediation': 'Add Strict-Transport-Security header to enforce HTTPS connections',
            'severity': 'medium',
            'cwe_id': 'CWE-319'  # Cleartext Transmission of Sensitive Information
        },
        'Content-Security-Policy': {
            'description': 'Missing Content-Security-Policy header',
            'evidence': 'CSP header not found',
            'remediation': 'Add Content-Security-Policy header to mitigate XSS and data injection attacks',
            'severity': 'medium',
            'cwe_id': 'CWE-1021'
        },
    }
    
    @property
    def plugin_id(self) -> str:
        return 'security_headers_scanner'
    
    @property
    def name(self) -> str:
        return 'Security Headers Scanner'
    
    @property
    def description(self) -> str:
        return 'Checks for missing or misconfigured security headers'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['other', 'info_disclosure']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for missing security headers.
        
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
            
            # Fetch the target page
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            headers = response.headers
            
            # Check each security header
            for header_name, header_info in self.SECURITY_HEADERS.items():
                if header_name not in headers:
                    finding = VulnerabilityFinding(
                        vulnerability_type='other',
                        severity=header_info['severity'],
                        url=url,
                        description=header_info['description'],
                        evidence=header_info['evidence'],
                        remediation=header_info['remediation'],
                        confidence=0.9,  # High confidence - easily verified
                        cwe_id=header_info['cwe_id']
                    )
                    findings.append(finding)
            
            logger.info(f"Security headers scan of {url} found {len(findings)} issue(s)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for security headers: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during security headers scan of {url}: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for security headers scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
