"""
SSL/TLS Scanner Plugin

This plugin checks for SSL/TLS configuration issues.
"""

import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class SSLScannerPlugin(BaseScanPlugin):
    """
    SSL/TLS configuration scanner plugin.
    
    Checks for:
    - Use of insecure HTTP instead of HTTPS
    - Other SSL/TLS configuration issues (TODO: expand in future)
    """
    
    @property
    def plugin_id(self) -> str:
        return 'ssl_scanner'
    
    @property
    def name(self) -> str:
        return 'SSL/TLS Scanner'
    
    @property
    def description(self) -> str:
        return 'Checks for SSL/TLS configuration issues'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['info_disclosure', 'other']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for SSL/TLS issues.
        
        Args:
            url: Target URL to scan
            config: Configuration dictionary
        
        Returns:
            List of vulnerability findings
        """
        config = config or self.get_default_config()
        findings = []
        
        try:
            parsed = urlparse(url)
            
            # Check if using insecure HTTP
            if parsed.scheme == 'http':
                finding = VulnerabilityFinding(
                    vulnerability_type='info_disclosure',
                    severity='medium',
                    url=url,
                    description='Site uses insecure HTTP protocol',
                    evidence='URL scheme is http:// instead of https://',
                    remediation='Implement HTTPS with valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.',
                    confidence=0.95,  # Very high confidence
                    cwe_id='CWE-319'  # Cleartext Transmission of Sensitive Information
                )
                findings.append(finding)
            
            # TODO: Add more SSL/TLS checks in future phases:
            # - Certificate validation
            # - Weak cipher suites
            # - Protocol version issues
            # - Certificate expiration
            
            logger.info(f"SSL/TLS scan of {url} found {len(findings)} issue(s)")
            
        except Exception as e:
            logger.error(f"Unexpected error during SSL/TLS scan of {url}: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for SSL/TLS scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
