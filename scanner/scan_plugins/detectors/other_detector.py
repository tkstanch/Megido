"""
Generic Vulnerability Detection Plugin

This plugin detects various other vulnerability types not covered by specific detectors.
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


class OtherDetectorPlugin(BaseScanPlugin):
    """Generic vulnerability detection plugin."""
    
    # Generic vulnerability indicators
    INDICATORS = {
        'debug_mode': ['debug=true', 'debug:true', 'DEBUG', 'TRACE'],
        'admin_panel': ['/admin', '/administrator', '/wp-admin', '/phpmyadmin'],
        'backup_files': ['.bak', '.backup', '.old', '.tmp', '~'],
        'default_creds': ['admin:admin', 'root:root', 'admin:password'],
    }
    
    @property
    def plugin_id(self) -> str:
        return 'other_detector'
    
    @property
    def name(self) -> str:
        return 'Generic Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects miscellaneous vulnerabilities'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['other']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """Scan for generic vulnerabilities."""
        if not HAS_REQUESTS:
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            content = response.text.lower()
            
            # Check for debug mode
            for indicator in self.INDICATORS['debug_mode']:
                if indicator.lower() in content:
                    finding = VulnerabilityFinding(
                        vulnerability_type='other',
                        severity='low',
                        url=url,
                        description='Debug mode appears to be enabled',
                        evidence=f'Found indicator: {indicator}',
                        remediation='Disable debug mode in production',
                        confidence=0.6,
                        cwe_id='CWE-489'
                    )
                    findings.append(finding)
                    break
            
            logger.info(f"Generic scan found {len(findings)} issue(s)")
            
        except Exception as e:
            logger.error(f"Error during generic scan: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        return {'verify_ssl': False, 'timeout': 10}
