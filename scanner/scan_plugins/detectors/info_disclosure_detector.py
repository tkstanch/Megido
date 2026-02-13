"""
Information Disclosure Detection Plugin

Enhanced plugin for detecting information leakage and sensitive data exposure.
"""

import logging
import re
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class InfoDisclosureDetectorPlugin(BaseScanPlugin):
    """Information Disclosure detection plugin."""
    
    # Patterns for sensitive information
    PATTERNS = {
        'api_key': r'(api[_-]?key|apikey)["\s:=]+([a-zA-Z0-9_-]{20,})',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (RSA |)PRIVATE KEY-----',
        'password': r'(password|passwd|pwd)["\s:=]+[^\s]{6,}',
        'database': r'(mysql://|postgres://|mongodb://)[^\s]+',
        'jwt': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'stack_trace': r'(Exception|Error|Traceback|at\s+[\w\.]+\([\w\.]+:\d+\))',
    }
    
    @property
    def plugin_id(self) -> str:
        return 'info_disclosure_detector'
    
    @property
    def name(self) -> str:
        return 'Information Disclosure Detector'
    
    @property
    def description(self) -> str:
        return 'Detects sensitive data exposure and information leakage'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['info_disclosure']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """Scan for information disclosure vulnerabilities."""
        if not HAS_REQUESTS:
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            content = response.text + '\n' + str(response.headers)
            
            for pattern_name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    finding = VulnerabilityFinding(
                        vulnerability_type='info_disclosure',
                        severity='medium' if pattern_name in ['email', 'ip_address'] else 'high',
                        url=url,
                        description=f'Information disclosure: {pattern_name} detected',
                        evidence=f'Found {len(matches)} instance(s) of {pattern_name}',
                        remediation='Remove sensitive data from responses, implement proper access controls.',
                        confidence=0.8,
                        cwe_id='CWE-200'
                    )
                    findings.append(finding)
            
            logger.info(f"Info disclosure scan found {len(findings)} issue(s)")
            
        except Exception as e:
            logger.error(f"Error during info disclosure scan: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        return {'verify_ssl': False, 'timeout': 10}
