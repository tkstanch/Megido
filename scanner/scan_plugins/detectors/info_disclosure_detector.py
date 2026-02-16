"""
Information Disclosure Detection Plugin

Enhanced plugin for detecting information leakage and sensitive data exposure.
Now captures real request/response data for repeater app integration.
"""

import logging
import re
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding, create_repeater_request

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
        """Scan for information disclosure vulnerabilities with request/response capture."""
        if not HAS_REQUESTS:
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            content = response.text + '\n' + str(response.headers)
            
            # Track patterns found for verification
            patterns_found = {}
            
            for pattern_name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    patterns_found[pattern_name] = matches
            
            # Create findings with enhanced data
            for pattern_name, matches in patterns_found.items():
                # Determine if this is verified based on pattern type
                is_verified = self._is_pattern_verified(pattern_name, matches, response)
                
                # Extract sample matches for evidence (limit to first 3)
                sample_matches = matches[:3]
                evidence_details = f'Found {len(matches)} instance(s) of {pattern_name}. '
                evidence_details += f'Samples: {", ".join(str(m)[:50] for m in sample_matches)}'
                
                # Create repeater request for manual verification
                repeater_req = create_repeater_request(
                    url=url,
                    method='GET',
                    headers={
                        'User-Agent': 'Megido Scanner',
                        'Accept': '*/*'
                    },
                    description=f'Request that disclosed {pattern_name}'
                )
                
                finding = VulnerabilityFinding(
                    vulnerability_type='info_disclosure',
                    severity=self._get_severity(pattern_name),
                    url=url,
                    description=f'Information disclosure: {pattern_name} detected',
                    evidence=evidence_details,
                    remediation='Remove sensitive data from responses, implement proper access controls.',
                    confidence=0.8,
                    cwe_id='CWE-200',
                    verified=is_verified,
                    successful_payloads=None,  # Detection, not exploitation
                    repeater_requests=[repeater_req]
                )
                findings.append(finding)
            
            logger.info(f"Info disclosure scan found {len(findings)} issue(s)")
            
        except Exception as e:
            logger.error(f"Error during info disclosure scan: {e}")
        
        return findings
    
    def _is_pattern_verified(self, pattern_name: str, matches: List, response) -> bool:
        """
        Determine if a pattern match represents a verified vulnerability.
        
        Patterns like stack_trace, private_key, aws_key, password are high-confidence
        and considered verified. Generic patterns like email, ip_address need context.
        """
        # High-confidence patterns that indicate definite vulnerability
        verified_patterns = {
            'stack_trace', 'private_key', 'aws_key', 'password', 
            'database', 'jwt', 'api_key', 'credit_card', 'ssn'
        }
        
        return pattern_name in verified_patterns
    
    def _get_severity(self, pattern_name: str) -> str:
        """Get severity level based on pattern type."""
        critical_patterns = {'private_key', 'aws_key', 'password', 'database', 'credit_card', 'ssn'}
        high_patterns = {'api_key', 'jwt', 'stack_trace'}
        
        if pattern_name in critical_patterns:
            return 'critical'
        elif pattern_name in high_patterns:
            return 'high'
        else:
            return 'medium'
    
    def get_default_config(self) -> Dict[str, Any]:
        return {'verify_ssl': False, 'timeout': 10}
