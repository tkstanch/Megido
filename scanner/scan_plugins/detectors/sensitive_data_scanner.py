"""
Sensitive Data Detection Plugin

This plugin detects exposed sensitive information including:
- API keys and tokens
- Credentials and passwords
- Private keys and certificates
- Database connection strings
- Personal identifiable information (PII)

Uses pattern matching and optional ML-based anomaly detection.
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class SensitiveDataScannerPlugin(BaseScanPlugin):
    """
    Sensitive data exposure detection plugin.
    
    Scans for exposed sensitive information such as:
    - API keys (AWS, Stripe, Google, etc.)
    - Authentication tokens
    - Database credentials
    - Private keys
    - Email addresses and PII
    """
    
    # Sensitive data patterns
    PATTERNS = {
        'aws_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'description': 'AWS Access Key ID',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'aws_secret': {
            'pattern': r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            'description': 'AWS Secret Access Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'stripe_key': {
            'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
            'description': 'Stripe Live Secret Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'google_api': {
            'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
            'description': 'Google API Key',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'github_token': {
            'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'description': 'GitHub Personal Access Token',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'description': 'JWT Token',
            'severity': 'medium',
            'cwe_id': 'CWE-200'
        },
        'private_key': {
            'pattern': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'description': 'Private Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'db_connection': {
            'pattern': r'(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+',
            'description': 'Database Connection String with Credentials',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'password_field': {
            'pattern': r'password\s*[:=]\s*["\']([^"\']{8,})["\']',
            'description': 'Hardcoded Password',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'email': {
            'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'description': 'Email Address (PII)',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
    }
    
    @property
    def plugin_id(self) -> str:
        return 'sensitive_data_scanner'
    
    @property
    def name(self) -> str:
        return 'Sensitive Data Exposure Scanner'
    
    @property
    def description(self) -> str:
        return 'Detects exposed sensitive information including API keys, credentials, and PII'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['info_disclosure', 'credential_exposure']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for exposed sensitive data.
        
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
            content = response.text
            
            # Also check headers and response metadata
            headers_str = str(response.headers)
            combined_content = content + '\n' + headers_str
            
            # Check each pattern
            for pattern_name, pattern_info in self.PATTERNS.items():
                matches = re.finditer(pattern_info['pattern'], combined_content, re.IGNORECASE)
                
                for match in matches:
                    # Found sensitive data
                    matched_text = match.group(0)
                    
                    # Sanitize the matched text for display (mask it)
                    sanitized = self._sanitize_sensitive_data(matched_text)
                    
                    finding = VulnerabilityFinding(
                        vulnerability_type='info_disclosure',
                        severity=pattern_info['severity'],
                        url=url,
                        description=f'Exposed {pattern_info["description"]}',
                        evidence=f'Found pattern: {sanitized} (sanitized)',
                        remediation=f'Remove exposed {pattern_info["description"]} from public responses. Store secrets securely using environment variables or secret management systems.',
                        confidence=0.85,  # High confidence for pattern matching
                        cwe_id=pattern_info['cwe_id']
                    )
                    findings.append(finding)
                    
                    # Limit findings per pattern to avoid spam
                    if len([f for f in findings if pattern_name in f.description.lower()]) >= 3:
                        break
            
            logger.info(f"Sensitive data scan of {url} found {len(findings)} exposure(s)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for sensitive data: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during sensitive data scan of {url}: {e}")
        
        return findings
    
    def _sanitize_sensitive_data(self, text: str) -> str:
        """
        Sanitize sensitive data for display.
        
        Args:
            text: Raw sensitive data
        
        Returns:
            Sanitized version safe for display
        """
        if len(text) <= 8:
            return '*' * len(text)
        
        # Show first 4 and last 4 characters
        return f"{text[:4]}...{text[-4:]}"
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for sensitive data scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_headers': True,
            'check_cookies': True,
            'check_comments': True,
            # TODO: Enable ML-based anomaly detection
            'use_ml': False,
        }
