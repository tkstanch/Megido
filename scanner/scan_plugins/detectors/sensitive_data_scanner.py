"""
Sensitive Data Detection Plugin - Enhanced Edition

This plugin detects exposed sensitive information including:
- 30+ API keys and tokens (AWS, Azure, GCP, Slack, etc.)
- Credentials and passwords
- Private keys and certificates
- Database connection strings
- Personal identifiable information (PII)
- Credit card numbers with Luhn validation
- Crypto wallet addresses
- Internal IP addresses
- Configuration files
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
    Enhanced sensitive data exposure detection plugin.
    
    Scans for 30+ types of exposed sensitive information:
    - Cloud provider keys (AWS, Azure, GCP, etc.)
    - Third-party service tokens (Slack, GitHub, Stripe, etc.)
    - Database credentials
    - Private keys
    - PII (SSN, credit cards, emails, phones)
    - Crypto wallet addresses
    - Internal network information
    """
    
    # Comprehensive sensitive data patterns
    PATTERNS = {
        # Cloud Provider Keys
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'description': 'AWS Access Key ID',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'aws_secret_key': {
            'pattern': r'aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            'description': 'AWS Secret Access Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'aws_session_token': {
            'pattern': r'aws_session_token\s*[:=]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
            'description': 'AWS Session Token',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'azure_storage_key': {
            'pattern': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});',
            'description': 'Azure Storage Account Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'azure_tenant_id': {
            'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'description': 'Azure Tenant/Client ID',
            'severity': 'medium',
            'cwe_id': 'CWE-200'
        },
        'gcp_api_key': {
            'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
            'description': 'Google Cloud Platform API Key',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'gcp_service_account': {
            'pattern': r'"private_key":\s*"-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----"',
            'description': 'GCP Service Account Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        
        # Third-Party Service Tokens
        'stripe_live_key': {
            'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
            'description': 'Stripe Live Secret Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'stripe_restricted_key': {
            'pattern': r'rk_live_[0-9a-zA-Z]{24,}',
            'description': 'Stripe Restricted Key',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'github_pat': {
            'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'description': 'GitHub Personal Access Token',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'github_oauth': {
            'pattern': r'gho_[A-Za-z0-9]{36}',
            'description': 'GitHub OAuth Token',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'gitlab_token': {
            'pattern': r'glpat-[A-Za-z0-9_-]{20}',
            'description': 'GitLab Personal Access Token',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
            'description': 'Slack Token',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'slack_webhook': {
            'pattern': r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}',
            'description': 'Slack Webhook URL',
            'severity': 'medium',
            'cwe_id': 'CWE-200'
        },
        'twilio_api_key': {
            'pattern': r'SK[a-f0-9]{32}',
            'description': 'Twilio API Key',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'mailgun_api_key': {
            'pattern': r'key-[0-9a-zA-Z]{32}',
            'description': 'Mailgun API Key',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'sendgrid_api_key': {
            'pattern': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            'description': 'SendGrid API Key',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        
        # Authentication & Secrets
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'description': 'JWT Token',
            'severity': 'medium',
            'cwe_id': 'CWE-200'
        },
        'private_key_rsa': {
            'pattern': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'description': 'Private Key',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'generic_api_key': {
            'pattern': r'api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            'description': 'Generic API Key',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'generic_secret': {
            'pattern': r'secret\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            'description': 'Generic Secret',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        'password_in_code': {
            'pattern': r'password\s*[:=]\s*["\']([^"\']{8,})["\']',
            'description': 'Hardcoded Password',
            'severity': 'high',
            'cwe_id': 'CWE-798'
        },
        
        # Database Credentials
        'postgres_connection': {
            'pattern': r'postgres://[^:]+:[^@]+@[^/]+',
            'description': 'PostgreSQL Connection String with Credentials',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'mysql_connection': {
            'pattern': r'mysql://[^:]+:[^@]+@[^/]+',
            'description': 'MySQL Connection String with Credentials',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        'mongodb_connection': {
            'pattern': r'mongodb(\+srv)?://[^:]+:[^@]+@[^/]+',
            'description': 'MongoDB Connection String with Credentials',
            'severity': 'critical',
            'cwe_id': 'CWE-798'
        },
        
        # PII
        'ssn': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'description': 'Social Security Number (SSN)',
            'severity': 'high',
            'cwe_id': 'CWE-359'  # Exposure of Private Personal Information
        },
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'description': 'Credit Card Number',
            'severity': 'critical',
            'cwe_id': 'CWE-359',
            'validate': 'luhn'
        },
        'email': {
            'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'description': 'Email Address (PII)',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
        'phone_us': {
            'pattern': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
            'description': 'US Phone Number',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
        
        # Crypto
        'bitcoin_address': {
            'pattern': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'description': 'Bitcoin Wallet Address',
            'severity': 'medium',
            'cwe_id': 'CWE-200'
        },
        'ethereum_address': {
            'pattern': r'\b0x[a-fA-F0-9]{40}\b',
            'description': 'Ethereum Wallet Address',
            'severity': 'medium',
            'cwe_id': 'CWE-200'
        },
        
        # Network & Infrastructure
        'internal_ip': {
            'pattern': r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b',
            'description': 'Internal IP Address',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
        
        # Development & Debug
        'stack_trace': {
            'pattern': r'(?:Exception|Error|Traceback|at\s+[\w\.]+\([\w\.]+:\d+\))',
            'description': 'Stack Trace / Error Message',
            'severity': 'low',
            'cwe_id': 'CWE-209'  # Generation of Error Message with Sensitive Information
        },
        'todo_comment': {
            'pattern': r'(?:TODO|FIXME|HACK|XXX):\s*([^\n]{10,})',
            'description': 'TODO/FIXME Comment (potential info leak)',
            'severity': 'info',
            'cwe_id': 'CWE-200'
        },
    }
    
    @property
    def plugin_id(self) -> str:
        return 'sensitive_data_scanner'
    
    @property
    def name(self) -> str:
        return 'Enhanced Sensitive Data Exposure Scanner'
    
    @property
    def description(self) -> str:
        return 'Detects 30+ types of sensitive information including API keys, credentials, PII, and crypto'
    
    @property
    def version(self) -> str:
        return '3.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['info_disclosure', 'credential_exposure', 'pii_exposure']
    
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
            
            # Also check headers
            headers_str = str(response.headers)
            
            # Combine content sources
            combined_content = content + '\n' + headers_str
            
            # Track findings per pattern to avoid duplicates
            pattern_findings = {}
            
            # Check each pattern
            for pattern_name, pattern_info in self.PATTERNS.items():
                matches = list(re.finditer(pattern_info['pattern'], combined_content, re.IGNORECASE | re.MULTILINE))
                
                if matches:
                    # Limit findings per pattern
                    max_per_pattern = config.get('max_findings_per_pattern', 3)
                    
                    for match in matches[:max_per_pattern]:
                        matched_text = match.group(0)
                        
                        # Validate if required
                        if pattern_info.get('validate') == 'luhn':
                            if not self._validate_luhn(matched_text.replace(' ', '').replace('-', '')):
                                continue  # Skip invalid credit card
                        
                        # Sanitize the matched text for display
                        sanitized = self._sanitize_sensitive_data(matched_text)
                        
                        finding = VulnerabilityFinding(
                            vulnerability_type='info_disclosure',
                            severity=pattern_info['severity'],
                            url=url,
                            description=f'Exposed {pattern_info["description"]}',
                            evidence=f'Found pattern: {sanitized} (sanitized)',
                            remediation=f'Remove exposed {pattern_info["description"]} from public responses. Store secrets securely using environment variables or secret management systems.',
                            confidence=0.85,
                            cwe_id=pattern_info['cwe_id']
                        )
                        findings.append(finding)
                    
                    if len(matches) > max_per_pattern:
                        logger.info(f"Found {len(matches)} instances of {pattern_name}, showing first {max_per_pattern}")
            
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
    
    def _validate_luhn(self, card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        
        Args:
            card_number: Credit card number to validate
        
        Returns:
            True if valid, False otherwise
        """
        try:
            digits = [int(d) for d in card_number]
            checksum = 0
            
            # Process from right to left
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:  # Every second digit from right
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            
            return checksum % 10 == 0
        except (ValueError, TypeError):
            return False
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for sensitive data scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_headers': True,
            'check_cookies': True,
            'check_comments': True,
            'max_findings_per_pattern': 3,
        }
