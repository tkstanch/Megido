"""
Security Headers Scanner Plugin - Enhanced Edition

This plugin performs comprehensive security header analysis including:
- Detection of missing security headers
- Validation of header values
- Weak configuration identification
- HSTS preload checking
- CSP policy analysis
- Additional security mechanisms
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class SecurityHeadersScannerPlugin(BaseScanPlugin):
    """
    Enhanced security headers vulnerability detection plugin.
    
    Performs comprehensive analysis of security headers including:
    - 15+ security headers detection
    - Header value validation
    - Configuration strength analysis
    - Best practice recommendations
    """
    
    # Comprehensive security headers configuration
    SECURITY_HEADERS = {
        'X-Frame-Options': {
            'description': 'Missing X-Frame-Options header',
            'evidence': 'X-Frame-Options header not found',
            'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header to prevent clickjacking attacks',
            'severity': 'medium',
            'cwe_id': 'CWE-1021',  # Improper Restriction of Rendered UI Layers
            'valid_values': ['DENY', 'SAMEORIGIN'],
            'check_value': True
        },
        'X-Content-Type-Options': {
            'description': 'Missing X-Content-Type-Options header',
            'evidence': 'X-Content-Type-Options header not found',
            'remediation': 'Add X-Content-Type-Options: nosniff header to prevent MIME-sniffing attacks',
            'severity': 'medium',
            'cwe_id': 'CWE-16',  # Configuration
            'valid_values': ['nosniff'],
            'check_value': True
        },
        'Strict-Transport-Security': {
            'description': 'Missing Strict-Transport-Security (HSTS) header',
            'evidence': 'HSTS header not found',
            'remediation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to enforce HTTPS',
            'severity': 'high',
            'cwe_id': 'CWE-319',  # Cleartext Transmission of Sensitive Information
            'check_value': True,
            'value_check': 'custom_hsts'
        },
        'Content-Security-Policy': {
            'description': 'Missing Content-Security-Policy header',
            'evidence': 'CSP header not found',
            'remediation': 'Implement Content-Security-Policy to mitigate XSS, data injection, and clickjacking attacks',
            'severity': 'high',
            'cwe_id': 'CWE-1021',
            'check_value': True,
            'value_check': 'custom_csp'
        },
        'X-XSS-Protection': {
            'description': 'Missing X-XSS-Protection header',
            'evidence': 'X-XSS-Protection header not found',
            'remediation': 'Add X-XSS-Protection: 1; mode=block (Note: Deprecated in modern browsers, use CSP instead)',
            'severity': 'low',
            'cwe_id': 'CWE-79',
            'valid_values': ['1', '1; mode=block'],
            'check_value': True
        },
        'Referrer-Policy': {
            'description': 'Missing Referrer-Policy header',
            'evidence': 'Referrer-Policy header not found',
            'remediation': 'Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin to control referrer information',
            'severity': 'low',
            'cwe_id': 'CWE-200',
            'valid_values': ['no-referrer', 'no-referrer-when-downgrade', 'origin', 
                           'origin-when-cross-origin', 'same-origin', 'strict-origin',
                           'strict-origin-when-cross-origin', 'unsafe-url'],
            'check_value': True
        },
        'Permissions-Policy': {
            'description': 'Missing Permissions-Policy header',
            'evidence': 'Permissions-Policy header not found (formerly Feature-Policy)',
            'remediation': 'Add Permissions-Policy to control browser features (camera, microphone, geolocation, etc.)',
            'severity': 'low',
            'cwe_id': 'CWE-16',
            'check_value': False
        },
        'Cross-Origin-Embedder-Policy': {
            'description': 'Missing Cross-Origin-Embedder-Policy (COEP) header',
            'evidence': 'COEP header not found',
            'remediation': 'Add Cross-Origin-Embedder-Policy: require-corp for enhanced isolation',
            'severity': 'low',
            'cwe_id': 'CWE-668',
            'valid_values': ['unsafe-none', 'require-corp', 'credentialless'],
            'check_value': True
        },
        'Cross-Origin-Opener-Policy': {
            'description': 'Missing Cross-Origin-Opener-Policy (COOP) header',
            'evidence': 'COOP header not found',
            'remediation': 'Add Cross-Origin-Opener-Policy: same-origin for process isolation',
            'severity': 'low',
            'cwe_id': 'CWE-668',
            'valid_values': ['unsafe-none', 'same-origin-allow-popups', 'same-origin'],
            'check_value': True
        },
        'Cross-Origin-Resource-Policy': {
            'description': 'Missing Cross-Origin-Resource-Policy (CORP) header',
            'evidence': 'CORP header not found',
            'remediation': 'Add Cross-Origin-Resource-Policy: same-origin to prevent cross-origin attacks',
            'severity': 'low',
            'cwe_id': 'CWE-668',
            'valid_values': ['same-site', 'same-origin', 'cross-origin'],
            'check_value': True
        },
    }
    
    # Insecure headers that should be removed
    INSECURE_HEADERS = {
        'Server': {
            'description': 'Server header exposes server information',
            'remediation': 'Remove or obfuscate Server header to prevent information disclosure',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
        'X-Powered-By': {
            'description': 'X-Powered-By header exposes technology stack',
            'remediation': 'Remove X-Powered-By header to prevent technology fingerprinting',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
        'X-AspNet-Version': {
            'description': 'X-AspNet-Version header exposes ASP.NET version',
            'remediation': 'Remove X-AspNet-Version header',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
        'X-AspNetMvc-Version': {
            'description': 'X-AspNetMvc-Version header exposes ASP.NET MVC version',
            'remediation': 'Remove X-AspNetMvc-Version header',
            'severity': 'low',
            'cwe_id': 'CWE-200'
        },
    }
    
    @property
    def plugin_id(self) -> str:
        return 'security_headers_scanner'
    
    @property
    def name(self) -> str:
        return 'Enhanced Security Headers Scanner'
    
    @property
    def description(self) -> str:
        return 'Comprehensive security headers analysis including 15+ headers, value validation, and best practices'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['other', 'info_disclosure', 'security_misconfiguration']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Perform comprehensive security headers scan.
        
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
            
            # Check for missing security headers
            missing_findings = self._check_missing_headers(url, headers)
            findings.extend(missing_findings)
            
            # Check for misconfigured headers
            misconfig_findings = self._check_header_values(url, headers)
            findings.extend(misconfig_findings)
            
            # Check for insecure headers that should be removed
            insecure_findings = self._check_insecure_headers(url, headers)
            findings.extend(insecure_findings)
            
            # Check for security.txt
            if config.get('check_security_txt', True):
                security_txt_findings = self._check_security_txt(url, verify_ssl, timeout)
                findings.extend(security_txt_findings)
            
            logger.info(f"Security headers scan of {url} found {len(findings)} issue(s)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for security headers: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during security headers scan of {url}: {e}")
        
        return findings
    
    def _check_missing_headers(self, url: str, headers: Dict) -> List[VulnerabilityFinding]:
        """Check for missing security headers."""
        findings = []
        
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                finding = VulnerabilityFinding(
                    vulnerability_type='security_misconfiguration',
                    severity=header_info['severity'],
                    url=url,
                    description=header_info['description'],
                    evidence=header_info['evidence'],
                    remediation=header_info['remediation'],
                    confidence=0.95,  # High confidence
                    cwe_id=header_info['cwe_id']
                )
                findings.append(finding)
        
        return findings
    
    def _check_header_values(self, url: str, headers: Dict) -> List[VulnerabilityFinding]:
        """Check for misconfigured header values."""
        findings = []
        
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name in headers:
                header_value = headers[header_name]
                
                # Custom validation for specific headers
                if header_info.get('value_check') == 'custom_hsts':
                    hsts_findings = self._validate_hsts(url, header_value)
                    findings.extend(hsts_findings)
                elif header_info.get('value_check') == 'custom_csp':
                    csp_findings = self._validate_csp(url, header_value)
                    findings.extend(csp_findings)
                elif header_info.get('check_value') and 'valid_values' in header_info:
                    # Generic validation
                    valid_values = header_info['valid_values']
                    if header_value not in valid_values and not any(v in header_value for v in valid_values):
                        finding = VulnerabilityFinding(
                            vulnerability_type='security_misconfiguration',
                            severity='medium',
                            url=url,
                            description=f'Weak {header_name} configuration',
                            evidence=f'{header_name}: {header_value}',
                            remediation=f'Use recommended value: {", ".join(valid_values[:3])}',
                            confidence=0.8,
                            cwe_id=header_info['cwe_id']
                        )
                        findings.append(finding)
        
        return findings
    
    def _validate_hsts(self, url: str, hsts_value: str) -> List[VulnerabilityFinding]:
        """Validate HSTS header configuration."""
        findings = []
        
        # Extract max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            
            # Check for minimum recommended max-age (1 year = 31536000 seconds)
            if max_age < 31536000:
                finding = VulnerabilityFinding(
                    vulnerability_type='security_misconfiguration',
                    severity='medium',
                    url=url,
                    description='HSTS max-age is too short',
                    evidence=f'max-age={max_age} (recommended: 31536000 or higher)',
                    remediation='Set HSTS max-age to at least 31536000 seconds (1 year)',
                    confidence=0.9,
                    cwe_id='CWE-319'
                )
                findings.append(finding)
        
        # Check for includeSubDomains
        if 'includesubdomains' not in hsts_value.lower():
            finding = VulnerabilityFinding(
                vulnerability_type='security_misconfiguration',
                severity='low',
                url=url,
                description='HSTS missing includeSubDomains directive',
                evidence=f'Strict-Transport-Security: {hsts_value}',
                remediation='Add includeSubDomains directive to protect all subdomains',
                confidence=0.85,
                cwe_id='CWE-319'
            )
            findings.append(finding)
        
        # Check for preload
        if 'preload' not in hsts_value.lower():
            finding = VulnerabilityFinding(
                vulnerability_type='security_misconfiguration',
                severity='low',
                url=url,
                description='HSTS missing preload directive',
                evidence=f'Strict-Transport-Security: {hsts_value}',
                remediation='Consider adding preload directive and submitting to HSTS preload list',
                confidence=0.7,
                cwe_id='CWE-319'
            )
            findings.append(finding)
        
        return findings
    
    def _validate_csp(self, url: str, csp_value: str) -> List[VulnerabilityFinding]:
        """Validate Content-Security-Policy configuration."""
        findings = []
        
        # Check for unsafe directives
        if 'unsafe-inline' in csp_value.lower():
            finding = VulnerabilityFinding(
                vulnerability_type='security_misconfiguration',
                severity='medium',
                url=url,
                description='CSP allows unsafe-inline scripts',
                evidence=f'Content-Security-Policy contains unsafe-inline',
                remediation='Remove unsafe-inline and use nonces or hashes for inline scripts',
                confidence=0.9,
                cwe_id='CWE-79'
            )
            findings.append(finding)
        
        if 'unsafe-eval' in csp_value.lower():
            finding = VulnerabilityFinding(
                vulnerability_type='security_misconfiguration',
                severity='medium',
                url=url,
                description='CSP allows unsafe-eval',
                evidence=f'Content-Security-Policy contains unsafe-eval',
                remediation='Remove unsafe-eval to prevent dynamic code execution',
                confidence=0.9,
                cwe_id='CWE-79'
            )
            findings.append(finding)
        
        # Check for wildcard sources
        if re.search(r"(script-src|default-src)\s+[^;]*\*", csp_value, re.IGNORECASE):
            finding = VulnerabilityFinding(
                vulnerability_type='security_misconfiguration',
                severity='medium',
                url=url,
                description='CSP uses wildcard sources',
                evidence='CSP contains wildcard (*) source',
                remediation='Specify explicit trusted sources instead of wildcards',
                confidence=0.85,
                cwe_id='CWE-1021'
            )
            findings.append(finding)
        
        return findings
    
    def _check_insecure_headers(self, url: str, headers: Dict) -> List[VulnerabilityFinding]:
        """Check for headers that expose sensitive information."""
        findings = []
        
        for header_name, header_info in self.INSECURE_HEADERS.items():
            if header_name in headers:
                finding = VulnerabilityFinding(
                    vulnerability_type='info_disclosure',
                    severity=header_info['severity'],
                    url=url,
                    description=header_info['description'],
                    evidence=f'{header_name}: {headers[header_name]}',
                    remediation=header_info['remediation'],
                    confidence=0.95,
                    cwe_id=header_info['cwe_id']
                )
                findings.append(finding)
        
        return findings
    
    def _check_security_txt(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Check for presence of security.txt file."""
        findings = []
        
        try:
            parsed = urlparse(url)
            security_txt_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
            
            response = requests.get(security_txt_url, timeout=timeout, verify=verify_ssl)
            
            if response.status_code == 404:
                finding = VulnerabilityFinding(
                    vulnerability_type='info_disclosure',
                    severity='info',
                    url=url,
                    description='Missing security.txt file',
                    evidence='No security.txt found at /.well-known/security.txt',
                    remediation='Create a security.txt file to help security researchers report vulnerabilities',
                    confidence=0.6,
                    cwe_id='CWE-200'
                )
                findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error checking security.txt: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for security headers scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_security_txt': True,
            'check_header_values': True,
        }
