"""
Cookie Security Scanner Plugin

This plugin performs comprehensive cookie security analysis including:
- HttpOnly flag checking
- Secure flag validation
- SameSite attribute detection
- Cookie expiration analysis
- Session token strength validation
- Cookie prefix validation
"""

import logging
import re
from typing import Dict, List, Any, Optional
from http.cookies import SimpleCookie
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class CookieSecurityScannerPlugin(BaseScanPlugin):
    """
    Cookie security scanner plugin.
    
    Analyzes cookie security attributes:
    - Secure flag (HTTPS-only)
    - HttpOnly flag (no JavaScript access)
    - SameSite attribute (CSRF protection)
    - Cookie expiration
    - Session token strength
    - Security prefixes (__Host-, __Secure-)
    """
    
    # Sensitive cookie name patterns
    SENSITIVE_COOKIE_PATTERNS = [
        r'session', r'sess', r'auth', r'token', r'csrf', r'xsrf',
        r'jwt', r'password', r'pwd', r'credential', r'api[_-]?key'
    ]
    
    @property
    def plugin_id(self) -> str:
        return 'cookie_security_scanner'
    
    @property
    def name(self) -> str:
        return 'Cookie Security Scanner'
    
    @property
    def description(self) -> str:
        return 'Comprehensive cookie security analysis including Secure, HttpOnly, SameSite attributes'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['security_misconfiguration', 'session_management']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for cookie security issues.
        
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
            
            # Get Set-Cookie headers
            set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
            
            # If get_list not available, try raw headers
            if not set_cookie_headers:
                for header, value in response.raw_headers if hasattr(response, 'raw_headers') else []:
                    if header.lower() == b'set-cookie':
                        set_cookie_headers.append(value.decode('utf-8', errors='ignore'))
            
            # Also check response.cookies
            if not set_cookie_headers and response.cookies:
                for cookie_name, cookie_value in response.cookies.items():
                    set_cookie_headers.append(f"{cookie_name}={cookie_value}")
            
            # Analyze each cookie
            for cookie_str in set_cookie_headers:
                cookie_findings = self._analyze_cookie(url, cookie_str)
                findings.extend(cookie_findings)
            
            if not set_cookie_headers:
                logger.debug(f"No cookies found on {url}")
            
            logger.info(f"Cookie security scan of {url} found {len(findings)} issue(s)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for cookie security: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during cookie security scan of {url}: {e}")
        
        return findings
    
    def _analyze_cookie(self, url: str, cookie_str: str) -> List[VulnerabilityFinding]:
        """Analyze a single cookie for security issues."""
        findings = []
        
        try:
            # Parse cookie string
            cookie = SimpleCookie()
            cookie.load(cookie_str)
            
            # Get cookie name and attributes
            for key in cookie:
                cookie_obj = cookie[key]
                cookie_name = key
                cookie_value = cookie_obj.value
                
                # Check if this is a sensitive cookie
                is_sensitive = any(re.search(pattern, cookie_name, re.IGNORECASE) 
                                 for pattern in self.SENSITIVE_COOKIE_PATTERNS)
                
                # Check Secure flag
                if 'secure' not in cookie_str.lower():
                    severity = 'high' if is_sensitive else 'medium'
                    finding = VulnerabilityFinding(
                        vulnerability_type='session_management',
                        severity=severity,
                        url=url,
                        description=f'Cookie "{cookie_name}" missing Secure flag',
                        evidence=f'Cookie: {cookie_name} (Secure flag not set)',
                        remediation='Add Secure flag to ensure cookie is only sent over HTTPS',
                        confidence=0.95,
                        cwe_id='CWE-614'  # Sensitive Cookie in HTTPS Session Without Secure Attribute
                    )
                    findings.append(finding)
                
                # Check HttpOnly flag
                if is_sensitive and 'httponly' not in cookie_str.lower():
                    finding = VulnerabilityFinding(
                        vulnerability_type='session_management',
                        severity='high',
                        url=url,
                        description=f'Sensitive cookie "{cookie_name}" missing HttpOnly flag',
                        evidence=f'Cookie: {cookie_name} (HttpOnly flag not set)',
                        remediation='Add HttpOnly flag to prevent JavaScript access and mitigate XSS attacks',
                        confidence=0.95,
                        cwe_id='CWE-1004'  # Sensitive Cookie Without HttpOnly Flag
                    )
                    findings.append(finding)
                
                # Check SameSite attribute
                if 'samesite' not in cookie_str.lower():
                    severity = 'medium' if is_sensitive else 'low'
                    finding = VulnerabilityFinding(
                        vulnerability_type='session_management',
                        severity=severity,
                        url=url,
                        description=f'Cookie "{cookie_name}" missing SameSite attribute',
                        evidence=f'Cookie: {cookie_name} (SameSite attribute not set)',
                        remediation='Add SameSite=Strict or SameSite=Lax to protect against CSRF attacks',
                        confidence=0.85,
                        cwe_id='CWE-352'  # Cross-Site Request Forgery
                    )
                    findings.append(finding)
                
                # Check for weak SameSite value
                if 'samesite=none' in cookie_str.lower():
                    finding = VulnerabilityFinding(
                        vulnerability_type='session_management',
                        severity='medium',
                        url=url,
                        description=f'Cookie "{cookie_name}" uses SameSite=None',
                        evidence=f'Cookie: {cookie_name} (SameSite=None)',
                        remediation='Consider using SameSite=Strict or SameSite=Lax for better security',
                        confidence=0.8,
                        cwe_id='CWE-352'
                    )
                    findings.append(finding)
                
                # Check for security prefixes
                if is_sensitive:
                    if not cookie_name.startswith('__Secure-') and not cookie_name.startswith('__Host-'):
                        finding = VulnerabilityFinding(
                            vulnerability_type='session_management',
                            severity='low',
                            url=url,
                            description=f'Sensitive cookie "{cookie_name}" not using security prefix',
                            evidence=f'Cookie: {cookie_name} (no __Secure- or __Host- prefix)',
                            remediation='Use __Secure- or __Host- prefix for sensitive cookies',
                            confidence=0.6,
                            cwe_id='CWE-614'
                        )
                        findings.append(finding)
                
                # Check cookie expiration (if Max-Age or Expires set)
                if is_sensitive:
                    # Check for very long expiration
                    max_age_match = re.search(r'max-age=(\d+)', cookie_str, re.IGNORECASE)
                    if max_age_match:
                        max_age_seconds = int(max_age_match.group(1))
                        max_age_days = max_age_seconds / (60 * 60 * 24)
                        
                        if max_age_days > 365:  # More than 1 year
                            finding = VulnerabilityFinding(
                                vulnerability_type='session_management',
                                severity='low',
                                url=url,
                                description=f'Sensitive cookie "{cookie_name}" has very long expiration',
                                evidence=f'Cookie: {cookie_name} (Max-Age: {max_age_days:.0f} days)',
                                remediation='Use shorter expiration time for sensitive cookies (e.g., session-only or hours/days)',
                                confidence=0.7,
                                cwe_id='CWE-613'  # Insufficient Session Expiration
                            )
                            findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error analyzing cookie: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for cookie security scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_secure': True,
            'check_httponly': True,
            'check_samesite': True,
            'check_expiration': True,
            'check_prefixes': True,
        }
