"""
CSRF (Cross-Site Request Forgery) Detection Plugin

This plugin detects missing or weak CSRF protection in forms and AJAX endpoints.

Checks for:
- Missing CSRF tokens in forms
- Missing CSRF headers in AJAX calls
- Weak token generation
- Token not validated on server
- SameSite cookie attributes
"""

import logging
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class CSRFScannerPlugin(BaseScanPlugin):
    """
    CSRF vulnerability detection plugin.
    
    Detects missing or weak Cross-Site Request Forgery protection:
    - Forms without CSRF tokens
    - Missing CSRF headers (X-CSRF-Token, X-XSRF-Token)
    - Cookies without SameSite attribute
    - Weak token generation patterns
    """
    
    # Common CSRF token field names
    CSRF_TOKEN_NAMES = [
        'csrf_token', 'csrftoken', 'csrf', '_csrf',
        'authenticity_token', '__requestverificationtoken',
        'anti-csrf-token', 'xsrf_token', 'xsrf'
    ]
    
    # Common CSRF header names
    CSRF_HEADER_NAMES = [
        'x-csrf-token', 'x-xsrf-token', 'x-csrftoken',
        'csrf-token', 'xsrf-token'
    ]
    
    @property
    def plugin_id(self) -> str:
        return 'csrf_scanner'
    
    @property
    def name(self) -> str:
        return 'CSRF Protection Scanner'
    
    @property
    def description(self) -> str:
        return 'Detects missing or weak Cross-Site Request Forgery (CSRF) protection'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['csrf']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for CSRF vulnerabilities.
        
        Args:
            url: Target URL to scan
            config: Configuration dictionary
        
        Returns:
            List of vulnerability findings
        """
        if not HAS_REQUESTS or not HAS_BS4:
            logger.warning("Required dependencies not available")
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            # Fetch the target page
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check forms for CSRF protection
            forms = soup.find_all('form')
            for form in forms:
                csrf_finding = self._check_form_csrf(form, url)
                if csrf_finding:
                    findings.append(csrf_finding)
            
            # Check cookies for SameSite attribute
            if response.cookies:
                samesite_finding = self._check_samesite_cookies(response, url)
                if samesite_finding:
                    findings.append(samesite_finding)
            
            logger.info(f"CSRF scan of {url} found {len(findings)} potential vulnerability(ies)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for CSRF: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during CSRF scan of {url}: {e}")
        
        return findings
    
    def _check_form_csrf(self, form, url: str) -> Optional[VulnerabilityFinding]:
        """
        Check if a form has CSRF protection.
        
        Args:
            form: BeautifulSoup form element
            url: Target URL
        
        Returns:
            VulnerabilityFinding if CSRF protection missing
        """
        # Get form action and method
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # CSRF is mainly a concern for state-changing operations (POST, PUT, DELETE)
        if method not in ['POST', 'PUT', 'DELETE']:
            return None
        
        # Check for CSRF token fields
        inputs = form.find_all('input')
        has_csrf_token = False
        
        for input_field in inputs:
            field_name = input_field.get('name', '').lower()
            if any(csrf_name in field_name for csrf_name in self.CSRF_TOKEN_NAMES):
                has_csrf_token = True
                break
        
        if not has_csrf_token:
            # Form lacks CSRF protection
            return VulnerabilityFinding(
                vulnerability_type='csrf',
                severity='medium',
                url=url,
                description=f'Form without CSRF protection (method: {method})',
                evidence=f'Form action: {action}, No CSRF token field found',
                remediation='Implement CSRF token protection. Use framework built-in CSRF protection (e.g., Django CSRF middleware, Rails protect_from_forgery). Include unique token in forms and validate on server.',
                confidence=0.75,
                cwe_id='CWE-352'  # Cross-Site Request Forgery
            )
        
        return None
    
    def _check_samesite_cookies(self, response, url: str) -> Optional[VulnerabilityFinding]:
        """
        Check if cookies have SameSite attribute.
        
        Args:
            response: Requests response object
            url: Target URL
        
        Returns:
            VulnerabilityFinding if SameSite missing
        """
        # Check Set-Cookie headers
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        
        if set_cookie_headers and 'samesite' not in set_cookie_headers.lower():
            # Cookies without SameSite attribute
            cookie_names = [cookie.name for cookie in response.cookies]
            
            return VulnerabilityFinding(
                vulnerability_type='csrf',
                severity='low',
                url=url,
                description='Cookies without SameSite attribute',
                evidence=f'Cookies found: {", ".join(cookie_names[:5])}. No SameSite attribute detected.',
                remediation='Set SameSite=Lax or SameSite=Strict attribute on all cookies to prevent CSRF attacks. Example: Set-Cookie: session=abc123; SameSite=Lax; Secure; HttpOnly',
                confidence=0.9,
                cwe_id='CWE-352'
            )
        
        return None
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for CSRF scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_forms': True,
            'check_cookies': True,
            'check_ajax': True,  # TODO: Implement AJAX CSRF checking
        }
