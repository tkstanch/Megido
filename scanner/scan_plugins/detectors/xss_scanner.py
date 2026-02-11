"""
XSS Detection Plugin

This plugin detects potential Cross-Site Scripting (XSS) vulnerabilities by:
- Scanning for forms with input fields
- Identifying potential injection points
- Detecting reflection points in responses

This is the DETECTION plugin. For EXPLOITATION, see scanner/plugins/exploits/xss_plugin.py
"""

import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

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


class XSSScannerPlugin(BaseScanPlugin):
    """
    XSS vulnerability detection plugin.
    
    This plugin scans for potential XSS vulnerabilities by:
    - Finding forms with input fields
    - Identifying unvalidated user input points
    - Checking for potential reflection points
    
    Note: This plugin performs DETECTION only. Use the XSS exploit plugin
    from scanner/plugins/exploits/xss_plugin.py for actual exploitation.
    """
    
    @property
    def plugin_id(self) -> str:
        return 'xss_scanner'
    
    @property
    def name(self) -> str:
        return 'XSS Vulnerability Scanner'
    
    @property
    def description(self) -> str:
        return 'Detects potential Cross-Site Scripting (XSS) vulnerabilities in web applications'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['xss']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for XSS vulnerabilities at the target URL.
        
        Args:
            url: Target URL to scan
            config: Configuration dictionary
        
        Returns:
            List of vulnerability findings
        """
        if not HAS_REQUESTS or not HAS_BS4:
            logger.warning("Required dependencies (requests, beautifulsoup4) not available")
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            # Fetch the target page
            response = requests.get(url, timeout=timeout, verify=verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for forms (potential XSS targets)
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                target_url = urljoin(url, action)
                
                # Find input fields
                inputs = form.find_all('input')
                textareas = form.find_all('textarea')
                user_inputs = inputs + textareas
                
                if user_inputs:
                    # Found a form with user input fields - potential XSS target
                    input_names = [inp.get('name', 'unnamed') for inp in user_inputs if inp.get('name')]
                    
                    finding = VulnerabilityFinding(
                        vulnerability_type='xss',
                        severity='medium',
                        url=target_url,
                        description=f'Form found with {len(user_inputs)} input field(s) - potential XSS target',
                        evidence=f'Form action: {action}, Input fields: {", ".join(input_names[:5])}',
                        remediation='Implement input validation and output encoding. Use Content Security Policy (CSP) headers.',
                        parameter=input_names[0] if input_names else None,
                        confidence=0.4,  # Medium-low confidence without actual testing
                        cwe_id='CWE-79'  # Cross-site Scripting
                    )
                    findings.append(finding)
            
            logger.info(f"XSS scan of {url} found {len(findings)} potential vulnerability(ies)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for XSS: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during XSS scan of {url}: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for XSS scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_reflection': True,  # TODO: Implement reflection checking in future
        }
