"""
LFI (Local File Inclusion) Detection Plugin

This plugin detects Local File Inclusion vulnerabilities where attackers can read
local files from the server through path traversal or file inclusion.
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

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class LFIDetectorPlugin(BaseScanPlugin):
    """
    LFI vulnerability detection plugin.
    
    Detects Local File Inclusion vulnerabilities through:
    - Path traversal testing
    - Common file reading attempts
    - Filter bypass techniques
    - Null byte injection (when applicable)
    """
    
    # Common files to test on different systems
    TEST_FILES = {
        'linux': [
            '/etc/passwd',
            '/etc/hosts',
            '/etc/group',
            '/etc/issue',
            '/etc/hostname',
            '/proc/self/environ',
            '/proc/version',
            '/var/log/apache2/access.log',
        ],
        'windows': [
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\win.ini',
            'C:\\boot.ini',
            'C:\\Windows\\System32\\license.rtf',
        ]
    }
    
    # Path traversal sequences
    TRAVERSAL_SEQUENCES = [
        '../',
        '..\\',
        '..../',
        '....\\',
        '..%2f',
        '..%5c',
        '%2e%2e/',
        '%2e%2e\\',
    ]
    
    # Signatures that indicate successful file read
    FILE_SIGNATURES = {
        '/etc/passwd': [
            'root:x:0:0',
            'root:.*:/root:/bin',
            'daemon:',
            '/bin/bash',
            '/bin/sh',
        ],
        '/etc/hosts': [
            '127.0.0.1',
            'localhost',
            '::1',
        ],
        '/etc/group': [
            'root:x:0:',
            'daemon:x:',
        ],
        'win.ini': [
            '[fonts]',
            '[extensions]',
            '; for 16-bit app support',
        ],
        'hosts': [
            '127.0.0.1',
            'localhost',
        ]
    }
    
    @property
    def plugin_id(self) -> str:
        return 'lfi_detector'
    
    @property
    def name(self) -> str:
        return 'LFI Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects Local File Inclusion (LFI) vulnerabilities including path traversal'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['lfi']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for LFI vulnerabilities.
        
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
            
            # Test for path traversal
            if config.get('test_path_traversal', True):
                traversal_findings = self._test_path_traversal(url, verify_ssl, timeout)
                findings.extend(traversal_findings)
            
            # Test for direct file inclusion
            if config.get('test_direct_inclusion', True):
                direct_findings = self._test_direct_inclusion(url, verify_ssl, timeout)
                findings.extend(direct_findings)
            
            # Test for filter bypass
            if config.get('test_filter_bypass', True):
                bypass_findings = self._test_filter_bypass(url, verify_ssl, timeout)
                findings.extend(bypass_findings)
            
            logger.info(f"LFI scan of {url} found {len(findings)} potential vulnerability(ies)")
            
        except requests.RequestException as e:
            logger.error(f"Error scanning {url} for LFI: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during LFI scan of {url}: {e}")
        
        return findings
    
    def _test_path_traversal(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for path traversal vulnerabilities."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            # Test each parameter
            for param_name in params.keys():
                # Try Linux files
                for target_file in self.TEST_FILES['linux'][:3]:  # Test first 3
                    # Build traversal payload
                    for depth in range(1, 6):  # Try different depths
                        payload = '../' * depth + target_file.lstrip('/')
                        
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        try:
                            response = requests.get(
                                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                params=test_params,
                                timeout=timeout,
                                verify=verify_ssl
                            )
                            
                            # Check for file signatures
                            if self._check_file_signatures(response.text, target_file):
                                finding = VulnerabilityFinding(
                                    vulnerability_type='lfi',
                                    severity='high',
                                    url=url,
                                    description=f'Path traversal vulnerability detected in parameter "{param_name}"',
                                    evidence=f'Successfully read file: {target_file} using payload: {payload}',
                                    remediation='Use whitelist validation for file paths, avoid user input in file operations, use absolute paths, and implement proper access controls.',
                                    parameter=param_name,
                                    confidence=0.9,
                                    cwe_id='CWE-22'  # Path Traversal
                                )
                                findings.append(finding)
                                logger.info(f"Found path traversal in {param_name}")
                                return findings  # Found one, no need to continue
                        except Exception as e:
                            logger.debug(f"Error testing path traversal: {e}")
                
                # Try Windows files
                for target_file in self.TEST_FILES['windows'][:2]:
                    payload = target_file
                    
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                        response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        if self._check_file_signatures(response.text, target_file):
                            finding = VulnerabilityFinding(
                                vulnerability_type='lfi',
                                severity='high',
                                url=url,
                                description=f'Local file inclusion vulnerability detected in parameter "{param_name}"',
                                evidence=f'Successfully read file: {target_file}',
                                remediation='Use whitelist validation for file paths, avoid user input in file operations, and implement proper access controls.',
                                parameter=param_name,
                                confidence=0.9,
                                cwe_id='CWE-22'
                            )
                            findings.append(finding)
                            logger.info(f"Found LFI in {param_name}")
                            return findings
                    except Exception as e:
                        logger.debug(f"Error testing Windows file: {e}")
        
        except Exception as e:
            logger.error(f"Error in path traversal testing: {e}")
        
        return findings
    
    def _test_direct_inclusion(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for direct file inclusion without traversal."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            for param_name in params.keys():
                # Test direct paths
                for target_file in ['/etc/passwd', '/etc/hosts']:
                    test_params = params.copy()
                    test_params[param_name] = [target_file]
                    
                    try:
                        response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        if self._check_file_signatures(response.text, target_file):
                            finding = VulnerabilityFinding(
                                vulnerability_type='lfi',
                                severity='high',
                                url=url,
                                description=f'Direct file inclusion vulnerability in parameter "{param_name}"',
                                evidence=f'Successfully read file: {target_file}',
                                remediation='Never use user input directly in file paths. Use indirect references and whitelist validation.',
                                parameter=param_name,
                                confidence=0.95,
                                cwe_id='CWE-73'  # External Control of File Name or Path
                            )
                            findings.append(finding)
                            logger.info(f"Found direct file inclusion in {param_name}")
                            return findings
                    except Exception as e:
                        logger.debug(f"Error testing direct inclusion: {e}")
        
        except Exception as e:
            logger.error(f"Error in direct inclusion testing: {e}")
        
        return findings
    
    def _test_filter_bypass(self, url: str, verify_ssl: bool, timeout: int) -> List[VulnerabilityFinding]:
        """Test for filter bypass techniques."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings
            
            # Filter bypass techniques
            bypass_payloads = [
                '....//....//....//etc/passwd',
                '....\\\\....\\\\....\\\\windows\\win.ini',
                '..%252f..%252f..%252fetc%252fpasswd',
                '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            ]
            
            for param_name in params.keys():
                for payload in bypass_payloads[:2]:  # Test a couple
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                        response = requests.get(
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            params=test_params,
                            timeout=timeout,
                            verify=verify_ssl
                        )
                        
                        # Check for passwd or win.ini
                        if ('root:' in response.text or '[fonts]' in response.text):
                            finding = VulnerabilityFinding(
                                vulnerability_type='lfi',
                                severity='high',
                                url=url,
                                description=f'Filter bypass LFI vulnerability in parameter "{param_name}"',
                                evidence=f'Bypassed filters using payload: {payload}',
                                remediation='Implement robust input validation that cannot be bypassed with encoding or traversal sequences.',
                                parameter=param_name,
                                confidence=0.85,
                                cwe_id='CWE-22'
                            )
                            findings.append(finding)
                            logger.info(f"Found filter bypass LFI in {param_name}")
                            return findings
                    except Exception as e:
                        logger.debug(f"Error testing filter bypass: {e}")
        
        except Exception as e:
            logger.error(f"Error in filter bypass testing: {e}")
        
        return findings
    
    def _check_file_signatures(self, response_text: str, target_file: str) -> bool:
        """Check if response contains signatures of the target file."""
        # Get file basename for signature lookup
        file_key = target_file.split('/')[-1].split('\\')[-1]
        
        # Look for exact file matches
        if file_key in self.FILE_SIGNATURES:
            patterns = self.FILE_SIGNATURES[file_key]
        else:
            # Look for partial matches
            for key, patterns in self.FILE_SIGNATURES.items():
                if key in file_key or file_key in key:
                    break
            else:
                return False
        
        # Check each signature pattern
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for LFI scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_path_traversal': True,
            'test_direct_inclusion': True,
            'test_filter_bypass': True,
            'common_files': ['/etc/passwd', '/etc/hosts', 'C:\\Windows\\win.ini'],
        }
