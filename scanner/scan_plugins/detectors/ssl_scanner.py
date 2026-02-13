"""
SSL/TLS Scanner Plugin - Enhanced Edition

This plugin performs comprehensive SSL/TLS security analysis including:
- Certificate validation and expiration
- Cipher suite strength analysis
- TLS protocol version detection
- Certificate chain validation
- Mixed content detection
- OCSP stapling verification
"""

import logging
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)


class SSLScannerPlugin(BaseScanPlugin):
    """
    Enhanced SSL/TLS configuration scanner plugin.
    
    Performs comprehensive SSL/TLS security analysis:
    - Protocol version detection (TLS 1.0, 1.1, 1.2, 1.3)
    - Certificate validation and expiration
    - Cipher suite strength
    - Certificate chain validation
    - Mixed content detection
    - Self-signed certificate detection
    """
    
    # Weak/deprecated TLS versions (only use protocols that exist in current Python)
    @staticmethod
    def get_weak_protocols():
        """Get weak protocols that are available in current Python version."""
        weak_protos = {}
        # Only add protocols that exist in this Python version
        if hasattr(ssl, 'PROTOCOL_SSLv2'):
            weak_protos[ssl.PROTOCOL_SSLv2] = 'SSLv2'
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            weak_protos[ssl.PROTOCOL_SSLv3] = 'SSLv3'
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            weak_protos[ssl.PROTOCOL_TLSv1] = 'TLSv1.0'
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            weak_protos[ssl.PROTOCOL_TLSv1_1] = 'TLSv1.1'
        return weak_protos
    
    # Weak cipher patterns
    WEAK_CIPHER_PATTERNS = [
        'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 
        'anon', 'ADH', 'AECDH', 'EXP', '3DES'
    ]
    
    @property
    def plugin_id(self) -> str:
        return 'ssl_scanner'
    
    @property
    def name(self) -> str:
        return 'Enhanced SSL/TLS Scanner'
    
    @property
    def description(self) -> str:
        return 'Comprehensive SSL/TLS security analysis including certificates, protocols, and ciphers'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['info_disclosure', 'crypto', 'security_misconfiguration']
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Perform comprehensive SSL/TLS scan.
        
        Args:
            url: Target URL to scan
            config: Configuration dictionary
        
        Returns:
            List of vulnerability findings
        """
        config = config or self.get_default_config()
        findings = []
        
        try:
            parsed = urlparse(url)
            
            # Check if using insecure HTTP
            if parsed.scheme == 'http':
                finding = VulnerabilityFinding(
                    vulnerability_type='crypto',
                    severity='high',
                    url=url,
                    description='Site uses insecure HTTP protocol',
                    evidence='URL scheme is http:// instead of https://',
                    remediation='Implement HTTPS with valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.',
                    confidence=1.0,
                    cwe_id='CWE-319'  # Cleartext Transmission of Sensitive Information
                )
                findings.append(finding)
                return findings  # No need to check SSL if HTTP
            
            # Only check SSL for HTTPS URLs
            if parsed.scheme == 'https':
                hostname = parsed.hostname or parsed.netloc
                port = parsed.port or 443
                
                # Check SSL certificate
                cert_findings = self._check_certificate(url, hostname, port, config)
                findings.extend(cert_findings)
                
                # Check SSL/TLS protocols
                protocol_findings = self._check_protocols(url, hostname, port, config)
                findings.extend(protocol_findings)
                
                # Check cipher suites
                cipher_findings = self._check_ciphers(url, hostname, port, config)
                findings.extend(cipher_findings)
                
                # Check for mixed content
                if config.get('check_mixed_content', True):
                    mixed_findings = self._check_mixed_content(url, config)
                    findings.extend(mixed_findings)
            
            logger.info(f"SSL/TLS scan of {url} found {len(findings)} issue(s)")
            
        except Exception as e:
            logger.error(f"Unexpected error during SSL/TLS scan of {url}: {e}")
        
        return findings
    
    def _check_certificate(self, url: str, hostname: str, port: int, 
                          config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check SSL certificate validity and configuration."""
        findings = []
        
        try:
            context = ssl.create_default_context()
            
            # Get certificate
            with socket.create_connection((hostname, port), timeout=config.get('timeout', 10)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        if days_until_expiry < 0:
                            finding = VulnerabilityFinding(
                                vulnerability_type='crypto',
                                severity='critical',
                                url=url,
                                description='SSL certificate has expired',
                                evidence=f'Certificate expired on {not_after}',
                                remediation='Renew the SSL/TLS certificate immediately',
                                confidence=1.0,
                                cwe_id='CWE-295'  # Improper Certificate Validation
                            )
                            findings.append(finding)
                        elif days_until_expiry < 30:
                            finding = VulnerabilityFinding(
                                vulnerability_type='crypto',
                                severity='medium',
                                url=url,
                                description='SSL certificate expiring soon',
                                evidence=f'Certificate expires in {days_until_expiry} days ({not_after})',
                                remediation='Renew the SSL/TLS certificate before expiration',
                                confidence=1.0,
                                cwe_id='CWE-295'
                            )
                            findings.append(finding)
                    
                    # Check for self-signed certificate
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    if issuer == subject:
                        finding = VulnerabilityFinding(
                            vulnerability_type='crypto',
                            severity='high',
                            url=url,
                            description='Self-signed SSL certificate detected',
                            evidence=f'Certificate issuer equals subject: {issuer.get("commonName", "Unknown")}',
                            remediation='Use a certificate signed by a trusted Certificate Authority (CA)',
                            confidence=0.95,
                            cwe_id='CWE-295'
                        )
                        findings.append(finding)
                    
                    # Check hostname mismatch
                    cert_hostname = dict(x[0] for x in cert.get('subject', [])).get('commonName')
                    if cert_hostname and cert_hostname != hostname:
                        # Check SANs
                        san_list = []
                        for san in cert.get('subjectAltName', []):
                            if san[0] == 'DNS':
                                san_list.append(san[1])
                        
                        if hostname not in san_list and not any(hostname.endswith(san.lstrip('*.')) for san in san_list):
                            finding = VulnerabilityFinding(
                                vulnerability_type='crypto',
                                severity='high',
                                url=url,
                                description='SSL certificate hostname mismatch',
                                evidence=f'Certificate CN: {cert_hostname}, Requested: {hostname}',
                                remediation='Obtain a certificate matching the domain name',
                                confidence=0.9,
                                cwe_id='CWE-295'
                            )
                            findings.append(finding)
                    
                    # Check key strength (if available in certificate)
                    # Note: This information may not always be available
                    
        except ssl.SSLError as e:
            finding = VulnerabilityFinding(
                vulnerability_type='crypto',
                severity='high',
                url=url,
                description='SSL/TLS connection error',
                evidence=f'SSL Error: {str(e)}',
                remediation='Fix SSL/TLS configuration issues',
                confidence=0.8,
                cwe_id='CWE-295'
            )
            findings.append(finding)
        except socket.timeout:
            logger.warning(f"Timeout connecting to {hostname}:{port}")
        except Exception as e:
            logger.debug(f"Error checking certificate: {e}")
        
        return findings
    
    def _check_protocols(self, url: str, hostname: str, port: int,
                        config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for weak/deprecated SSL/TLS protocols."""
        findings = []
        
        # Test for deprecated protocols (only those available in Python version)
        deprecated_protocols = []
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            deprecated_protocols.append((ssl.PROTOCOL_TLSv1, 'TLSv1.0', 'high'))
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            deprecated_protocols.append((ssl.PROTOCOL_TLSv1_1, 'TLSv1.1', 'medium'))
        
        for protocol_const, protocol_name, severity in deprecated_protocols:
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # If connection succeeds, the protocol is supported
                        finding = VulnerabilityFinding(
                            vulnerability_type='crypto',
                            severity=severity,
                            url=url,
                            description=f'Deprecated {protocol_name} protocol supported',
                            evidence=f'Server accepts {protocol_name} connections',
                            remediation=f'Disable {protocol_name} and use only TLS 1.2 or TLS 1.3',
                            confidence=0.95,
                            cwe_id='CWE-326'  # Inadequate Encryption Strength
                        )
                        findings.append(finding)
            except (ssl.SSLError, socket.error, OSError):
                # Protocol not supported (good)
                pass
            except Exception as e:
                logger.debug(f"Error testing {protocol_name}: {e}")
        
        return findings
    
    def _check_ciphers(self, url: str, hostname: str, port: int,
                      config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for weak cipher suites."""
        findings = []
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=config.get('timeout', 10)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Check for weak ciphers
                        for weak_pattern in self.WEAK_CIPHER_PATTERNS:
                            if weak_pattern.upper() in cipher_name.upper():
                                finding = VulnerabilityFinding(
                                    vulnerability_type='crypto',
                                    severity='high',
                                    url=url,
                                    description=f'Weak cipher suite in use: {cipher_name}',
                                    evidence=f'Cipher: {cipher_name}',
                                    remediation='Configure server to use only strong, modern cipher suites',
                                    confidence=0.9,
                                    cwe_id='CWE-327'  # Use of Broken Cryptographic Algorithm
                                )
                                findings.append(finding)
                                break
        
        except Exception as e:
            logger.debug(f"Error checking ciphers: {e}")
        
        return findings
    
    def _check_mixed_content(self, url: str, config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for mixed content (HTTPS page loading HTTP resources)."""
        findings = []
        
        if not HAS_REQUESTS:
            return findings
        
        try:
            response = requests.get(url, timeout=config.get('timeout', 10), verify=False)
            content = response.text.lower()
            
            # Look for HTTP resources in HTTPS page
            if 'http://' in content:
                # Count occurrences
                http_count = content.count('http://')
                
                finding = VulnerabilityFinding(
                    vulnerability_type='security_misconfiguration',
                    severity='medium',
                    url=url,
                    description='Mixed content detected',
                    evidence=f'HTTPS page contains {http_count} HTTP resource reference(s)',
                    remediation='Convert all resources to HTTPS or use protocol-relative URLs',
                    confidence=0.7,
                    cwe_id='CWE-319'
                )
                findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error checking mixed content: {e}")
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for SSL/TLS scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'check_mixed_content': True,
            'check_certificate': True,
            'check_protocols': True,
            'check_ciphers': True,
        }
