"""
Service and version detection module.
Identifies services running on open ports and their versions.
"""

import socket
import re
from typing import Dict, Optional, List, Tuple


class ServiceDetector:
    """
    Service detection engine for identifying running services and versions.
    """
    
    # Common service signatures
    SERVICE_SIGNATURES = {
        21: {
            'service': 'ftp',
            'patterns': [
                (r'220.*ProFTPD (\d+\.\d+\.\d+)', 'ProFTPD'),
                (r'220.*vsftpd (\d+\.\d+\.\d+)', 'vsftpd'),
                (r'220.*FileZilla Server', 'FileZilla'),
            ]
        },
        22: {
            'service': 'ssh',
            'patterns': [
                (r'SSH-(\d+\.\d+)-OpenSSH[_-](\d+\.\d+)', 'OpenSSH'),
                (r'SSH-(\d+\.\d+)-Cisco', 'Cisco SSH'),
            ]
        },
        25: {
            'service': 'smtp',
            'patterns': [
                (r'220.*Postfix', 'Postfix'),
                (r'220.*Sendmail', 'Sendmail'),
                (r'220.*Microsoft ESMTP MAIL', 'Microsoft Exchange'),
            ]
        },
        80: {
            'service': 'http',
            'patterns': [
                (r'Server: Apache/(\d+\.\d+\.\d+)', 'Apache'),
                (r'Server: nginx/(\d+\.\d+\.\d+)', 'nginx'),
                (r'Server: Microsoft-IIS/(\d+\.\d+)', 'Microsoft IIS'),
            ]
        },
        443: {
            'service': 'https',
            'patterns': [
                (r'Server: Apache/(\d+\.\d+\.\d+)', 'Apache'),
                (r'Server: nginx/(\d+\.\d+\.\d+)', 'nginx'),
                (r'Server: Microsoft-IIS/(\d+\.\d+)', 'Microsoft IIS'),
            ]
        },
        3306: {
            'service': 'mysql',
            'patterns': [
                (r'(\d+\.\d+\.\d+).*MySQL', 'MySQL'),
                (r'(\d+\.\d+\.\d+).*MariaDB', 'MariaDB'),
            ]
        },
        5432: {
            'service': 'postgresql',
            'patterns': [
                (r'PostgreSQL', 'PostgreSQL'),
            ]
        },
        3389: {
            'service': 'ms-wbt-server',
            'patterns': [
                (r'.*', 'Microsoft Terminal Services'),
            ]
        },
    }
    
    # HTTP probes
    HTTP_PROBE = b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n"
    
    def __init__(self):
        """Initialize service detector."""
        self.detection_results = []
    
    def detect_service(self, 
                      target: str, 
                      port: int,
                      protocol: str = 'tcp') -> Dict:
        """
        Detect service running on specified port.
        
        Args:
            target: Target host
            port: Port number
            protocol: Protocol (tcp/udp)
        
        Returns:
            Dictionary with service information
        """
        result = {
            'port': port,
            'protocol': protocol,
            'service_name': 'unknown',
            'service_version': '',
            'product': '',
            'confidence': 0,
            'banner': None,
        }
        
        if protocol == 'tcp':
            banner = self._grab_banner(target, port)
            
            if banner:
                result['banner'] = banner
                detected = self._analyze_banner(port, banner)
                result.update(detected)
        
        # If no banner, try service-specific probes
        if result['service_name'] == 'unknown':
            probed = self._probe_service(target, port)
            result.update(probed)
        
        self.detection_results.append(result)
        return result
    
    def detect_multiple_services(self,
                                target: str,
                                ports: List[int]) -> List[Dict]:
        """
        Detect services on multiple ports.
        
        Args:
            target: Target host
            ports: List of port numbers
        
        Returns:
            List of service detection results
        """
        results = []
        for port in ports:
            result = self.detect_service(target, port)
            results.append(result)
        
        return results
    
    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """
        Grab service banner from port.
        
        Args:
            target: Target host
            port: Port number
        
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Some services send banner immediately
            banner = sock.recv(1024)
            
            # If no immediate banner, try sending probe
            if not banner and port in [80, 443, 8080, 8443]:
                sock.send(self.HTTP_PROBE % target.encode())
                banner = sock.recv(4096)
            
            sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
        
        except (socket.timeout, socket.error, ConnectionRefusedError):
            pass
        
        return None
    
    def _analyze_banner(self, port: int, banner: str) -> Dict:
        """
        Analyze banner to identify service and version.
        
        Args:
            port: Port number
            banner: Banner string
        
        Returns:
            Dictionary with detected information
        """
        result = {
            'service_name': 'unknown',
            'service_version': '',
            'product': '',
            'confidence': 50,
        }
        
        # Check port-specific signatures
        if port in self.SERVICE_SIGNATURES:
            sig = self.SERVICE_SIGNATURES[port]
            result['service_name'] = sig['service']
            
            for pattern, product in sig['patterns']:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result['product'] = product
                    result['confidence'] = 90
                    
                    # Extract version if captured
                    if match.groups():
                        result['service_version'] = match.group(1)
                        if len(match.groups()) > 1:
                            result['service_version'] = match.group(2)
                    
                    break
        
        # Generic pattern matching
        if result['service_name'] == 'unknown':
            result.update(self._generic_pattern_matching(banner))
        
        return result
    
    def _generic_pattern_matching(self, banner: str) -> Dict:
        """
        Perform generic pattern matching on banner.
        
        Args:
            banner: Banner string
        
        Returns:
            Dictionary with detected information
        """
        result = {
            'service_name': 'unknown',
            'service_version': '',
            'product': '',
            'confidence': 30,
        }
        
        # Common patterns
        patterns = [
            (r'Apache/(\d+\.\d+\.\d+)', 'http', 'Apache'),
            (r'nginx/(\d+\.\d+\.\d+)', 'http', 'nginx'),
            (r'Microsoft-IIS/(\d+\.\d+)', 'http', 'Microsoft IIS'),
            (r'OpenSSH[_-](\d+\.\d+)', 'ssh', 'OpenSSH'),
            (r'MySQL (\d+\.\d+\.\d+)', 'mysql', 'MySQL'),
            (r'PostgreSQL (\d+\.\d+)', 'postgresql', 'PostgreSQL'),
            (r'ProFTPD (\d+\.\d+\.\d+)', 'ftp', 'ProFTPD'),
            (r'vsftpd (\d+\.\d+\.\d+)', 'ftp', 'vsftpd'),
        ]
        
        for pattern, service, product in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                result['service_name'] = service
                result['product'] = product
                result['confidence'] = 80
                
                if match.groups():
                    result['service_version'] = match.group(1)
                
                break
        
        return result
    
    def _probe_service(self, target: str, port: int) -> Dict:
        """
        Send service-specific probes to identify service.
        
        Args:
            target: Target host
            port: Port number
        
        Returns:
            Dictionary with detected information
        """
        result = {
            'service_name': 'unknown',
            'service_version': '',
            'product': '',
            'confidence': 0,
        }
        
        # HTTP probe
        if port in [80, 8080, 8000, 8888]:
            http_result = self._http_probe(target, port)
            if http_result['service_name'] != 'unknown':
                return http_result
        
        # HTTPS probe
        if port in [443, 8443]:
            result['service_name'] = 'https'
            result['confidence'] = 70
        
        # Common service port defaults
        service_defaults = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            110: 'pop3',
            143: 'imap',
            3306: 'mysql',
            5432: 'postgresql',
            3389: 'ms-wbt-server',
            5900: 'vnc',
        }
        
        if port in service_defaults:
            result['service_name'] = service_defaults[port]
            result['confidence'] = 50
        
        return result
    
    def _http_probe(self, target: str, port: int) -> Dict:
        """
        Probe HTTP service for details.
        
        Args:
            target: Target host
            port: Port number
        
        Returns:
            Dictionary with HTTP service information
        """
        result = {
            'service_name': 'http',
            'service_version': '',
            'product': '',
            'confidence': 60,
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:  # Limit response size
                    break
            
            sock.close()
            
            # Parse headers
            response_str = response.decode('utf-8', errors='ignore')
            headers = self._parse_http_headers(response_str)
            
            # Extract server information
            if 'server' in headers:
                server = headers['server']
                result['product'] = server
                result['confidence'] = 90
                
                # Extract version
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', server)
                if version_match:
                    result['service_version'] = version_match.group(1)
        
        except (socket.timeout, socket.error):
            pass
        
        return result
    
    def _parse_http_headers(self, response: str) -> Dict[str, str]:
        """
        Parse HTTP response headers.
        
        Args:
            response: HTTP response string
        
        Returns:
            Dictionary of headers
        """
        headers = {}
        
        lines = response.split('\r\n')
        for line in lines[1:]:  # Skip status line
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            elif not line.strip():
                break  # End of headers
        
        return headers
    
    def generate_cpe(self, 
                    vendor: str,
                    product: str,
                    version: str) -> str:
        """
        Generate CPE (Common Platform Enumeration) string.
        
        Args:
            vendor: Vendor name
            product: Product name
            version: Version string
        
        Returns:
            CPE string
        """
        # Simplified CPE generation
        vendor = vendor.lower().replace(' ', '_')
        product = product.lower().replace(' ', '_')
        
        if version:
            return f"cpe:/a:{vendor}:{product}:{version}"
        else:
            return f"cpe:/a:{vendor}:{product}"
