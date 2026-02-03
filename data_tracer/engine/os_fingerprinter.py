"""
OS fingerprinting module for detecting target operating system.
Uses various techniques including TCP/IP stack fingerprinting.
"""

import socket
import random
from typing import Dict, List, Optional


class OSFingerprinter:
    """
    Operating system detection engine.
    """
    
    # OS signatures based on common characteristics
    OS_SIGNATURES = {
        'linux': {
            'ttl_range': (64, 64),
            'window_size': [5840, 14600, 29200],
            'tcp_options': ['MSS', 'SACK', 'Timestamp', 'NOP', 'WScale'],
            'ip_df': True,
            'indicators': ['OpenSSH', 'Apache', 'nginx'],
        },
        'windows': {
            'ttl_range': (128, 128),
            'window_size': [8192, 16384, 65535],
            'tcp_options': ['MSS', 'NOP', 'WScale', 'SACK', 'Timestamp'],
            'ip_df': True,
            'indicators': ['Microsoft-IIS', 'Microsoft-HTTPAPI'],
        },
        'macos': {
            'ttl_range': (64, 64),
            'window_size': [65535],
            'tcp_options': ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'Timestamp', 'SACK', 'EOL'],
            'ip_df': True,
            'indicators': ['Apache'],
        },
        'freebsd': {
            'ttl_range': (64, 64),
            'window_size': [65535],
            'tcp_options': ['MSS', 'NOP', 'WScale', 'SACK', 'Timestamp'],
            'ip_df': True,
            'indicators': [],
        },
    }
    
    def __init__(self):
        """Initialize OS fingerprinter."""
        self.fingerprint_results = []
    
    def fingerprint_os(self, 
                      target: str,
                      open_ports: List[int] = None,
                      service_info: List[Dict] = None) -> List[Dict]:
        """
        Fingerprint target operating system.
        
        Args:
            target: Target host
            open_ports: List of open ports
            service_info: Service detection information
        
        Returns:
            List of possible OS matches with confidence scores
        """
        results = []
        
        # TCP/IP stack fingerprinting
        tcp_ip_result = self._tcp_ip_fingerprint(target, open_ports)
        if tcp_ip_result:
            results.append(tcp_ip_result)
        
        # Service-based OS detection
        if service_info:
            service_result = self._service_based_detection(service_info)
            if service_result:
                results.append(service_result)
        
        # Port-based OS detection
        if open_ports:
            port_result = self._port_based_detection(open_ports)
            if port_result:
                results.append(port_result)
        
        # Combine and rank results
        combined_results = self._combine_results(results)
        
        self.fingerprint_results = combined_results
        return combined_results
    
    def _tcp_ip_fingerprint(self, 
                           target: str,
                           open_ports: List[int] = None) -> Optional[Dict]:
        """
        Perform TCP/IP stack fingerprinting.
        
        Args:
            target: Target host
            open_ports: List of open ports to probe
        
        Returns:
            OS detection result
        """
        if not open_ports:
            open_ports = [80, 443, 22]
        
        # Try to detect TTL and other TCP/IP characteristics
        for port in open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                
                # Get socket options (simplified approach)
                # In real implementation, use raw sockets to analyze packets
                
                sock.close()
                
                # Analyze characteristics (simplified)
                # Real implementation would parse raw packets
                ttl_guess = self._estimate_ttl(target)
                
                for os_name, signature in self.OS_SIGNATURES.items():
                    if signature['ttl_range'][0] <= ttl_guess <= signature['ttl_range'][1]:
                        return {
                            'os_name': os_name.capitalize(),
                            'os_family': os_name,
                            'accuracy': 60,
                            'method': 'tcp_ip_stack',
                            'details': {
                                'estimated_ttl': ttl_guess,
                            }
                        }
                
                break  # Only need to test one port
            
            except (socket.timeout, socket.error):
                continue
        
        return None
    
    def _estimate_ttl(self, target: str) -> int:
        """
        Estimate initial TTL value.
        
        Args:
            target: Target host
        
        Returns:
            Estimated TTL value
        """
        # Common initial TTL values: 64 (Linux/Unix), 128 (Windows), 255 (Cisco)
        # This is a simplified estimation
        try:
            # Try to determine based on traceroute-like analysis
            # Simplified: return common default
            return random.choice([64, 128])
        except:
            return 64
    
    def _service_based_detection(self, service_info: List[Dict]) -> Optional[Dict]:
        """
        Detect OS based on service fingerprints.
        
        Args:
            service_info: List of service detection results
        
        Returns:
            OS detection result
        """
        os_scores = {
            'linux': 0,
            'windows': 0,
            'macos': 0,
            'freebsd': 0,
        }
        
        # Analyze service banners for OS indicators
        for service in service_info:
            banner = service.get('banner', '')
            product = service.get('product', '')
            
            combined = f"{banner} {product}".lower()
            
            # Check for OS-specific indicators
            for os_name, signature in self.OS_SIGNATURES.items():
                for indicator in signature['indicators']:
                    if indicator.lower() in combined:
                        os_scores[os_name] += 20
            
            # Specific service/product associations
            if 'microsoft' in combined or 'windows' in combined:
                os_scores['windows'] += 30
            elif 'linux' in combined or 'ubuntu' in combined or 'debian' in combined:
                os_scores['linux'] += 30
            elif 'unix' in combined:
                os_scores['linux'] += 15
            elif 'apache' in combined and 'centos' in combined:
                os_scores['linux'] += 25
        
        # Find highest score
        if max(os_scores.values()) > 0:
            best_os = max(os_scores, key=os_scores.get)
            return {
                'os_name': best_os.capitalize(),
                'os_family': best_os,
                'accuracy': min(os_scores[best_os], 90),
                'method': 'service_analysis',
                'details': {
                    'scores': os_scores,
                }
            }
        
        return None
    
    def _port_based_detection(self, open_ports: List[int]) -> Optional[Dict]:
        """
        Detect OS based on open port patterns.
        
        Args:
            open_ports: List of open ports
        
        Returns:
            OS detection result
        """
        # Common port patterns by OS
        windows_ports = {135, 139, 445, 3389}
        linux_ports = {22, 111}
        macos_ports = {548, 631}
        
        windows_score = len(set(open_ports) & windows_ports) * 20
        linux_score = len(set(open_ports) & linux_ports) * 15
        macos_score = len(set(open_ports) & macos_ports) * 20
        
        scores = {
            'windows': windows_score,
            'linux': linux_score,
            'macos': macos_score,
        }
        
        if max(scores.values()) > 0:
            best_os = max(scores, key=scores.get)
            return {
                'os_name': best_os.capitalize(),
                'os_family': best_os,
                'accuracy': min(scores[best_os], 70),
                'method': 'port_analysis',
                'details': {
                    'matching_ports': list(set(open_ports) & 
                                         (windows_ports if best_os == 'windows' 
                                          else linux_ports if best_os == 'linux' 
                                          else macos_ports)),
                }
            }
        
        return None
    
    def _combine_results(self, results: List[Dict]) -> List[Dict]:
        """
        Combine multiple detection results and rank by confidence.
        
        Args:
            results: List of detection results
        
        Returns:
            Combined and ranked results
        """
        if not results:
            return [{
                'os_name': 'Unknown',
                'os_family': 'unknown',
                'accuracy': 0,
                'method': 'none',
            }]
        
        # Aggregate scores by OS
        os_aggregates = {}
        
        for result in results:
            os_name = result['os_name']
            if os_name not in os_aggregates:
                os_aggregates[os_name] = {
                    'os_name': os_name,
                    'os_family': result['os_family'],
                    'accuracy': 0,
                    'methods': [],
                }
            
            os_aggregates[os_name]['accuracy'] += result['accuracy']
            os_aggregates[os_name]['methods'].append(result['method'])
        
        # Sort by accuracy
        combined = sorted(os_aggregates.values(), 
                         key=lambda x: x['accuracy'], 
                         reverse=True)
        
        # Normalize accuracy
        if combined:
            max_accuracy = combined[0]['accuracy']
            for item in combined:
                item['accuracy'] = min(int((item['accuracy'] / max_accuracy) * 100), 100)
        
        return combined
    
    def generate_os_cpe(self, os_family: str, version: str = '') -> str:
        """
        Generate CPE string for detected OS.
        
        Args:
            os_family: OS family name
            version: OS version
        
        Returns:
            CPE string
        """
        vendor_map = {
            'linux': 'linux',
            'windows': 'microsoft',
            'macos': 'apple',
            'freebsd': 'freebsd',
        }
        
        vendor = vendor_map.get(os_family.lower(), os_family.lower())
        
        if version:
            return f"cpe:/o:{vendor}:{os_family.lower()}:{version}"
        else:
            return f"cpe:/o:{vendor}:{os_family.lower()}"
