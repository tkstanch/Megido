"""
Port scanning module implementing various scan techniques.
Similar to Nmap's port scanning capabilities.
"""

import socket
import random
import time
import struct
from typing import List, Dict, Tuple, Optional


class PortScanner:
    """
    Port scanning engine with multiple scan techniques.
    """
    
    # Common ports to scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443
    ]
    
    # Well-known port ranges
    WELL_KNOWN_PORTS = list(range(1, 1024))
    
    def __init__(self, stealth_config: Optional[Dict] = None):
        """
        Initialize port scanner.
        
        Args:
            stealth_config: Configuration for stealth scanning
        """
        self.stealth_config = stealth_config or {}
        self.scan_results = []
    
    def scan_ports(self, 
                   target: str, 
                   ports: Optional[List[int]] = None,
                   scan_type: str = 'connect') -> List[Dict]:
        """
        Scan ports on target host.
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan (default: common ports)
            scan_type: Type of scan (connect, syn, ack, fin, xmas, null, udp)
        
        Returns:
            List of scan results
        """
        if ports is None:
            ports = self.COMMON_PORTS
        
        # Randomize port order for stealth if configured
        if self.stealth_config.get('randomize_hosts', False):
            ports = random.sample(ports, len(ports))
        
        scan_methods = {
            'connect': self._tcp_connect_scan,
            'syn': self._tcp_syn_scan,
            'ack': self._tcp_ack_scan,
            'fin': self._tcp_fin_scan,
            'xmas': self._tcp_xmas_scan,
            'null': self._tcp_null_scan,
            'udp': self._udp_scan,
        }
        
        scan_method = scan_methods.get(scan_type, self._tcp_connect_scan)
        results = scan_method(target, ports)
        
        self.scan_results = results
        return results
    
    def _tcp_connect_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Perform TCP connect scan (full three-way handshake).
        Most reliable but easily detectable.
        
        Args:
            target: Target host
            ports: Ports to scan
        
        Returns:
            List of port scan results
        """
        results = []
        
        for port in ports:
            try:
                # Apply stealth delay
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    state = 'open'
                    # Try to grab banner
                    banner = self._grab_banner(sock)
                else:
                    state = 'closed'
                    banner = None
                
                sock.close()
                
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': state,
                    'scan_type': 'connect',
                    'banner': banner,
                })
                
            except socket.timeout:
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'filtered',
                    'scan_type': 'connect',
                    'banner': None,
                })
            except socket.error as e:
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'closed',
                    'scan_type': 'connect',
                    'banner': None,
                    'error': str(e),
                })
        
        return results
    
    def _tcp_syn_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Perform TCP SYN scan (stealth scan).
        Sends SYN packet and analyzes response without completing handshake.
        Requires raw socket access (root/admin privileges).
        
        Args:
            target: Target host
            ports: Ports to scan
        
        Returns:
            List of port scan results
        """
        results = []
        
        # Note: True SYN scanning requires raw socket access
        # This is a simplified implementation using connect() with timeout
        # In a real implementation, you would use scapy or raw sockets
        
        for port in ports:
            try:
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Set socket to non-blocking to simulate SYN scan behavior
                sock.setblocking(False)
                
                try:
                    sock.connect((target, port))
                    state = 'open'
                except BlockingIOError:
                    # Connection in progress - port likely open
                    state = 'open'
                except ConnectionRefusedError:
                    state = 'closed'
                except socket.timeout:
                    state = 'filtered'
                
                sock.close()
                
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': state,
                    'scan_type': 'syn',
                    'banner': None,
                })
                
            except socket.error:
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'filtered',
                    'scan_type': 'syn',
                    'banner': None,
                })
        
        return results
    
    def _tcp_ack_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Perform TCP ACK scan for firewall detection.
        Sends ACK packet to determine if port is filtered.
        
        Args:
            target: Target host
            ports: Ports to scan
        
        Returns:
            List of port scan results
        """
        results = []
        
        # ACK scanning requires raw socket manipulation
        # This is a simplified implementation
        for port in ports:
            try:
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                result = sock.connect_ex((target, port))
                
                if result == 0 or result == 111:
                    state = 'unfiltered'
                else:
                    state = 'filtered'
                
                sock.close()
                
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': state,
                    'scan_type': 'ack',
                    'banner': None,
                })
                
            except socket.error:
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'filtered',
                    'scan_type': 'ack',
                    'banner': None,
                })
        
        return results
    
    def _tcp_fin_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Perform TCP FIN scan.
        Sends FIN packet - closed port responds with RST, open port ignores.
        Stealthy but less reliable.
        
        Args:
            target: Target host
            ports: Ports to scan
        
        Returns:
            List of port scan results
        """
        results = []
        
        # FIN scanning requires raw socket manipulation
        # This is a simplified implementation
        for port in ports:
            try:
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                try:
                    result = sock.connect_ex((target, port))
                    if result == 111:  # Connection refused
                        state = 'closed'
                    else:
                        state = 'open|filtered'
                except socket.timeout:
                    state = 'open|filtered'
                
                sock.close()
                
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': state,
                    'scan_type': 'fin',
                    'banner': None,
                })
                
            except socket.error:
                results.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open|filtered',
                    'scan_type': 'fin',
                    'banner': None,
                })
        
        return results
    
    def _tcp_xmas_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Perform TCP XMAS scan.
        Sends packet with FIN, PSH, and URG flags set.
        Similar to FIN scan behavior.
        
        Args:
            target: Target host
            ports: Ports to scan
        
        Returns:
            List of port scan results
        """
        # XMAS scan behavior similar to FIN scan in this simplified version
        results = self._tcp_fin_scan(target, ports)
        for result in results:
            result['scan_type'] = 'xmas'
        
        return results
    
    def _tcp_null_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Perform TCP NULL scan.
        Sends packet with no flags set.
        Similar to FIN scan behavior.
        
        Args:
            target: Target host
            ports: Ports to scan
        
        Returns:
            List of port scan results
        """
        # NULL scan behavior similar to FIN scan in this simplified version
        results = self._tcp_fin_scan(target, ports)
        for result in results:
            result['scan_type'] = 'null'
        
        return results
    
    def _udp_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """
        Perform UDP port scan.
        UDP scanning is challenging - no response might mean open or filtered.
        
        Args:
            target: Target host
            ports: Ports to scan
        
        Returns:
            List of port scan results
        """
        results = []
        
        for port in ports:
            try:
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                
                # Send empty UDP packet
                sock.sendto(b'\x00', (target, port))
                
                try:
                    # Try to receive response
                    data, addr = sock.recvfrom(1024)
                    state = 'open'
                except socket.timeout:
                    # No response could mean open or filtered
                    state = 'open|filtered'
                except socket.error:
                    # ICMP port unreachable means closed
                    state = 'closed'
                
                sock.close()
                
                results.append({
                    'port': port,
                    'protocol': 'udp',
                    'state': state,
                    'scan_type': 'udp',
                    'banner': None,
                })
                
            except socket.error:
                results.append({
                    'port': port,
                    'protocol': 'udp',
                    'state': 'open|filtered',
                    'scan_type': 'udp',
                    'banner': None,
                })
        
        return results
    
    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """
        Attempt to grab service banner from open port.
        
        Args:
            sock: Connected socket
        
        Returns:
            Banner string or None
        """
        try:
            sock.settimeout(2)
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
        except (socket.timeout, socket.error):
            return None
    
    def _get_randomized_delay(self) -> float:
        """
        Get randomized delay for stealth operations.
        
        Returns:
            Delay in seconds
        """
        base_delay = self.stealth_config.get('scan_delay', 0)
        max_delay = self.stealth_config.get('max_scan_delay', base_delay * 2)
        
        if max_delay > base_delay:
            return random.uniform(base_delay, max_delay)
        return base_delay
    
    def scan_port_range(self, 
                       target: str,
                       start_port: int = 1,
                       end_port: int = 1024,
                       scan_type: str = 'connect') -> List[Dict]:
        """
        Scan a range of ports.
        
        Args:
            target: Target host
            start_port: Starting port number
            end_port: Ending port number
            scan_type: Type of scan
        
        Returns:
            List of scan results
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports(target, ports, scan_type)
