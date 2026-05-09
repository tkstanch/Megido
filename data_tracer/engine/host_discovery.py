"""
Host discovery module for detecting active hosts on a network.
Implements various host discovery techniques similar to Nmap.
"""

import socket
import struct
import random
import time
import subprocess
import platform
import errno
from typing import List, Dict, Tuple, Optional


class HostDiscovery:
    """
    Host discovery engine implementing multiple discovery techniques.
    """
    
    def __init__(self, stealth_config: Optional[Dict] = None):
        """
        Initialize the host discovery engine.
        
        Args:
            stealth_config: Optional configuration for stealth operations
        """
        self.stealth_config = stealth_config or {}
        self.discovery_results = []
    
    def discover_hosts(self, target: str, method: str = 'ping') -> List[Dict]:
        """
        Discover active hosts using specified method.
        
        Args:
            target: Target IP or network range
            method: Discovery method (ping, arp, tcp, udp)
        
        Returns:
            List of discovered hosts with their information
        """
        results = []
        
        if method == 'ping':
            results = self._icmp_ping_sweep(target)
        elif method == 'arp':
            results = self._arp_discovery(target)
        elif method == 'tcp':
            results = self._tcp_discovery(target)
        elif method == 'udp':
            results = self._udp_discovery(target)
        else:
            results = self._combined_discovery(target)
        
        self.discovery_results = results
        return results
    
    def _icmp_ping_sweep(self, target: str) -> List[Dict]:
        """
        Perform ICMP echo request (ping) sweep.
        
        Args:
            target: Target IP or range
        
        Returns:
            List of responding hosts
        """
        results = []
        hosts = self._parse_target_range(target)
        
        for host in hosts:
            try:
                # Apply stealth timing if configured
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                reachable = self._ping_host(host)
                discovery_method = 'icmp_ping'

                if not reachable:
                    reachable = self._is_host_reachable_via_tcp(host)
                    if reachable:
                        discovery_method = 'tcp_connect_fallback'

                if reachable:
                    results.append({
                        'ip': host,
                        'status': 'up',
                        'method': discovery_method,
                        'response_time': random.uniform(0.01, 0.5),  # Simulated RTT
                    })
            except (socket.error, socket.timeout):
                # Host not reachable
                pass
        
        return results
    
    def _arp_discovery(self, target: str) -> List[Dict]:
        """
        Perform ARP-based host discovery (local network).
        
        Args:
            target: Target IP or range
        
        Returns:
            List of discovered hosts
        """
        results = []
        hosts = self._parse_target_range(target)
        
        # ARP discovery typically requires raw socket access and root privileges
        # This is a simplified implementation
        for host in hosts:
            try:
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                # Attempt connection to verify host
                socket.setdefaulttimeout(1)
                hostname = socket.gethostbyaddr(host)
                
                results.append({
                    'ip': host,
                    'status': 'up',
                    'method': 'arp',
                    'hostname': hostname[0] if hostname else None,
                })
            except (socket.error, socket.timeout):
                pass
        
        return results
    
    def _tcp_discovery(self, target: str, ports: List[int] = None) -> List[Dict]:
        """
        Perform TCP-based host discovery.
        
        Args:
            target: Target IP or range
            ports: List of ports to probe (default: common ports)
        
        Returns:
            List of discovered hosts
        """
        if ports is None:
            ports = [80, 443, 22, 21, 25, 3389, 8080]
        
        results = []
        hosts = self._parse_target_range(target)
        
        for host in hosts:
            host_up = False
            open_ports = []
            
            for port in ports:
                try:
                    if self.stealth_config.get('scan_delay', 0) > 0:
                        delay = self._get_randomized_delay()
                        time.sleep(delay)
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        host_up = True
                        open_ports.append(port)
                    elif self._is_connection_refused(result):
                        # Connection refused means the host is reachable even if port is closed
                        host_up = True
                except socket.error:
                    pass
            
            if host_up:
                results.append({
                    'ip': host,
                    'status': 'up',
                    'method': 'tcp_probe',
                    'open_ports': open_ports,
                })
        
        return results
    
    def _udp_discovery(self, target: str) -> List[Dict]:
        """
        Perform UDP-based host discovery.
        
        Args:
            target: Target IP or range
        
        Returns:
            List of discovered hosts
        """
        results = []
        hosts = self._parse_target_range(target)
        common_udp_ports = [53, 67, 68, 123, 161, 500, 514]
        
        for host in hosts:
            try:
                if self.stealth_config.get('scan_delay', 0) > 0:
                    delay = self._get_randomized_delay()
                    time.sleep(delay)
                
                # Send UDP probes to common ports
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                
                for port in common_udp_ports:
                    try:
                        sock.sendto(b'\x00', (host, port))
                        # If we get any response or error, host is likely up
                        data, addr = sock.recvfrom(1024)
                        results.append({
                            'ip': host,
                            'status': 'up',
                            'method': 'udp_probe',
                        })
                        break
                    except socket.timeout:
                        continue
                    except socket.error:
                        # ICMP port unreachable means host is up
                        results.append({
                            'ip': host,
                            'status': 'up',
                            'method': 'udp_probe',
                        })
                        break
                
                sock.close()
            except socket.error:
                pass
        
        return results
    
    def _combined_discovery(self, target: str) -> List[Dict]:
        """
        Perform combined host discovery using multiple methods.
        
        Args:
            target: Target IP or range
        
        Returns:
            List of discovered hosts
        """
        all_results = {}
        
        # Try ICMP first
        icmp_results = self._icmp_ping_sweep(target)
        for result in icmp_results:
            all_results[result['ip']] = result
        
        # Try TCP on hosts that didn't respond to ICMP
        if len(all_results) == 0:
            tcp_results = self._tcp_discovery(target)
            for result in tcp_results:
                if result['ip'] not in all_results:
                    all_results[result['ip']] = result
        
        return list(all_results.values())
    
    def _parse_target_range(self, target: str) -> List[str]:
        """
        Parse target specification into list of IP addresses.
        
        Args:
            target: Target specification (single IP, CIDR, range)
        
        Returns:
            List of IP addresses
        """
        # Handle single IP
        if self._is_valid_ip(target):
            return [target]
        
        # Handle CIDR notation (simplified)
        if '/' in target:
            return self._expand_cidr(target)
        
        # Handle range notation (e.g., 192.168.1.1-10)
        if '-' in target:
            return self._expand_range(target)
        
        # Try to resolve hostname
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except socket.error:
            return []
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def _expand_cidr(self, cidr: str) -> List[str]:
        """
        Expand CIDR notation to list of IPs (simplified).
        
        Args:
            cidr: CIDR notation (e.g., 192.168.1.0/24)
        
        Returns:
            List of IP addresses
        """
        try:
            ip, mask = cidr.split('/')
            mask = int(mask)
            
            # Convert IP to integer
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            
            # Calculate number of hosts
            num_hosts = 2 ** (32 - mask)
            
            # Limit to reasonable number
            if num_hosts > 1024:
                num_hosts = 1024
            
            # Generate IP list
            ips = []
            for i in range(1, min(num_hosts, 254)):
                new_ip = socket.inet_ntoa(struct.pack('!I', ip_int + i))
                ips.append(new_ip)
            
            return ips
        except (ValueError, socket.error):
            return []
    
    def _expand_range(self, range_spec: str) -> List[str]:
        """
        Expand IP range notation (simplified).
        
        Args:
            range_spec: Range notation (e.g., 192.168.1.1-10)
        
        Returns:
            List of IP addresses
        """
        try:
            parts = range_spec.split('.')
            if len(parts) != 4:
                return []
            
            # Check if last octet has range
            if '-' in parts[3]:
                start, end = parts[3].split('-')
                start = int(start)
                end = int(end)
                
                base_ip = '.'.join(parts[:3])
                ips = []
                for i in range(start, min(end + 1, 255)):
                    ips.append(f"{base_ip}.{i}")
                
                return ips
        except (ValueError, IndexError):
            pass
        
        return []

    def _ping_host(self, host: str, timeout_seconds: int = 1) -> bool:
        """Probe a host with platform-appropriate ping arguments."""
        try:
            if platform.system().lower().startswith('win'):
                command = ['ping', '-n', '1', '-w', str(timeout_seconds * 1000), host]
            else:
                command = ['ping', '-c', '1', '-W', str(timeout_seconds), host]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 1,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def _is_host_reachable_via_tcp(self, host: str, ports: Optional[List[int]] = None) -> bool:
        """Fallback host liveness check using TCP connect probes."""
        if ports is None:
            ports = [80, 443, 22, 53]

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0 or self._is_connection_refused(result):
                    return True
            except socket.error:
                continue

        return False

    @staticmethod
    def _is_connection_refused(code: int) -> bool:
        """Cross-platform connection-refused detection for connect_ex return codes."""
        refused_codes = {errno.ECONNREFUSED}
        wsa_refused = getattr(errno, 'WSAECONNREFUSED', None)
        if wsa_refused is not None:
            refused_codes.add(wsa_refused)
        else:
            refused_codes.add(10061)
        return code in refused_codes
    
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
