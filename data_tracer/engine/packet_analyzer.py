"""
Packet capture and analysis module.
Collects network packets, analyzes them, and determines relevance.
"""

import socket
import struct
import time
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


class PacketAnalyzer:
    """
    Network packet capture and analysis engine.
    """
    
    # Protocol numbers
    PROTO_ICMP = 1
    PROTO_TCP = 6
    PROTO_UDP = 17
    
    # TCP flags
    TCP_FIN = 0x01
    TCP_SYN = 0x02
    TCP_RST = 0x04
    TCP_PSH = 0x08
    TCP_ACK = 0x10
    TCP_URG = 0x20
    
    def __init__(self):
        """Initialize packet analyzer."""
        self.captured_packets = []
        self.analysis_results = []
    
    def capture_packets(self,
                       target: str,
                       duration: int = 10,
                       max_packets: int = 100) -> List[Dict]:
        """
        Capture network packets for analysis.
        
        Args:
            target: Target IP address
            duration: Capture duration in seconds
            max_packets: Maximum number of packets to capture
        
        Returns:
            List of captured packet information
        """
        packets = []
        start_time = time.time()
        
        # Note: Real packet capture requires raw socket access and privileges
        # This is a simplified simulation
        
        # Simulate packet capture
        count = 0
        while time.time() - start_time < duration and count < max_packets:
            # In real implementation, this would capture actual packets
            # For now, we'll create placeholder entries
            time.sleep(0.1)
            count += 1
        
        self.captured_packets = packets
        return packets
    
    def analyze_packet(self, packet_data: bytes) -> Dict:
        """
        Analyze a single network packet.
        
        Args:
            packet_data: Raw packet bytes
        
        Returns:
            Packet analysis dictionary
        """
        analysis = {
            'packet_type': 'unknown',
            'source_ip': None,
            'destination_ip': None,
            'source_port': None,
            'destination_port': None,
            'packet_size': len(packet_data),
            'flags': [],
            'payload': b'',
            'relevance': 'low',
            'analysis_notes': [],
        }
        
        try:
            # Parse IP header (simplified)
            if len(packet_data) >= 20:
                ip_header = self._parse_ip_header(packet_data[:20])
                analysis.update(ip_header)
                
                # Parse transport layer based on protocol
                if ip_header['protocol'] == self.PROTO_TCP and len(packet_data) >= 40:
                    tcp_info = self._parse_tcp_header(packet_data[20:40])
                    analysis.update(tcp_info)
                    analysis['packet_type'] = 'tcp'
                
                elif ip_header['protocol'] == self.PROTO_UDP and len(packet_data) >= 28:
                    udp_info = self._parse_udp_header(packet_data[20:28])
                    analysis.update(udp_info)
                    analysis['packet_type'] = 'udp'
                
                elif ip_header['protocol'] == self.PROTO_ICMP:
                    analysis['packet_type'] = 'icmp'
                
                # Determine relevance
                analysis['relevance'] = self._determine_relevance(analysis)
                
                # Generate analysis notes
                analysis['analysis_notes'] = self._generate_analysis_notes(analysis)
        
        except Exception as e:
            analysis['analysis_notes'].append(f"Error parsing packet: {str(e)}")
        
        return analysis
    
    def _parse_ip_header(self, header: bytes) -> Dict:
        """
        Parse IP header.
        
        Args:
            header: IP header bytes (20 bytes)
        
        Returns:
            Dictionary with IP header information
        """
        # Unpack IP header
        ip_header = struct.unpack('!BBHHHBBH4s4s', header)
        
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        ttl = ip_header[5]
        protocol = ip_header[6]
        source_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'ip_version': version,
            'ttl': ttl,
            'protocol': protocol,
            'source_ip': source_ip,
            'destination_ip': dest_ip,
        }
    
    def _parse_tcp_header(self, header: bytes) -> Dict:
        """
        Parse TCP header.
        
        Args:
            header: TCP header bytes (20 bytes minimum)
        
        Returns:
            Dictionary with TCP header information
        """
        # Unpack TCP header
        tcp_header = struct.unpack('!HHLLBBHHH', header)
        
        source_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        flags = tcp_header[5]
        
        # Parse flags
        flag_list = []
        if flags & self.TCP_FIN:
            flag_list.append('FIN')
        if flags & self.TCP_SYN:
            flag_list.append('SYN')
        if flags & self.TCP_RST:
            flag_list.append('RST')
        if flags & self.TCP_PSH:
            flag_list.append('PSH')
        if flags & self.TCP_ACK:
            flag_list.append('ACK')
        if flags & self.TCP_URG:
            flag_list.append('URG')
        
        return {
            'source_port': source_port,
            'destination_port': dest_port,
            'seq_number': seq_num,
            'ack_number': ack_num,
            'flags': flag_list,
        }
    
    def _parse_udp_header(self, header: bytes) -> Dict:
        """
        Parse UDP header.
        
        Args:
            header: UDP header bytes (8 bytes)
        
        Returns:
            Dictionary with UDP header information
        """
        # Unpack UDP header
        udp_header = struct.unpack('!HHHH', header)
        
        source_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        
        return {
            'source_port': source_port,
            'destination_port': dest_port,
            'udp_length': length,
        }
    
    def _determine_relevance(self, packet_info: Dict) -> str:
        """
        Determine packet relevance for analysis.
        
        Args:
            packet_info: Parsed packet information
        
        Returns:
            Relevance level (high, medium, low, none)
        """
        relevance = 'low'
        
        # High relevance criteria
        high_relevance_ports = [21, 22, 23, 25, 80, 443, 3389, 3306, 5432]
        
        if packet_info.get('packet_type') == 'tcp':
            # SYN packets are interesting for port scanning
            if 'SYN' in packet_info.get('flags', []) and 'ACK' not in packet_info.get('flags', []):
                relevance = 'high'
            
            # Packets to/from interesting ports
            dest_port = packet_info.get('destination_port')
            src_port = packet_info.get('source_port')
            
            if dest_port in high_relevance_ports or src_port in high_relevance_ports:
                relevance = 'high'
            
            # RST packets indicate closed ports
            if 'RST' in packet_info.get('flags', []):
                relevance = 'medium'
            
            # PSH+ACK indicates data transfer
            if 'PSH' in packet_info.get('flags', []) and 'ACK' in packet_info.get('flags', []):
                relevance = 'high'
        
        elif packet_info.get('packet_type') == 'udp':
            # UDP packets to common services
            dest_port = packet_info.get('destination_port')
            if dest_port in [53, 123, 161, 500]:
                relevance = 'medium'
        
        elif packet_info.get('packet_type') == 'icmp':
            # ICMP packets are moderately interesting
            relevance = 'medium'
        
        return relevance
    
    def _generate_analysis_notes(self, packet_info: Dict) -> List[str]:
        """
        Generate human-readable analysis notes.
        
        Args:
            packet_info: Parsed packet information
        
        Returns:
            List of analysis notes
        """
        notes = []
        
        packet_type = packet_info.get('packet_type', 'unknown')
        notes.append(f"Packet type: {packet_type.upper()}")
        
        if packet_type == 'tcp':
            flags = packet_info.get('flags', [])
            notes.append(f"TCP flags: {', '.join(flags)}")
            
            # Interpret common flag combinations
            if 'SYN' in flags and 'ACK' not in flags:
                notes.append("SYN packet - connection initiation attempt")
            elif 'SYN' in flags and 'ACK' in flags:
                notes.append("SYN-ACK packet - connection accepted")
            elif 'RST' in flags:
                notes.append("RST packet - connection refused or terminated")
            elif 'FIN' in flags:
                notes.append("FIN packet - connection termination")
            
            # Port significance
            dest_port = packet_info.get('destination_port')
            if dest_port:
                port_services = {
                    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                    80: 'HTTP', 443: 'HTTPS', 3389: 'RDP',
                    3306: 'MySQL', 5432: 'PostgreSQL',
                }
                if dest_port in port_services:
                    notes.append(f"Target port {dest_port} ({port_services[dest_port]})")
        
        elif packet_type == 'udp':
            dest_port = packet_info.get('destination_port')
            if dest_port:
                udp_services = {
                    53: 'DNS', 67: 'DHCP', 123: 'NTP',
                    161: 'SNMP', 500: 'IKE',
                }
                if dest_port in udp_services:
                    notes.append(f"UDP port {dest_port} ({udp_services[dest_port]})")
        
        elif packet_type == 'icmp':
            notes.append("ICMP packet - typically used for ping or error messages")
        
        return notes
    
    def aggregate_analysis(self, packets: List[Dict]) -> Dict:
        """
        Aggregate analysis of multiple packets.
        
        Args:
            packets: List of analyzed packets
        
        Returns:
            Aggregated analysis
        """
        aggregated = {
            'total_packets': len(packets),
            'packet_types': defaultdict(int),
            'high_relevance_count': 0,
            'unique_ports': set(),
            'unique_ips': set(),
            'flags_distribution': defaultdict(int),
        }
        
        for packet in packets:
            # Count packet types
            packet_type = packet.get('packet_type', 'unknown')
            aggregated['packet_types'][packet_type] += 1
            
            # Count relevance
            if packet.get('relevance') == 'high':
                aggregated['high_relevance_count'] += 1
            
            # Collect unique ports and IPs
            if packet.get('source_port'):
                aggregated['unique_ports'].add(packet['source_port'])
            if packet.get('destination_port'):
                aggregated['unique_ports'].add(packet['destination_port'])
            if packet.get('source_ip'):
                aggregated['unique_ips'].add(packet['source_ip'])
            if packet.get('destination_ip'):
                aggregated['unique_ips'].add(packet['destination_ip'])
            
            # Count flags
            for flag in packet.get('flags', []):
                aggregated['flags_distribution'][flag] += 1
        
        # Convert sets to lists for JSON serialization
        aggregated['unique_ports'] = list(aggregated['unique_ports'])
        aggregated['unique_ips'] = list(aggregated['unique_ips'])
        aggregated['packet_types'] = dict(aggregated['packet_types'])
        aggregated['flags_distribution'] = dict(aggregated['flags_distribution'])
        
        return aggregated
    
    def act_on_packet(self, packet_info: Dict) -> Dict:
        """
        Take action based on packet relevance and content.
        
        Args:
            packet_info: Analyzed packet information
        
        Returns:
            Dictionary describing action taken
        """
        action = {
            'action': 'none',
            'reason': '',
            'details': {},
        }
        
        relevance = packet_info.get('relevance', 'low')
        
        if relevance == 'high':
            # Log high-relevance packets
            action['action'] = 'log'
            action['reason'] = 'High relevance packet detected'
            action['details'] = {
                'packet_type': packet_info.get('packet_type'),
                'source': f"{packet_info.get('source_ip')}:{packet_info.get('source_port', 'N/A')}",
                'destination': f"{packet_info.get('destination_ip')}:{packet_info.get('destination_port', 'N/A')}",
            }
            
            # Check for potential security issues
            if packet_info.get('packet_type') == 'tcp':
                flags = packet_info.get('flags', [])
                if 'SYN' in flags and 'ACK' not in flags:
                    action['action'] = 'alert'
                    action['reason'] = 'Potential port scan detected'
        
        return action
