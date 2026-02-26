"""
Deep traffic analysis engine for Data Tracer.
Implements DPI, protocol dissection, flow analysis,
anomaly detection, and encrypted traffic analysis.
"""

import random
import hashlib
import struct
import socket
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict


# Protocol signatures for DPI
PROTOCOL_SIGNATURES = {
    'http': {
        'ports': [80, 8080, 8000, 8888],
        'patterns': [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HTTP/'],
        'description': 'Hypertext Transfer Protocol',
    },
    'https': {
        'ports': [443, 8443],
        'patterns': [b'\x16\x03'],  # TLS handshake
        'description': 'HTTP over TLS',
    },
    'ssh': {
        'ports': [22],
        'patterns': [b'SSH-'],
        'description': 'Secure Shell Protocol',
    },
    'ftp': {
        'ports': [21],
        'patterns': [b'220 ', b'FTP'],
        'description': 'File Transfer Protocol',
    },
    'smtp': {
        'ports': [25, 465, 587],
        'patterns': [b'220 ', b'EHLO', b'HELO'],
        'description': 'Simple Mail Transfer Protocol',
    },
    'pop3': {
        'ports': [110, 995],
        'patterns': [b'+OK'],
        'description': 'Post Office Protocol v3',
    },
    'imap': {
        'ports': [143, 993],
        'patterns': [b'* OK'],
        'description': 'Internet Message Access Protocol',
    },
    'dns': {
        'ports': [53],
        'patterns': [],
        'description': 'Domain Name System',
    },
    'mysql': {
        'ports': [3306],
        'patterns': [b'\x4a\x00\x00\x00'],  # MySQL greeting
        'description': 'MySQL Database Protocol',
    },
    'redis': {
        'ports': [6379],
        'patterns': [b'+PONG', b'-ERR', b'*'],
        'description': 'Redis Protocol',
    },
    'mongodb': {
        'ports': [27017],
        'patterns': [b'\x3f\x00\x00\x00'],
        'description': 'MongoDB Wire Protocol',
    },
    'elasticsearch': {
        'ports': [9200, 9300],
        'patterns': [b'"cluster_name"', b'You Know, for Search'],
        'description': 'Elasticsearch HTTP API',
    },
    'rdp': {
        'ports': [3389],
        'patterns': [b'\x03\x00'],  # TPKT header
        'description': 'Remote Desktop Protocol',
    },
    'vnc': {
        'ports': [5900, 5901],
        'patterns': [b'RFB '],
        'description': 'Virtual Network Computing',
    },
    'mqtt': {
        'ports': [1883, 8883],
        'patterns': [b'\x10'],  # CONNECT packet type
        'description': 'Message Queuing Telemetry Transport',
    },
    'amqp': {
        'ports': [5672, 5671],
        'patterns': [b'AMQP'],
        'description': 'Advanced Message Queuing Protocol',
    },
    'smb': {
        'ports': [445, 139],
        'patterns': [b'\xff\x53\x4d\x42', b'\xfe\x53\x4d\x42'],  # SMB1/SMB2
        'description': 'Server Message Block',
    },
    'ldap': {
        'ports': [389, 636],
        'patterns': [b'\x30'],  # ASN.1 SEQUENCE
        'description': 'Lightweight Directory Access Protocol',
    },
    'snmp': {
        'ports': [161, 162],
        'patterns': [b'\x30'],  # ASN.1
        'description': 'Simple Network Management Protocol',
    },
    'ntp': {
        'ports': [123],
        'patterns': [],
        'description': 'Network Time Protocol',
    },
    'sip': {
        'ports': [5060, 5061],
        'patterns': [b'SIP/', b'INVITE ', b'REGISTER '],
        'description': 'Session Initiation Protocol',
    },
    'rtsp': {
        'ports': [554],
        'patterns': [b'RTSP/'],
        'description': 'Real Time Streaming Protocol',
    },
    'postgresql': {
        'ports': [5432],
        'patterns': [],
        'description': 'PostgreSQL Database Protocol',
    },
}

# JA3 hash database for TLS fingerprinting
JA3_DATABASE = {
    'e6573e91e6eb777c0933c5b8f97f10cd': {'client': 'Python requests', 'version': '2.x'},
    '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0': {
        'client': 'Chrome 91+', 'os': 'Various'
    },
    'aaa': {'client': 'Firefox', 'version': '89+'},
}

# Anomaly detection thresholds
ANOMALY_THRESHOLDS = {
    'port_scan': {
        'unique_ports_per_src': 50,  # >50 unique ports from single source = port scan
        'time_window_seconds': 60,
    },
    'ddos': {
        'packets_per_second': 10000,
        'connections_per_second': 1000,
    },
    'data_exfiltration': {
        'bytes_per_hour': 1_000_000_000,  # 1GB/hour
        'dns_queries_per_minute': 100,
    },
    'c2_beacon': {
        'interval_variance': 0.1,  # Very regular intervals suggest beaconing
        'min_interval_seconds': 30,
    },
}


class TrafficAnalyzer:
    """
    Deep traffic analysis engine implementing DPI, protocol dissection,
    flow reconstruction, and anomaly detection.
    """

    def __init__(self):
        """Initialize the traffic analyzer."""
        self.captured_packets: List[Dict] = []
        self.flows: Dict[str, Dict] = {}
        self.protocol_stats: Dict[str, int] = defaultdict(int)
        self.anomalies: List[Dict] = []
        self.bandwidth_stats: Dict = defaultdict(int)

    def analyze_packet(self, packet_data: Dict) -> Dict:
        """
        Analyze a single packet using deep packet inspection.

        Args:
            packet_data: Dictionary containing packet information

        Returns:
            Enriched packet analysis
        """
        analysis = {
            'original': packet_data,
            'protocol': 'unknown',
            'application_protocol': 'unknown',
            'flow_id': None,
            'direction': 'unknown',
            'anomalies': [],
            'extracted_data': {},
            'timestamp': datetime.utcnow().isoformat(),
        }

        # Determine transport protocol
        packet_type = packet_data.get('packet_type', '').lower()
        src_port = packet_data.get('source_port')
        dst_port = packet_data.get('destination_port')
        payload = packet_data.get('payload', b'')

        # Identify application protocol
        analysis['application_protocol'] = self._identify_protocol(
            src_port, dst_port, payload, packet_type
        )

        # Generate flow ID
        analysis['flow_id'] = self._generate_flow_id(packet_data)

        # Update flow tracking
        self._update_flow(packet_data, analysis)

        # Extract application-layer data
        if analysis['application_protocol'] == 'http':
            analysis['extracted_data'] = self._parse_http(payload)
        elif analysis['application_protocol'] == 'dns':
            analysis['extracted_data'] = self._parse_dns(payload)
        elif analysis['application_protocol'] == 'smtp':
            analysis['extracted_data'] = self._parse_smtp(payload)

        # Check for anomalies
        analysis['anomalies'] = self._check_packet_anomalies(packet_data, analysis)

        # Update bandwidth statistics
        src_ip = packet_data.get('source_ip', '')
        dst_ip = packet_data.get('destination_ip', '')
        size = packet_data.get('packet_size', 0)
        self.bandwidth_stats[f"{src_ip}->out"] += size
        self.bandwidth_stats[f"{dst_ip}->in"] += size
        self.protocol_stats[analysis['application_protocol']] += 1

        self.captured_packets.append(analysis)
        return analysis

    def _identify_protocol(
        self, src_port: Optional[int], dst_port: Optional[int],
        payload: bytes, transport: str
    ) -> str:
        """Identify application protocol via DPI."""
        if not isinstance(payload, bytes):
            try:
                payload = bytes(payload) if payload else b''
            except (TypeError, ValueError):
                payload = b''

        # Check payload signatures
        for proto_name, proto_info in PROTOCOL_SIGNATURES.items():
            for pattern in proto_info.get('patterns', []):
                if payload and payload[:len(pattern)] == pattern:
                    return proto_name

        # Fall back to port-based identification
        for port in [dst_port, src_port]:
            if port is None:
                continue
            for proto_name, proto_info in PROTOCOL_SIGNATURES.items():
                if port in proto_info.get('ports', []):
                    return proto_name

        return 'unknown'

    def _generate_flow_id(self, packet: Dict) -> str:
        """Generate a unique flow identifier for a packet."""
        src = f"{packet.get('source_ip', '')}:{packet.get('source_port', '')}"
        dst = f"{packet.get('destination_ip', '')}:{packet.get('destination_port', '')}"
        proto = packet.get('packet_type', '')

        # Bidirectional flow ID (normalize order)
        parts = sorted([src, dst])
        flow_str = f"{parts[0]}-{parts[1]}-{proto}"
        return hashlib.md5(flow_str.encode()).hexdigest()[:16]

    def _update_flow(self, packet: Dict, analysis: Dict) -> None:
        """Update flow tracking with packet information."""
        flow_id = analysis['flow_id']

        if flow_id not in self.flows:
            self.flows[flow_id] = {
                'flow_id': flow_id,
                'src_ip': packet.get('source_ip'),
                'dst_ip': packet.get('destination_ip'),
                'src_port': packet.get('source_port'),
                'dst_port': packet.get('destination_port'),
                'protocol': packet.get('packet_type'),
                'application_protocol': analysis['application_protocol'],
                'packet_count': 0,
                'byte_count': 0,
                'start_time': datetime.utcnow().isoformat(),
                'last_seen': datetime.utcnow().isoformat(),
                'state': 'active',
                'flags': [],
            }

        flow = self.flows[flow_id]
        flow['packet_count'] += 1
        flow['byte_count'] += packet.get('packet_size', 0)
        flow['last_seen'] = datetime.utcnow().isoformat()

        # Track TCP flags
        flags = packet.get('flags', '').upper()
        if flags and flags not in flow['flags']:
            flow['flags'].append(flags)

        # Detect flow state
        if 'SYN' in flags and 'ACK' not in flags:
            flow['state'] = 'syn_sent'
        elif 'SYN' in flags and 'ACK' in flags:
            flow['state'] = 'established'
        elif 'FIN' in flags or 'RST' in flags:
            flow['state'] = 'closed'

    def _parse_http(self, payload: bytes) -> Dict:
        """Parse HTTP request/response."""
        if not payload:
            return {}

        try:
            text = payload.decode('utf-8', errors='ignore')
        except (AttributeError, UnicodeDecodeError):
            return {}

        parsed = {}
        lines = text.split('\r\n')

        if not lines:
            return parsed

        first_line = lines[0]

        # Parse HTTP request
        if first_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')):
            parts = first_line.split(' ')
            if len(parts) >= 2:
                parsed['method'] = parts[0]
                parsed['url'] = parts[1]
                parsed['version'] = parts[2] if len(parts) > 2 else ''

        # Parse HTTP response
        elif first_line.startswith('HTTP/'):
            parts = first_line.split(' ', 2)
            if len(parts) >= 2:
                parsed['version'] = parts[0]
                parsed['status_code'] = parts[1]
                parsed['reason'] = parts[2] if len(parts) > 2 else ''

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, _, value = line.partition(':')
                headers[key.strip().lower()] = value.strip()
            elif line == '':
                break

        parsed['headers'] = headers

        # Extract credentials from Authorization header
        auth = headers.get('authorization', '')
        if auth.lower().startswith('basic '):
            import base64
            try:
                decoded = base64.b64decode(auth[6:]).decode('utf-8', errors='ignore')
                parsed['credentials'] = decoded  # username:password
            except Exception:
                pass

        # Extract URLs
        url_pattern = re.compile(r'https?://[^\s"\'<>]+')
        urls = url_pattern.findall(text)
        if urls:
            parsed['extracted_urls'] = urls[:10]

        # Extract email addresses
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        emails = email_pattern.findall(text)
        if emails:
            parsed['extracted_emails'] = list(set(emails))[:10]

        return parsed

    def _parse_dns(self, payload: bytes) -> Dict:
        """Parse DNS packet."""
        if not payload or len(payload) < 12:
            return {}

        try:
            # Parse DNS header
            txid = struct.unpack('!H', payload[:2])[0]
            flags = struct.unpack('!H', payload[2:4])[0]
            qdcount = struct.unpack('!H', payload[4:6])[0]
            ancount = struct.unpack('!H', payload[6:8])[0]

            is_response = bool(flags & 0x8000)
            opcode = (flags >> 11) & 0xF
            rcode = flags & 0xF

            return {
                'transaction_id': txid,
                'is_response': is_response,
                'opcode': opcode,
                'question_count': qdcount,
                'answer_count': ancount,
                'response_code': rcode,
            }
        except struct.error:
            return {}

    def _parse_smtp(self, payload: bytes) -> Dict:
        """Parse SMTP data."""
        if not payload:
            return {}

        try:
            text = payload.decode('utf-8', errors='ignore')
        except AttributeError:
            return {}

        parsed = {}

        # Extract SMTP commands and responses
        for line in text.split('\r\n'):
            if line.startswith('EHLO') or line.startswith('HELO'):
                parsed['client_domain'] = line.split(' ', 1)[1] if ' ' in line else ''
            elif line.startswith('MAIL FROM:'):
                parsed['from'] = line[10:].strip()
            elif line.startswith('RCPT TO:'):
                parsed.setdefault('recipients', []).append(line[8:].strip())
            elif line.startswith('Subject:'):
                parsed['subject'] = line[8:].strip()

        return parsed

    def _check_packet_anomalies(self, packet: Dict, analysis: Dict) -> List[Dict]:
        """Check for anomalies in a packet."""
        anomalies = []
        dst_port = packet.get('destination_port')
        src_ip = packet.get('source_ip', '')

        # Check for suspicious port combinations
        flags = packet.get('flags', '').upper()
        if 'FIN' in flags and 'URG' in flags and 'PSH' in flags:
            anomalies.append({
                'type': 'xmas_scan',
                'severity': 'medium',
                'description': 'XMAS scan packet detected (FIN+URG+PSH flags)',
            })

        if not flags and packet.get('packet_type') == 'tcp':
            anomalies.append({
                'type': 'null_scan',
                'severity': 'medium',
                'description': 'NULL scan packet detected (no TCP flags)',
            })

        # Check for suspicious payloads
        payload = packet.get('payload', b'')
        if payload:
            payload_text = ''
            if isinstance(payload, bytes):
                payload_text = payload.decode('utf-8', errors='ignore')
            elif isinstance(payload, str):
                payload_text = payload

            # Check for potential SQLi in HTTP traffic
            sqli_patterns = ["' OR ", "UNION SELECT", "DROP TABLE", "1=1--"]
            for pattern in sqli_patterns:
                if pattern.lower() in payload_text.lower():
                    anomalies.append({
                        'type': 'potential_sqli',
                        'severity': 'high',
                        'description': f'Potential SQL injection pattern detected: {pattern}',
                    })

            # Check for potential XSS
            xss_patterns = ['<script>', 'javascript:', 'onerror=']
            for pattern in xss_patterns:
                if pattern.lower() in payload_text.lower():
                    anomalies.append({
                        'type': 'potential_xss',
                        'severity': 'high',
                        'description': f'Potential XSS pattern detected: {pattern}',
                    })

        return anomalies

    def detect_port_scan(self, time_window_seconds: int = 60) -> List[Dict]:
        """
        Detect port scanning activity in captured traffic.

        Args:
            time_window_seconds: Time window for analysis

        Returns:
            List of detected port scan events
        """
        port_scans = []
        src_port_map = defaultdict(set)

        for packet in self.captured_packets:
            orig = packet.get('original', {})
            src_ip = orig.get('source_ip', '')
            dst_port = orig.get('destination_port')

            if src_ip and dst_port:
                src_port_map[src_ip].add(dst_port)

        threshold = ANOMALY_THRESHOLDS['port_scan']['unique_ports_per_src']
        for src_ip, ports in src_port_map.items():
            if len(ports) >= threshold:
                port_scans.append({
                    'type': 'port_scan',
                    'severity': 'high',
                    'source_ip': src_ip,
                    'unique_ports': len(ports),
                    'description': f'Potential port scan from {src_ip}: {len(ports)} unique destination ports',
                    'ports_scanned': sorted(list(ports))[:20],
                })

        return port_scans

    def detect_dns_tunneling(self) -> List[Dict]:
        """
        Detect DNS tunneling in captured traffic.

        Returns:
            List of potential DNS tunneling events
        """
        findings = []
        dns_by_domain = defaultdict(list)

        for packet in self.captured_packets:
            if packet.get('application_protocol') == 'dns':
                extracted = packet.get('extracted_data', {})
                # Long subdomains are indicative of DNS tunneling
                dns_by_domain['dns_queries'].append(extracted)

        # Check for characteristics of DNS tunneling
        high_entropy_domains = [
            d for d in dns_by_domain.get('dns_queries', [])
            if d.get('question_count', 0) > 0
        ]

        if len(high_entropy_domains) > 50:
            findings.append({
                'type': 'dns_tunneling',
                'severity': 'high',
                'description': f'High volume of DNS queries detected: {len(high_entropy_domains)} queries',
                'recommendation': 'Investigate DNS traffic for data exfiltration via DNS tunneling',
            })

        return findings

    def compute_ja3_fingerprint(self, tls_data: Dict) -> str:
        """
        Compute JA3 fingerprint for TLS client identification.

        Args:
            tls_data: TLS handshake data

        Returns:
            JA3 hash string
        """
        version = tls_data.get('version', 771)
        ciphers = tls_data.get('cipher_suites', [])
        extensions = tls_data.get('extensions', [])
        elliptic_curves = tls_data.get('elliptic_curves', [])
        ec_point_formats = tls_data.get('ec_point_formats', [])

        # Build JA3 string
        ja3_str = (
            f"{version},"
            f"{'-'.join(str(c) for c in ciphers)},"
            f"{'-'.join(str(e) for e in extensions)},"
            f"{'-'.join(str(c) for c in elliptic_curves)},"
            f"{'-'.join(str(f) for f in ec_point_formats)}"
        )

        return hashlib.md5(ja3_str.encode()).hexdigest()

    def get_bandwidth_statistics(self) -> Dict:
        """
        Get bandwidth statistics per host and protocol.

        Returns:
            Dictionary of bandwidth statistics
        """
        stats = {
            'per_host': {},
            'per_protocol': dict(self.protocol_stats),
            'total_bytes': sum(self.bandwidth_stats.values()),
            'total_packets': len(self.captured_packets),
        }

        # Aggregate per-host stats
        for key, bytes_count in self.bandwidth_stats.items():
            if '->' in key:
                parts = key.split('->')
                host = parts[0]
                direction = parts[1]
                if host not in stats['per_host']:
                    stats['per_host'][host] = {'in': 0, 'out': 0}
                stats['per_host'][host][direction] = bytes_count

        return stats

    def reconstruct_sessions(self) -> List[Dict]:
        """
        Reconstruct TCP/UDP sessions from captured flows.

        Returns:
            List of reconstructed sessions
        """
        sessions = []
        for flow_id, flow in self.flows.items():
            session = {
                'session_id': flow_id,
                'client': f"{flow.get('src_ip')}:{flow.get('src_port')}",
                'server': f"{flow.get('dst_ip')}:{flow.get('dst_port')}",
                'protocol': flow.get('protocol'),
                'application': flow.get('application_protocol'),
                'packets': flow.get('packet_count', 0),
                'bytes': flow.get('byte_count', 0),
                'state': flow.get('state', 'unknown'),
                'duration': 'unknown',
                'start_time': flow.get('start_time'),
                'end_time': flow.get('last_seen'),
            }
            sessions.append(session)

        return sorted(sessions, key=lambda x: x['bytes'], reverse=True)

    def analyze_dga(self, dns_queries: List[str]) -> List[Dict]:
        """
        Detect Domain Generation Algorithm (DGA) activity.

        Args:
            dns_queries: List of DNS query domain names

        Returns:
            List of potential DGA domains
        """
        dga_suspects = []

        for domain in dns_queries:
            # Calculate domain characteristics
            domain_name = domain.split('.')[0] if '.' in domain else domain

            # High entropy suggests DGA
            entropy = self._calculate_entropy(domain_name)
            consonant_ratio = self._consonant_ratio(domain_name)
            has_numbers = any(c.isdigit() for c in domain_name)
            length = len(domain_name)

            # DGA detection heuristics
            is_dga = (
                (entropy > 3.5 and length > 10) or
                (consonant_ratio > 0.75 and length > 12) or
                (has_numbers and entropy > 3.0 and length > 15)
            )

            if is_dga:
                dga_suspects.append({
                    'domain': domain,
                    'entropy': round(entropy, 3),
                    'length': length,
                    'consonant_ratio': round(consonant_ratio, 3),
                    'has_numbers': has_numbers,
                    'confidence': 'high' if entropy > 4.0 else 'medium',
                })

        return dga_suspects

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        import math
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
            if count > 0
        )
        return entropy

    def _consonant_ratio(self, text: str) -> float:
        """Calculate ratio of consonants to total characters."""
        if not text:
            return 0.0
        consonants = set('bcdfghjklmnpqrstvwxyz')
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return 0.0
        return sum(1 for c in letters if c in consonants) / len(letters)
