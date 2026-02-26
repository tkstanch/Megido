"""Network forensics utilities."""

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def analyze_pcap(file_path: str) -> dict:
    """Analyze a PCAP file."""
    result = {
        'file_path': file_path,
        'scapy_available': SCAPY_AVAILABLE,
        'packet_count': 0,
        'connections': [],
        'dns_queries': [],
        'http_sessions': [],
        'iocs': [],
        'error': None,
    }
    if not SCAPY_AVAILABLE:
        result['error'] = 'scapy not installed - install for PCAP analysis'
        return result
    try:
        packets = rdpcap(file_path)
        result['packet_count'] = len(packets)
        result['connections'] = extract_connections(packets)
        result['dns_queries'] = extract_dns_queries(packets)
        result['http_sessions'] = extract_http_sessions(packets)
        result['iocs'] = extract_network_iocs(result)
    except Exception as e:
        result['error'] = str(e)
    return result


def extract_connections(packets) -> list:
    """Extract TCP/UDP connections from packets."""
    conns = {}
    try:
        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = 'tcp' if TCP in pkt else ('udp' if UDP in pkt else 'other')
                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                key = (src, sport, dst, dport, proto)
                if key not in conns:
                    conns[key] = {'src_ip': src, 'src_port': sport, 'dst_ip': dst,
                                  'dst_port': dport, 'protocol': proto, 'packets': 0}
                conns[key]['packets'] += 1
    except Exception:
        pass
    return list(conns.values())[:200]


def extract_dns_queries(packets) -> list:
    """Extract DNS queries from packets."""
    queries = []
    try:
        for pkt in packets:
            if DNS in pkt and DNSQR in pkt:
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode('utf-8', errors='replace').rstrip('.')
                queries.append({'query': qname, 'type': pkt[DNSQR].qtype})
                if len(queries) >= 500:
                    break
    except Exception:
        pass
    return queries


def extract_http_sessions(packets) -> list:
    """Extract HTTP sessions from packets."""
    sessions = []
    try:
        for pkt in packets:
            if hasattr(pkt, 'haslayer') and pkt.haslayer('HTTPRequest'):
                try:
                    http = pkt['HTTPRequest']
                    sessions.append({
                        'method': http.Method.decode() if http.Method else '',
                        'host': http.Host.decode() if http.Host else '',
                        'path': http.Path.decode() if http.Path else '',
                    })
                except Exception:
                    continue
                if len(sessions) >= 200:
                    break
    except Exception:
        pass
    return sessions


def extract_network_iocs(pcap_results: dict) -> list:
    """Extract IOCs from PCAP analysis results."""
    iocs = []
    for conn in pcap_results.get('connections', []):
        dst = conn.get('dst_ip', '')
        if dst and dst not in ('0.0.0.0', '127.0.0.1', '255.255.255.255'):
            iocs.append({'type': 'ipv4', 'value': dst})
    for query in pcap_results.get('dns_queries', []):
        q = query.get('query', '')
        if q:
            iocs.append({'type': 'domain', 'value': q})
    return iocs
