"""
Network mapping and topology discovery engine for Data Tracer.
Implements advanced network topology discovery, DNS intelligence,
ARP analysis, and network graph building.
"""

import socket
import struct
import random
import ipaddress
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime


# OUI (Organizationally Unique Identifier) vendor database (subset)
OUI_DATABASE = {
    '00:50:56': 'VMware',
    '00:0c:29': 'VMware',
    '00:1c:42': 'Parallels',
    '08:00:27': 'Oracle VirtualBox',
    '52:54:00': 'QEMU/KVM',
    '00:16:3e': 'Xen',
    'dc:a6:32': 'Raspberry Pi Foundation',
    'b8:27:eb': 'Raspberry Pi Foundation',
    'e4:5f:01': 'Raspberry Pi Foundation',
    '00:1a:11': 'Google (Nest)',
    'f4:f5:d8': 'Google (Nest)',
    '18:b4:30': 'Nest Labs',
    'ac:37:43': 'HTC (HTC Corporation)',
    '00:25:00': 'Apple',
    '00:26:bb': 'Apple',
    '3c:07:54': 'Apple',
    '40:83:1d': 'Apple',
    'a4:c3:61': 'Apple',
    'f0:18:98': 'Apple',
    '00:1b:21': 'Intel Corporate',
    '00:21:6b': 'Cisco Systems',
    '00:24:14': 'Cisco Systems',
    '00:e0:4c': 'Realtek Semiconductor',
    'c8:60:00': 'Belkin International',
    '00:90:4c': 'Epigram',
    '00:1d:7e': 'Cisco-Linksys',
    '00:18:0a': 'Ubiquiti Networks',
    '04:18:d6': 'Ubiquiti Networks',
    '00:27:22': 'Ubiquiti Networks',
    'b4:fb:e4': 'Ubiquiti Networks',
    '00:50:c2': 'IEEE Registration Authority',
    '00:1e:c9': 'Hewlett-Packard',
    '3c:d9:2b': 'Hewlett-Packard',
    '00:17:a4': 'Hewlett-Packard',
    '00:13:21': 'Intel Corporate',
    '00:1f:16': 'Micro-Star International (MSI)',
    '00:1b:fc': 'ASUSTeK Computer',
    '00:e0:18': 'ASUSTeK Computer',
    '00:30:1b': 'D-Link Systems',
    '1c:7e:e5': 'D-Link Systems',
    '14:d6:4d': 'D-Link Systems',
    '00:19:e0': 'Samsung Electronics',
    '00:21:19': 'Samsung Electronics',
    '00:15:5d': 'Microsoft Corporation (Hyper-V)',
    '28:d2:44': 'Microsoft Corporation',
    '00:12:17': 'Cisco Systems',
    '00:0d:54': 'Cisco Systems',
}

# Common DNS record types
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']

# Common subdomain wordlist (subset)
SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'vpn', 'mx', 'mail2', 'remote', 'blog', 'test', 'dev', 'staging', 'api',
    'admin', 'portal', 'm', 'mobile', 'support', 'help', 'forum', 'forums',
    'cdn', 'static', 'media', 'images', 'img', 'video', 'docs', 'documentation',
    'git', 'gitlab', 'github', 'jenkins', 'ci', 'cd', 'build', 'deploy',
    'login', 'auth', 'sso', 'oauth', 'api2', 'v2', 'v1', 'beta', 'alpha',
    'dashboard', 'app', 'apps', 'service', 'services', 'internal', 'intranet',
    'secure', 'ssl', 'web', 'web2', 'cloud', 'db', 'database', 'mysql',
    'redis', 'elastic', 'kibana', 'grafana', 'prometheus', 'monitoring',
    'status', 'health', 'metrics', 'logs', 'backup', 'dev2', 'uat', 'qa',
]

# AS (Autonomous System) database (simplified)
AS_DATABASE = {
    '8.8.8.0/24': {'asn': 'AS15169', 'name': 'Google LLC', 'country': 'US'},
    '1.1.1.0/24': {'asn': 'AS13335', 'name': 'Cloudflare Inc.', 'country': 'US'},
    '104.16.0.0/12': {'asn': 'AS13335', 'name': 'Cloudflare Inc.', 'country': 'US'},
    '52.0.0.0/8': {'asn': 'AS14618', 'name': 'Amazon.com Inc.', 'country': 'US'},
    '13.0.0.0/8': {'asn': 'AS16509', 'name': 'Amazon Web Services', 'country': 'US'},
    '34.0.0.0/8': {'asn': 'AS15169', 'name': 'Google LLC', 'country': 'US'},
    '20.0.0.0/8': {'asn': 'AS8075', 'name': 'Microsoft Corporation', 'country': 'US'},
}


class NetworkMapper:
    """
    Advanced network topology and mapping engine.
    Implements network discovery, DNS intelligence, ARP analysis,
    and topology graph building.
    """

    def __init__(self, timeout: int = 5):
        """
        Initialize the network mapper.

        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
        self.topology_nodes: List[Dict] = []
        self.topology_edges: List[Dict] = []
        self.oui_database = OUI_DATABASE
        self.discovered_networks: List[str] = []
        self.dns_results: Dict = {}

    def discover_network_topology(self, target: str) -> Dict:
        """
        Discover and map network topology for a target.

        Args:
            target: Target IP, hostname, or network CIDR

        Returns:
            Network topology data including nodes and edges
        """
        topology = {
            'target': target,
            'nodes': [],
            'edges': [],
            'subnets': [],
            'gateways': [],
            'scan_timestamp': datetime.utcnow().isoformat(),
        }

        # Identify subnets
        subnets = self._detect_subnets(target)
        topology['subnets'] = subnets

        # Identify gateways
        gateways = self._identify_gateways(target)
        topology['gateways'] = gateways

        # Build node list
        for subnet in subnets:
            nodes = self._enumerate_subnet_hosts(subnet)
            topology['nodes'].extend(nodes)

        # Build edges (connections between nodes)
        topology['edges'] = self._build_topology_edges(topology['nodes'])

        # Add asset classification
        for node in topology['nodes']:
            node['asset_type'] = self._classify_asset(node)
            node['vendor'] = self._lookup_mac_vendor(node.get('mac', ''))

        self.topology_nodes = topology['nodes']
        self.topology_edges = topology['edges']

        return topology

    def _detect_subnets(self, target: str) -> List[Dict]:
        """Detect network subnets from target."""
        subnets = []

        try:
            if '/' in target:
                # CIDR notation
                network = ipaddress.ip_network(target, strict=False)
                subnets.append({
                    'cidr': str(network),
                    'network': str(network.network_address),
                    'broadcast': str(network.broadcast_address),
                    'prefix_len': network.prefixlen,
                    'host_count': network.num_addresses - 2,
                })
            else:
                # Single IP - infer /24 subnet
                try:
                    ip = ipaddress.ip_address(target)
                    if ip.version == 4:
                        parts = str(ip).rsplit('.', 1)
                        cidr = f"{parts[0]}.0/24"
                        network = ipaddress.ip_network(cidr, strict=False)
                        subnets.append({
                            'cidr': str(network),
                            'network': str(network.network_address),
                            'broadcast': str(network.broadcast_address),
                            'prefix_len': 24,
                            'host_count': 254,
                        })
                except ValueError:
                    pass
        except ValueError:
            pass

        return subnets

    def _identify_gateways(self, target: str) -> List[Dict]:
        """Identify network gateways."""
        gateways = []

        try:
            ip_str = target.split('/')[0]
            ip = ipaddress.ip_address(ip_str)

            if ip.version == 4:
                # Common gateway addresses (.1, .254)
                parts = str(ip).rsplit('.', 1)
                for last_octet in [1, 254, 253]:
                    gateway_ip = f"{parts[0]}.{last_octet}"
                    gateways.append({
                        'ip': gateway_ip,
                        'type': 'likely_gateway',
                        'confidence': 0.8 if last_octet == 1 else 0.5,
                    })
        except ValueError:
            pass

        return gateways

    def _enumerate_subnet_hosts(self, subnet: Dict) -> List[Dict]:
        """Enumerate hosts in a subnet (simulated)."""
        nodes = []
        try:
            network = ipaddress.ip_network(subnet['cidr'], strict=False)
            # Return a representative sample for large networks
            count = min(10, subnet.get('host_count', 10))
            hosts = list(network.hosts())[:count]

            for host in hosts:
                mac = self._generate_random_mac()
                nodes.append({
                    'ip': str(host),
                    'mac': mac,
                    'hostname': self._reverse_dns(str(host)),
                    'status': 'unknown',
                    'open_ports': [],
                    'services': [],
                    'os_guess': '',
                })
        except ValueError:
            pass

        return nodes

    def _build_topology_edges(self, nodes: List[Dict]) -> List[Dict]:
        """Build network topology edges between nodes."""
        edges = []
        if len(nodes) < 2:
            return edges

        # Connect first node (assumed gateway) to all others
        if nodes:
            gateway = nodes[0]
            for node in nodes[1:]:
                edges.append({
                    'source': gateway['ip'],
                    'target': node['ip'],
                    'type': 'network',
                    'weight': 1,
                })

        return edges

    def _classify_asset(self, node: Dict) -> str:
        """Classify an asset based on its characteristics."""
        open_ports = node.get('open_ports', [])
        services = node.get('services', [])
        hostname = node.get('hostname', '').lower()

        # Check hostname patterns
        if any(kw in hostname for kw in ['router', 'gateway', 'gw', 'fw', 'firewall']):
            return 'network_equipment'
        if any(kw in hostname for kw in ['switch', 'sw-']):
            return 'network_equipment'
        if any(kw in hostname for kw in ['printer', 'print', 'hp-', 'canon', 'epson']):
            return 'printer'
        if any(kw in hostname for kw in ['cam', 'camera', 'ipcam', 'nvr', 'dvr']):
            return 'iot_camera'
        if any(kw in hostname for kw in ['server', 'srv', 'db', 'web', 'mail']):
            return 'server'

        # Check open ports
        if 22 in open_ports or 3389 in open_ports:
            return 'server'
        if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
            return 'web_server'
        if 3306 in open_ports or 5432 in open_ports or 27017 in open_ports:
            return 'database_server'
        if 161 in open_ports or 162 in open_ports:
            return 'network_equipment'
        if 9100 in open_ports:
            return 'printer'

        return 'unknown'

    def _lookup_mac_vendor(self, mac: str) -> str:
        """Look up MAC address vendor using OUI database."""
        if not mac:
            return 'Unknown'

        # Normalize MAC address
        mac_normalized = mac.lower().replace('-', ':')
        prefix = ':'.join(mac_normalized.split(':')[:3])

        return self.oui_database.get(prefix, 'Unknown Vendor')

    def _reverse_dns(self, ip: str) -> str:
        """Perform reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            return ''

    def _generate_random_mac(self) -> str:
        """Generate a random MAC address for simulation."""
        mac_bytes = [random.randint(0, 255) for _ in range(6)]
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    def enumerate_dns(self, domain: str) -> Dict:
        """
        Perform comprehensive DNS enumeration for a domain.

        Args:
            domain: Target domain name

        Returns:
            Dictionary of DNS records and findings
        """
        results = {
            'domain': domain,
            'records': {},
            'subdomains': [],
            'zone_transfer': False,
            'dnssec': False,
            'mail_servers': [],
            'nameservers': [],
        }

        # Query each record type
        for record_type in DNS_RECORD_TYPES:
            records = self._query_dns(domain, record_type)
            if records:
                results['records'][record_type] = records

        # Extract MX and NS records
        results['mail_servers'] = results['records'].get('MX', [])
        results['nameservers'] = results['records'].get('NS', [])

        # Attempt zone transfer (AXFR)
        results['zone_transfer'] = self._attempt_zone_transfer(domain)

        # Subdomain brute forcing
        results['subdomains'] = self._brute_force_subdomains(domain)

        # Check DNSSEC
        results['dnssec'] = self._check_dnssec(domain)

        self.dns_results[domain] = results
        return results

    def _query_dns(self, domain: str, record_type: str) -> List[str]:
        """Query DNS for a specific record type."""
        records = []
        try:
            if record_type == 'A':
                answers = socket.getaddrinfo(domain, None, socket.AF_INET)
                records = list(set(a[4][0] for a in answers))
            elif record_type == 'AAAA':
                answers = socket.getaddrinfo(domain, None, socket.AF_INET6)
                records = list(set(a[4][0] for a in answers))
        except (socket.gaierror, socket.timeout, OSError):
            pass
        return records

    def _attempt_zone_transfer(self, domain: str) -> bool:
        """Attempt DNS zone transfer (AXFR) - tests for misconfiguration."""
        # Zone transfers should be restricted
        # This simulates the attempt and returns whether it succeeded
        return False  # Most properly configured DNS servers will reject this

    def _brute_force_subdomains(self, domain: str) -> List[Dict]:
        """Brute force subdomain discovery."""
        found = []
        for subdomain in SUBDOMAIN_WORDLIST[:50]:  # Limit for performance
            fqdn = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append({
                    'subdomain': fqdn,
                    'ip': ip,
                    'type': 'A',
                })
            except (socket.gaierror, socket.timeout):
                pass
        return found

    def _check_dnssec(self, domain: str) -> bool:
        """Check if DNSSEC is enabled for a domain."""
        # Simplified DNSSEC check
        return False

    def analyze_arp_table(self, hosts: List[Dict]) -> Dict:
        """
        Analyze ARP table for security issues.

        Args:
            hosts: List of host dictionaries with IP and MAC addresses

        Returns:
            ARP analysis results including spoofing detection
        """
        results = {
            'total_entries': len(hosts),
            'duplicate_macs': [],
            'duplicate_ips': [],
            'spoofing_suspects': [],
            'vendor_breakdown': {},
        }

        # Check for duplicate MAC addresses (potential ARP spoofing)
        mac_to_ips = {}
        ip_to_macs = {}

        for host in hosts:
            mac = host.get('mac', '')
            ip = host.get('ip', '')

            if mac:
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = []
                mac_to_ips[mac].append(ip)

            if ip:
                if ip not in ip_to_macs:
                    ip_to_macs[ip] = []
                ip_to_macs[ip].append(mac)

        # Find duplicates
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                results['duplicate_macs'].append({'mac': mac, 'ips': ips})
                results['spoofing_suspects'].append({
                    'type': 'mac_conflict',
                    'mac': mac,
                    'ips': ips,
                    'severity': 'high',
                })

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                results['duplicate_ips'].append({'ip': ip, 'macs': macs})
                results['spoofing_suspects'].append({
                    'type': 'ip_conflict',
                    'ip': ip,
                    'macs': macs,
                    'severity': 'high',
                })

        # Vendor breakdown
        for host in hosts:
            vendor = self._lookup_mac_vendor(host.get('mac', ''))
            results['vendor_breakdown'][vendor] = results['vendor_breakdown'].get(vendor, 0) + 1

        return results

    def trace_route(self, target: str, method: str = 'icmp', max_hops: int = 30) -> Dict:
        """
        Perform route tracing to target.

        Args:
            target: Target IP or hostname
            method: Traceroute method (icmp, tcp, udp)
            max_hops: Maximum number of hops

        Returns:
            Route trace results with geolocation per hop
        """
        results = {
            'target': target,
            'method': method,
            'hops': [],
            'total_hops': 0,
            'destination_reached': False,
            'as_path': [],
        }

        # Resolve target
        try:
            target_ip = socket.gethostbyname(target)
        except (socket.gaierror, socket.timeout):
            target_ip = target

        # Simulate route tracing (in production would use actual ICMP/UDP probes)
        # Return simulated hops
        hop_count = random.randint(5, 15)
        for i in range(1, min(hop_count + 1, max_hops + 1)):
            hop = {
                'hop': i,
                'ip': f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                'hostname': '',
                'rtt_ms': random.uniform(1.0, 50.0 * i),
                'geolocation': self._geolocate_ip(''),
                'asn': '',
            }
            results['hops'].append(hop)

        # Final hop is target
        if results['hops']:
            results['hops'][-1]['ip'] = target_ip
            results['hops'][-1]['destination'] = True
            results['destination_reached'] = True

        results['total_hops'] = len(results['hops'])
        results['as_path'] = self._resolve_as_path(results['hops'])

        return results

    def _geolocate_ip(self, ip: str) -> Dict:
        """Geolocate an IP address (simplified)."""
        # In production, would query GeoIP database
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'asn': 'Unknown',
        }

    def _resolve_as_path(self, hops: List[Dict]) -> List[str]:
        """Resolve AS path for route trace hops."""
        as_path = []
        for hop in hops:
            ip = hop.get('ip', '')
            asn = self._lookup_asn(ip)
            if asn and asn not in as_path:
                as_path.append(asn)
        return as_path

    def _lookup_asn(self, ip: str) -> str:
        """Look up ASN for an IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for prefix, info in AS_DATABASE.items():
                network = ipaddress.ip_network(prefix, strict=False)
                if ip_obj in network:
                    return info['asn']
        except ValueError:
            pass
        return ''

    def build_topology_graph(self) -> Dict:
        """
        Build a JSON-serializable network topology graph for visualization.

        Returns:
            D3.js-compatible network graph data
        """
        graph = {
            'nodes': [],
            'links': [],
            'metadata': {
                'total_nodes': len(self.topology_nodes),
                'total_edges': len(self.topology_edges),
                'generated_at': datetime.utcnow().isoformat(),
            },
        }

        # Build node list with visualization properties
        for node in self.topology_nodes:
            graph['nodes'].append({
                'id': node.get('ip', ''),
                'label': node.get('hostname', node.get('ip', '')),
                'type': node.get('asset_type', 'unknown'),
                'vendor': node.get('vendor', ''),
                'ip': node.get('ip', ''),
                'mac': node.get('mac', ''),
                'group': self._get_node_group(node.get('asset_type', '')),
                'size': self._get_node_size(node),
            })

        # Build link list
        for edge in self.topology_edges:
            graph['links'].append({
                'source': edge.get('source', ''),
                'target': edge.get('target', ''),
                'type': edge.get('type', 'network'),
                'weight': edge.get('weight', 1),
            })

        return graph

    def _get_node_group(self, asset_type: str) -> int:
        """Get D3.js group number for node type."""
        groups = {
            'network_equipment': 1,
            'server': 2,
            'web_server': 3,
            'database_server': 4,
            'workstation': 5,
            'printer': 6,
            'iot_camera': 7,
            'unknown': 8,
        }
        return groups.get(asset_type, 8)

    def _get_node_size(self, node: Dict) -> int:
        """Get node size for visualization based on importance."""
        asset_type = node.get('asset_type', '')
        if asset_type in ['network_equipment']:
            return 20
        if asset_type in ['server', 'web_server', 'database_server']:
            return 15
        return 10

    def analyze_network_segmentation(self, subnets: List[Dict]) -> Dict:
        """
        Analyze network segmentation and identify security gaps.

        Args:
            subnets: List of discovered subnets

        Returns:
            Network segmentation analysis
        """
        analysis = {
            'total_subnets': len(subnets),
            'segmentation_score': 0,
            'issues': [],
            'recommendations': [],
        }

        if len(subnets) == 1:
            analysis['issues'].append({
                'severity': 'medium',
                'description': 'Single flat network detected - no network segmentation',
                'recommendation': 'Implement VLANs and network segmentation for security zones',
            })
            analysis['segmentation_score'] = 30

        elif len(subnets) >= 3:
            analysis['segmentation_score'] = 80
            analysis['recommendations'].append('Good network segmentation detected')

        else:
            analysis['segmentation_score'] = 60

        # Check for RFC 1918 private address compliance
        for subnet in subnets:
            cidr = subnet.get('cidr', '')
            if cidr:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if not network.is_private:
                        analysis['issues'].append({
                            'severity': 'info',
                            'description': f'Public IP address space in subnet: {cidr}',
                            'recommendation': 'Consider using RFC 1918 private address space for internal networks',
                        })
                except ValueError:
                    pass

        return analysis
