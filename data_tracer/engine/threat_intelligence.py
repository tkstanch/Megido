"""
Threat intelligence correlation engine for Data Tracer.
Implements IP reputation checking, IOC scanning, MITRE ATT&CK mapping,
YARA rule matching, and STIX/TAXII support.
"""

import hashlib
import json
import re
import ipaddress
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime


# MITRE ATT&CK technique database (subset)
MITRE_ATTACK_TECHNIQUES = {
    'T1190': {
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'description': 'Adversaries exploit vulnerabilities in internet-facing software',
        'mitigations': ['M1051', 'M1050', 'M1048'],
    },
    'T1059': {
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
        'description': 'Adversaries use command-line interfaces and scripting languages',
        'mitigations': ['M1042', 'M1026'],
    },
    'T1078': {
        'name': 'Valid Accounts',
        'tactic': 'Defense Evasion',
        'description': 'Adversaries use valid accounts to gain initial access',
        'mitigations': ['M1036', 'M1032', 'M1027'],
    },
    'T1110': {
        'name': 'Brute Force',
        'tactic': 'Credential Access',
        'description': 'Adversaries may use brute force techniques to gain access',
        'subtechniques': {
            'T1110.001': 'Password Guessing',
            'T1110.002': 'Password Cracking',
            'T1110.003': 'Password Spraying',
            'T1110.004': 'Credential Stuffing',
        },
        'mitigations': ['M1036', 'M1032'],
    },
    'T1046': {
        'name': 'Network Service Discovery',
        'tactic': 'Discovery',
        'description': 'Adversaries may attempt to get a listing of services running on remote hosts',
        'mitigations': ['M1042', 'M1030'],
    },
    'T1595': {
        'name': 'Active Scanning',
        'tactic': 'Reconnaissance',
        'description': 'Adversaries actively scan victim infrastructure prior to attack',
        'subtechniques': {
            'T1595.001': 'Scanning IP Blocks',
            'T1595.002': 'Vulnerability Scanning',
            'T1595.003': 'Wordlist Scanning',
        },
        'mitigations': ['M1056'],
    },
    'T1133': {
        'name': 'External Remote Services',
        'tactic': 'Initial Access',
        'description': 'Adversaries may leverage external-facing remote services to access networks',
        'mitigations': ['M1035', 'M1032'],
    },
    'T1021': {
        'name': 'Remote Services',
        'tactic': 'Lateral Movement',
        'description': 'Adversaries may use valid accounts to log into a service specifically designed for remote access',
        'subtechniques': {
            'T1021.001': 'Remote Desktop Protocol',
            'T1021.004': 'SSH',
            'T1021.006': 'Windows Remote Management',
        },
        'mitigations': ['M1035', 'M1032'],
    },
    'T1041': {
        'name': 'Exfiltration Over C2 Channel',
        'tactic': 'Exfiltration',
        'description': 'Adversaries may steal data by exfiltrating it over an existing command-and-control channel',
        'mitigations': ['M1057', 'M1031'],
    },
    'T1071': {
        'name': 'Application Layer Protocol',
        'tactic': 'Command and Control',
        'description': 'Adversaries communicate using OSI application layer protocols to avoid detection',
        'subtechniques': {
            'T1071.001': 'Web Protocols',
            'T1071.002': 'File Transfer Protocols',
            'T1071.003': 'Mail Protocols',
            'T1071.004': 'DNS',
        },
        'mitigations': ['M1031', 'M1037'],
    },
}

# Known malicious IP ranges (simplified)
MALICIOUS_IP_RANGES = [
    '185.220.0.0/16',  # Known Tor exit nodes range
    '192.42.116.0/24',  # Tor Project
    '10.0.0.0/8',  # Private (internal for testing)
]

# Known C2 indicators
C2_INDICATORS = {
    'domains': [
        'evil.com', 'malware.xyz', 'c2server.net',
        'botnet-c2.ru', 'apt-c2.cn',
    ],
    'ip_patterns': [
        r'^185\.220\.',  # Tor exit nodes
        r'^77\.247\.110\.',  # Known malicious range
    ],
    'user_agents': [
        'Mozilla/4.0 (compatible; MSIE 6.0',  # Ancient/malware UA
        'Go-http-client/1.1',  # Common malware UA
        'python-requests',  # Script-based attacks
    ],
    'http_paths': [
        '/gate.php', '/panel.php', '/bot.php',
        '/update.php', '/tasks.php', '/upload.php',
    ],
}

# YARA-like rules (Python-based pattern matching)
YARA_RULES = [
    {
        'rule_name': 'MalwareDownloader',
        'description': 'Detects common malware downloader patterns',
        'strings': [b'powershell -enc', b'cmd.exe /c', b'certutil -decode', b'bitsadmin /transfer'],
        'condition': 'any',
        'severity': 'high',
    },
    {
        'rule_name': 'CredentialHarvesting',
        'description': 'Detects credential harvesting indicators',
        'strings': [b'password=', b'passwd=', b'Authorization: Basic', b'api_key='],
        'condition': 'any',
        'severity': 'high',
    },
    {
        'rule_name': 'NetworkRecon',
        'description': 'Detects network reconnaissance patterns',
        'strings': [b'nmap', b'masscan', b'nikto', b'sqlmap', b'dirb'],
        'condition': 'any',
        'severity': 'medium',
    },
    {
        'rule_name': 'ShellcodeIndicator',
        'description': 'Detects potential shellcode patterns',
        'strings': [b'\x90\x90\x90\x90', b'\xcc\xcc\xcc\xcc', b'/bin/sh', b'/bin/bash'],
        'condition': 'any',
        'severity': 'critical',
    },
    {
        'rule_name': 'WebShell',
        'description': 'Detects web shell indicators',
        'strings': [b'eval(base64_decode', b'system($_GET', b'passthru(', b'exec($_POST'],
        'condition': 'any',
        'severity': 'critical',
    },
]

# Geographic threat data
GEO_THREAT_DATA = {
    'CN': {'threat_level': 'high', 'known_apt_groups': ['APT1', 'APT10', 'APT41']},
    'RU': {'threat_level': 'high', 'known_apt_groups': ['APT28', 'APT29', 'Cozy Bear', 'Fancy Bear']},
    'NK': {'threat_level': 'high', 'known_apt_groups': ['Lazarus Group', 'APT38']},
    'IR': {'threat_level': 'high', 'known_apt_groups': ['APT33', 'APT34', 'APT35']},
    'US': {'threat_level': 'medium', 'known_apt_groups': ['Equation Group']},
    'GB': {'threat_level': 'low', 'known_apt_groups': []},
}


class ThreatIntelligenceEngine:
    """
    Threat intelligence correlation engine implementing IP reputation,
    IOC scanning, MITRE ATT&CK mapping, and STIX support.
    """

    def __init__(self):
        """Initialize the threat intelligence engine."""
        self.ioc_matches: List[Dict] = []
        self.mitre_techniques = MITRE_ATTACK_TECHNIQUES
        self.yara_rules = YARA_RULES
        self.threat_cache: Dict = {}

    def check_ip_reputation(self, ip: str) -> Dict:
        """
        Check IP address reputation against threat intelligence feeds.

        Args:
            ip: IP address to check

        Returns:
            IP reputation assessment
        """
        result = {
            'ip': ip,
            'reputation': 'unknown',
            'threat_score': 0,
            'categories': [],
            'threat_feeds': [],
            'is_tor': False,
            'is_vpn': False,
            'is_proxy': False,
            'is_datacenter': False,
            'geolocation': {},
            'asn': '',
            'abuseipdb_score': 0,
            'virustotal_detections': 0,
            'first_seen': None,
            'last_seen': None,
        }

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check if private/reserved
            if ip_obj.is_private:
                result['reputation'] = 'private'
                result['categories'].append('private_ip')
                return result

            if ip_obj.is_loopback:
                result['reputation'] = 'loopback'
                return result

            # Check against malicious ranges
            for malicious_range in MALICIOUS_IP_RANGES:
                try:
                    network = ipaddress.ip_network(malicious_range, strict=False)
                    if ip_obj in network:
                        result['threat_score'] = max(result['threat_score'], 75)
                        result['categories'].append('known_malicious_range')
                        result['reputation'] = 'malicious'
                        result['threat_feeds'].append({
                            'feed': 'Internal Threat Intel',
                            'category': 'malicious_ip_range',
                            'confidence': 0.8,
                        })
                except ValueError:
                    pass

            # Check C2 IP patterns
            ip_str = str(ip)
            for pattern in C2_INDICATORS.get('ip_patterns', []):
                if re.match(pattern, ip_str):
                    result['threat_score'] = max(result['threat_score'], 90)
                    result['categories'].append('c2_server')
                    result['reputation'] = 'malicious'
                    result['threat_feeds'].append({
                        'feed': 'C2 Intelligence Feed',
                        'category': 'command_and_control',
                        'confidence': 0.9,
                    })

            # Simulate threat feed checks
            # In production, would query actual APIs (AbuseIPDB, VirusTotal, etc.)
            result['abuseipdb_score'] = 0  # Simulated
            result['virustotal_detections'] = 0  # Simulated

            if result['threat_score'] == 0:
                result['reputation'] = 'clean'

        except ValueError:
            result['reputation'] = 'invalid'
            result['error'] = f'Invalid IP address: {ip}'

        return result

    def scan_iocs(self, data: Dict) -> List[Dict]:
        """
        Scan data for Indicators of Compromise.

        Args:
            data: Dictionary containing IPs, domains, hashes, URLs to check

        Returns:
            List of IOC matches
        """
        matches = []

        # Check IPs
        for ip in data.get('ips', []):
            rep = self.check_ip_reputation(ip)
            if rep.get('reputation') == 'malicious':
                matches.append({
                    'type': 'ip',
                    'value': ip,
                    'category': 'malicious_ip',
                    'threat_score': rep['threat_score'],
                    'details': rep,
                })

        # Check domains
        for domain in data.get('domains', []):
            domain_check = self.check_domain_reputation(domain)
            if domain_check.get('malicious'):
                matches.append({
                    'type': 'domain',
                    'value': domain,
                    'category': 'malicious_domain',
                    'threat_score': domain_check.get('threat_score', 50),
                    'details': domain_check,
                })

        # Check file hashes
        for file_hash in data.get('hashes', []):
            hash_check = self.check_hash_reputation(file_hash)
            if hash_check.get('malicious'):
                matches.append({
                    'type': 'hash',
                    'value': file_hash,
                    'category': 'malware_hash',
                    'threat_score': 95,
                    'details': hash_check,
                })

        # Check URLs
        for url in data.get('urls', []):
            url_check = self.check_url_reputation(url)
            if url_check.get('malicious'):
                matches.append({
                    'type': 'url',
                    'value': url,
                    'category': 'malicious_url',
                    'threat_score': url_check.get('threat_score', 70),
                    'details': url_check,
                })

        self.ioc_matches.extend(matches)
        return matches

    def check_domain_reputation(self, domain: str) -> Dict:
        """Check domain reputation."""
        result = {
            'domain': domain,
            'malicious': False,
            'threat_score': 0,
            'categories': [],
        }

        # Check against known C2 domains
        if domain.lower() in C2_INDICATORS.get('domains', []):
            result['malicious'] = True
            result['threat_score'] = 95
            result['categories'].append('c2_domain')

        # Check for suspicious TLDs
        suspicious_tlds = ['.ru', '.cn', '.tk', '.xyz', '.pw', '.cc', '.su']
        for tld in suspicious_tlds:
            if domain.lower().endswith(tld):
                result['threat_score'] = max(result['threat_score'], 30)
                result['categories'].append('suspicious_tld')

        # Check for DGA-like patterns
        subdomain = domain.split('.')[0]
        if len(subdomain) > 15 and not any(c.isspace() for c in subdomain):
            entropy = self._calculate_entropy(subdomain)
            if entropy > 3.5:
                result['threat_score'] = max(result['threat_score'], 60)
                result['categories'].append('dga_like_domain')

        if result['threat_score'] > 50:
            result['malicious'] = True

        return result

    def check_hash_reputation(self, file_hash: str) -> Dict:
        """Check file hash reputation."""
        # In production, would query VirusTotal, MalwareBazaar, etc.
        known_bad_hashes = {
            'd41d8cd98f00b204e9800998ecf8427e': 'Empty file MD5',
        }

        return {
            'hash': file_hash,
            'malicious': file_hash in known_bad_hashes,
            'malware_family': known_bad_hashes.get(file_hash, None),
            'detections': 0,
        }

    def check_url_reputation(self, url: str) -> Dict:
        """Check URL reputation."""
        result = {
            'url': url,
            'malicious': False,
            'threat_score': 0,
            'categories': [],
        }

        # Check for C2 paths
        for path in C2_INDICATORS.get('http_paths', []):
            if path in url:
                result['malicious'] = True
                result['threat_score'] = 85
                result['categories'].append('c2_endpoint')
                break

        return result

    def map_to_mitre_attack(self, findings: List[Dict]) -> List[Dict]:
        """
        Map security findings to MITRE ATT&CK framework techniques.

        Args:
            findings: List of security findings to map

        Returns:
            List of MITRE ATT&CK technique mappings
        """
        mappings = []

        for finding in findings:
            finding_type = finding.get('type', '').lower()
            category = finding.get('category', '').lower()

            # Map finding types to techniques
            technique_mappings = {
                'port_scan': 'T1595',
                'active_scan': 'T1595',
                'vulnerability_scan': 'T1595',
                'brute_force': 'T1110',
                'default_credentials': 'T1078',
                'ssh_access': 'T1021',
                'rdp_access': 'T1021',
                'web_exploit': 'T1190',
                'sqli': 'T1190',
                'command_injection': 'T1059',
                'c2_communication': 'T1071',
                'data_exfiltration': 'T1041',
            }

            technique_id = None
            for key, tid in technique_mappings.items():
                if key in finding_type or key in category:
                    technique_id = tid
                    break

            if technique_id and technique_id in self.mitre_techniques:
                technique = self.mitre_techniques[technique_id]
                mappings.append({
                    'finding': finding,
                    'technique_id': technique_id,
                    'technique_name': technique['name'],
                    'tactic': technique['tactic'],
                    'description': technique['description'],
                    'mitigations': technique.get('mitigations', []),
                    'subtechniques': technique.get('subtechniques', {}),
                })

        return mappings

    def run_yara_scan(self, data: bytes) -> List[Dict]:
        """
        Run YARA-like rules against data.

        Args:
            data: Binary data to scan

        Returns:
            List of YARA rule matches
        """
        matches = []

        if not data:
            return matches

        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')

        for rule in self.yara_rules:
            rule_strings = rule.get('strings', [])
            condition = rule.get('condition', 'any')

            matched_strings = []
            for pattern in rule_strings:
                if pattern in data:
                    matched_strings.append(pattern.decode('utf-8', errors='replace'))

            matched = False
            if condition == 'any' and matched_strings:
                matched = True
            elif condition == 'all' and len(matched_strings) == len(rule_strings):
                matched = True

            if matched:
                matches.append({
                    'rule': rule['rule_name'],
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'matched_strings': matched_strings,
                    'matched_at': datetime.utcnow().isoformat(),
                })

        return matches

    def export_stix(self, findings: List[Dict]) -> Dict:
        """
        Export threat intelligence in STIX 2.1 format.

        Args:
            findings: List of threat findings to export

        Returns:
            STIX 2.1 bundle
        """
        stix_bundle = {
            'type': 'bundle',
            'id': f'bundle--{hashlib.md5(json.dumps(findings, default=str).encode()).hexdigest()}',
            'spec_version': '2.1',
            'objects': [],
        }

        for finding in findings:
            if finding.get('type') == 'ip':
                stix_obj = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': f'indicator--{hashlib.md5(str(finding).encode()).hexdigest()}',
                    'created': datetime.utcnow().isoformat() + 'Z',
                    'modified': datetime.utcnow().isoformat() + 'Z',
                    'name': f"Malicious IP: {finding.get('value')}",
                    'pattern': f"[ipv4-addr:value = '{finding.get('value')}']",
                    'pattern_type': 'stix',
                    'valid_from': datetime.utcnow().isoformat() + 'Z',
                    'indicator_types': ['malicious-activity'],
                    'confidence': finding.get('threat_score', 50),
                }
                stix_bundle['objects'].append(stix_obj)

            elif finding.get('type') == 'domain':
                stix_obj = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': f'indicator--{hashlib.md5(str(finding).encode()).hexdigest()}',
                    'created': datetime.utcnow().isoformat() + 'Z',
                    'modified': datetime.utcnow().isoformat() + 'Z',
                    'name': f"Malicious Domain: {finding.get('value')}",
                    'pattern': f"[domain-name:value = '{finding.get('value')}']",
                    'pattern_type': 'stix',
                    'valid_from': datetime.utcnow().isoformat() + 'Z',
                    'indicator_types': ['malicious-activity'],
                    'confidence': finding.get('threat_score', 50),
                }
                stix_bundle['objects'].append(stix_obj)

        return stix_bundle

    def get_geo_threat_context(self, country_code: str) -> Dict:
        """
        Get geographic threat context for a country.

        Args:
            country_code: ISO 3166-1 alpha-2 country code

        Returns:
            Geographic threat context
        """
        geo_data = GEO_THREAT_DATA.get(country_code.upper(), {
            'threat_level': 'unknown',
            'known_apt_groups': [],
        })

        return {
            'country_code': country_code,
            'threat_level': geo_data['threat_level'],
            'known_apt_groups': geo_data['known_apt_groups'],
            'apt_count': len(geo_data['known_apt_groups']),
        }

    def correlate_findings(self, findings: List[Dict]) -> Dict:
        """
        Correlate multiple findings to identify attack campaigns.

        Args:
            findings: List of security findings to correlate

        Returns:
            Correlation analysis with campaign indicators
        """
        correlation = {
            'total_findings': len(findings),
            'unique_source_ips': set(),
            'unique_techniques': set(),
            'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'campaign_indicators': [],
            'attack_chain': [],
            'mitre_coverage': [],
        }

        # Analyze findings
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in correlation['severity_breakdown']:
                correlation['severity_breakdown'][severity] += 1

            src_ip = finding.get('source_ip', finding.get('ip', ''))
            if src_ip:
                correlation['unique_source_ips'].add(src_ip)

        # Convert sets to lists for JSON serialization
        correlation['unique_source_ips'] = list(correlation['unique_source_ips'])

        # Map to MITRE ATT&CK
        correlation['mitre_coverage'] = self.map_to_mitre_attack(findings)
        correlation['unique_techniques'] = list(set(
            m['technique_id'] for m in correlation['mitre_coverage']
        ))

        # Identify potential attack chain
        tactics_order = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
                         'Privilege Escalation', 'Defense Evasion', 'Credential Access',
                         'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration',
                         'Command and Control']

        detected_tactics = set(m['tactic'] for m in correlation['mitre_coverage'])
        correlation['attack_chain'] = [t for t in tactics_order if t in detected_tactics]

        return correlation

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        import math
        from collections import defaultdict
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
            if count > 0
        )
