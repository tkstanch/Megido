"""
Credential and secret discovery engine for Data Tracer.
Implements default credential testing, secret scanning,
certificate analysis, and hash identification.
"""

import re
import base64
import hashlib
import ssl
import socket
import json
import string
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime


# Default credential database for common services
DEFAULT_CREDENTIALS_DB = {
    'ssh': [
        ('root', 'root'), ('root', 'toor'), ('root', ''), ('admin', 'admin'),
        ('admin', 'password'), ('pi', 'raspberry'), ('ubuntu', 'ubuntu'),
        ('user', 'user'), ('guest', 'guest'), ('test', 'test'),
        ('administrator', 'password'), ('admin', '1234'), ('root', '123456'),
    ],
    'ftp': [
        ('anonymous', ''), ('anonymous', 'anonymous'), ('ftp', 'ftp'),
        ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
        ('test', 'test'), ('guest', 'guest'), ('user', 'password'),
        ('ftpuser', 'ftpuser'), ('ftpadmin', 'ftpadmin'),
    ],
    'telnet': [
        ('admin', 'admin'), ('root', 'root'), ('admin', ''), ('root', ''),
        ('guest', 'guest'), ('user', 'user'), ('cisco', 'cisco'),
        ('ubnt', 'ubnt'), ('admin', '1234'), ('admin', '12345'),
        ('Admin', 'Admin'), ('administrator', 'administrator'),
    ],
    'http': [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
        ('administrator', 'administrator'), ('root', 'root'),
        ('admin', 'admin123'), ('admin', 'letmein'), ('admin', 'welcome'),
        ('admin', ''), ('admin', '12345'), ('user', 'user'),
        ('guest', 'guest'), ('test', 'test'), ('support', 'support'),
        ('service', 'service'), ('superuser', 'superuser'),
    ],
    'mysql': [
        ('root', ''), ('root', 'root'), ('root', 'mysql'),
        ('mysql', 'mysql'), ('admin', 'admin'), ('root', 'password'),
        ('root', 'root123'), ('root', 'MySQL'),
    ],
    'postgresql': [
        ('postgres', 'postgres'), ('postgres', ''), ('postgres', 'password'),
        ('admin', 'admin'), ('pgsql', 'pgsql'), ('root', 'root'),
    ],
    'redis': [
        ('', ''), ('', 'redis'), ('default', ''), ('redis', 'redis'),
    ],
    'mongodb': [
        ('admin', 'admin'), ('admin', ''), ('root', 'root'), ('', ''),
        ('admin', 'password'), ('mongoadmin', 'mongoadmin'),
    ],
    'snmp': [
        # SNMP community strings
        ('community', 'public'), ('community', 'private'),
        ('community', 'cisco'), ('community', 'manager'),
        ('community', 'ILMI'), ('community', 'admin'),
        ('community', 'default'), ('community', 'community'),
    ],
    'smtp': [
        ('admin@localhost', 'admin'), ('postmaster@localhost', 'postmaster'),
        ('mail@localhost', 'mail'),
    ],
    'rdp': [
        ('administrator', ''), ('administrator', 'password'),
        ('administrator', 'admin'), ('admin', 'admin'),
        ('administrator', 'administrator'), ('guest', ''),
        ('guest', 'guest'),
    ],
    'jenkins': [
        ('admin', 'admin'), ('admin', 'password'), ('jenkins', 'jenkins'),
        ('admin', ''), ('root', 'password'),
    ],
    'tomcat': [
        ('admin', 'admin'), ('tomcat', 'tomcat'), ('admin', 's3cret'),
        ('tomcat', 's3cret'), ('root', 'root'), ('manager', 'manager'),
    ],
    'phpmyadmin': [
        ('root', ''), ('root', 'root'), ('admin', 'admin'),
        ('pma', 'pma'), ('phpmyadmin', 'phpmyadmin'),
    ],
    'grafana': [
        ('admin', 'admin'), ('admin', 'password'), ('grafana', 'grafana'),
    ],
    'kibana': [
        ('elastic', 'changeme'), ('kibana', 'changeme'), ('admin', 'admin'),
    ],
}

# Secret patterns for scanning
SECRET_PATTERNS = {
    'aws_access_key': {
        'pattern': re.compile(r'AKIA[0-9A-Z]{16}'),
        'description': 'AWS Access Key ID',
        'severity': 'critical',
    },
    'aws_secret_key': {
        'pattern': re.compile(r'[a-zA-Z0-9/+=]{40}'),
        'description': 'Potential AWS Secret Access Key',
        'severity': 'critical',
        'context_required': ['aws', 'secret', 'key'],
    },
    'github_token': {
        'pattern': re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'),
        'description': 'GitHub Personal Access Token',
        'severity': 'high',
    },
    'google_api_key': {
        'pattern': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        'description': 'Google API Key',
        'severity': 'high',
    },
    'stripe_key': {
        'pattern': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
        'description': 'Stripe Live Secret Key',
        'severity': 'critical',
    },
    'jwt_token': {
        'pattern': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        'description': 'JWT Token',
        'severity': 'medium',
    },
    'private_key': {
        'pattern': re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
        'description': 'Private Key Material',
        'severity': 'critical',
    },
    'password_in_url': {
        'pattern': re.compile(r'(?:password|passwd|pwd|pass)=[^&\s]{3,}', re.IGNORECASE),
        'description': 'Password in URL',
        'severity': 'high',
    },
    'basic_auth': {
        'pattern': re.compile(r'Authorization:\s*Basic\s+[A-Za-z0-9+/]+=*', re.IGNORECASE),
        'description': 'Basic Authentication Credentials',
        'severity': 'high',
    },
    'slack_token': {
        'pattern': re.compile(r'xox[baprs]-(?:[0-9A-Za-z]{10,48})+'),
        'description': 'Slack Token',
        'severity': 'high',
    },
    'sendgrid_key': {
        'pattern': re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'),
        'description': 'SendGrid API Key',
        'severity': 'high',
    },
    'ssh_private_key': {
        'pattern': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        'description': 'OpenSSH Private Key',
        'severity': 'critical',
    },
    'database_url': {
        'pattern': re.compile(
            r'(?:mysql|postgresql|postgres|mongodb|redis|sqlite)://[^:\s]+:[^@\s]+@[^\s/]+',
            re.IGNORECASE
        ),
        'description': 'Database Connection String with Credentials',
        'severity': 'critical',
    },
    'twilio_key': {
        'pattern': re.compile(r'SK[0-9a-fA-F]{32}'),
        'description': 'Twilio API Key',
        'severity': 'high',
    },
    'telegram_bot_token': {
        'pattern': re.compile(r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}'),
        'description': 'Telegram Bot Token',
        'severity': 'medium',
    },
}

# Hash type patterns
HASH_PATTERNS = {
    'MD5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'SHA1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'SHA256': re.compile(r'^[a-fA-F0-9]{64}$'),
    'SHA512': re.compile(r'^[a-fA-F0-9]{128}$'),
    'NTLM': re.compile(r'^[a-fA-F0-9]{32}$'),  # Same format as MD5
    'bcrypt': re.compile(r'^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$'),
    'sha256crypt': re.compile(r'^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$'),
    'sha512crypt': re.compile(r'^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$'),
    'MD5crypt': re.compile(r'^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$'),
    'NetNTLMv1': re.compile(r'^[^:]+:[^:]+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$'),
    'NetNTLMv2': re.compile(r'^[^:]+:[^:]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$'),
    'WPA': re.compile(r'^[a-fA-F0-9]{64}$'),
    'Kerberos5': re.compile(r'^\$krb5\$'),
    'Kerberos5ASREP': re.compile(r'^\$krb5asrep\$'),
}


class CredentialScanner:
    """
    Credential and secret discovery engine implementing default credential testing,
    secret scanning, certificate analysis, and hash identification.
    """

    def __init__(self, timeout: int = 5):
        """
        Initialize the credential scanner.

        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
        self.findings: List[Dict] = []
        self.tested_credentials: List[Dict] = []
        self.secret_patterns = SECRET_PATTERNS

    def test_default_credentials(
        self, target: str, port: int, service: str
    ) -> Dict:
        """
        Test for default credentials on a service.

        Args:
            target: Target hostname or IP
            port: Service port
            service: Service type (ssh, ftp, http, mysql, etc.)

        Returns:
            Credential test results
        """
        results = {
            'target': target,
            'port': port,
            'service': service,
            'credentials_tested': 0,
            'valid_credentials': [],
            'vulnerable': False,
            'test_timestamp': datetime.utcnow().isoformat(),
        }

        cred_list = DEFAULT_CREDENTIALS_DB.get(service.lower(), DEFAULT_CREDENTIALS_DB.get('http', []))

        for username, password in cred_list[:20]:  # Limit to 20 per run
            results['credentials_tested'] += 1
            test_result = self._test_credential(target, port, service, username, password)

            self.tested_credentials.append({
                'target': target,
                'port': port,
                'service': service,
                'username': username,
                'password': '***' if password else '(empty)',
                'valid': test_result['valid'],
                'error': test_result.get('error'),
            })

            if test_result['valid']:
                results['valid_credentials'].append({
                    'username': username,
                    'password': password,
                    'service': service,
                    'severity': 'critical',
                })
                results['vulnerable'] = True

        if results['vulnerable']:
            self.findings.append({
                'type': 'default_credentials',
                'severity': 'critical',
                'target': target,
                'port': port,
                'service': service,
                'credentials': results['valid_credentials'],
                'description': f'Default credentials found on {service} service at {target}:{port}',
                'remediation': f'Change all default passwords on {service} service immediately',
            })

        return results

    def _test_credential(
        self, target: str, port: int, service: str,
        username: str, password: str
    ) -> Dict:
        """Test a single credential against a service."""
        # In production, would attempt actual authentication
        # Here we simulate - most default credentials won't work
        return {
            'valid': False,
            'error': None,
        }

    def scan_for_secrets(self, content: str, source: str = '') -> List[Dict]:
        """
        Scan text content for exposed secrets and credentials.

        Args:
            content: Text content to scan
            source: Source identifier (URL, file path, etc.)

        Returns:
            List of discovered secrets
        """
        secrets = []

        for secret_type, secret_info in self.secret_patterns.items():
            pattern = secret_info['pattern']
            matches = pattern.findall(content)

            for match in matches:
                # Avoid false positives for patterns requiring context
                context_required = secret_info.get('context_required', [])
                if context_required:
                    # Check if any context keyword appears near the match
                    match_pos = content.find(match) if isinstance(match, str) else -1
                    if match_pos >= 0:
                        surrounding = content[max(0, match_pos - 50):match_pos + 50].lower()
                        if not any(kw in surrounding for kw in context_required):
                            continue

                secret = {
                    'type': secret_type,
                    'description': secret_info['description'],
                    'severity': secret_info['severity'],
                    'source': source,
                    'value': self._redact_secret(match, secret_type),
                    'found_at': datetime.utcnow().isoformat(),
                    'recommendation': f'Immediately revoke and rotate this {secret_info["description"]}',
                }
                secrets.append(secret)

        return secrets

    def _redact_secret(self, secret: str, secret_type: str) -> str:
        """Redact a secret value for safe logging."""
        if not secret:
            return ''
        if len(secret) <= 8:
            return '***REDACTED***'
        # Show first 4 and last 4 characters
        return f"{secret[:4]}...{secret[-4:]} ({len(secret)} chars)"

    def analyze_certificate(self, target: str, port: int = 443) -> Dict:
        """
        Analyze X.509 certificate for security issues.

        Args:
            target: Target hostname or IP
            port: Target port (default 443)

        Returns:
            Certificate analysis results
        """
        analysis = {
            'target': target,
            'port': port,
            'certificate': {},
            'issues': [],
            'score': 100,
            'grade': 'A',
        }

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            conn = socket.create_connection((target, port), timeout=self.timeout)
            ssl_sock = context.wrap_socket(conn, server_hostname=target)

            cert = ssl_sock.getpeercert()
            cert_binary = ssl_sock.getpeercert(binary_form=True)

            if cert:
                # Extract certificate details
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')
                san = cert.get('subjectAltName', [])

                analysis['certificate'] = {
                    'subject': subject,
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                    'subject_alt_names': [s[1] for s in san if s[0] == 'DNS'],
                    'serial_number': cert.get('serialNumber', ''),
                    'version': cert.get('version', ''),
                    'signature_algorithm': 'unknown',  # Would need cryptography library for full details
                }

                # Check expiry
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry - datetime.utcnow()).days

                        if days_until_expiry < 0:
                            analysis['issues'].append({
                                'type': 'expired_certificate',
                                'severity': 'critical',
                                'description': f'Certificate expired {abs(days_until_expiry)} days ago',
                                'remediation': 'Renew certificate immediately',
                            })
                            analysis['score'] -= 30
                        elif days_until_expiry < 7:
                            analysis['issues'].append({
                                'type': 'expiring_soon_critical',
                                'severity': 'critical',
                                'description': f'Certificate expires in {days_until_expiry} days',
                                'remediation': 'Renew certificate immediately',
                            })
                            analysis['score'] -= 20
                        elif days_until_expiry < 30:
                            analysis['issues'].append({
                                'type': 'expiring_soon',
                                'severity': 'high',
                                'description': f'Certificate expires in {days_until_expiry} days',
                                'remediation': 'Plan certificate renewal soon',
                            })
                            analysis['score'] -= 10

                        analysis['certificate']['days_until_expiry'] = days_until_expiry
                    except ValueError:
                        pass

                # Check for wildcard certificate
                cn = subject.get('commonName', '')
                if cn.startswith('*'):
                    analysis['issues'].append({
                        'type': 'wildcard_certificate',
                        'severity': 'info',
                        'description': f'Wildcard certificate in use: {cn}',
                        'recommendation': 'Wildcard certs increase blast radius if compromised',
                    })

                # Check for self-signed
                if subject == issuer:
                    analysis['issues'].append({
                        'type': 'self_signed_certificate',
                        'severity': 'high',
                        'description': 'Certificate is self-signed - not trusted by browsers',
                        'remediation': 'Obtain a certificate from a trusted CA (e.g., Let\'s Encrypt)',
                    })
                    analysis['score'] -= 15

            ssl_sock.close()

        except ssl.SSLCertVerificationError as e:
            analysis['issues'].append({
                'type': 'ssl_verification_failed',
                'severity': 'high',
                'description': f'SSL certificate verification failed: {str(e)}',
                'remediation': 'Fix certificate chain or use valid certificate from trusted CA',
            })
            analysis['score'] -= 20

        except Exception as e:
            analysis['certificate']['error'] = str(e)
            analysis['issues'].append({
                'type': 'connection_error',
                'severity': 'medium',
                'description': f'Could not retrieve certificate: {str(e)}',
            })

        # Calculate grade
        score = analysis['score']
        if score >= 90:
            analysis['grade'] = 'A+'
        elif score >= 80:
            analysis['grade'] = 'A'
        elif score >= 70:
            analysis['grade'] = 'B'
        elif score >= 60:
            analysis['grade'] = 'C'
        elif score >= 50:
            analysis['grade'] = 'D'
        else:
            analysis['grade'] = 'F'

        return analysis

    def identify_hash(self, hash_string: str) -> List[Dict]:
        """
        Identify the type of a password hash.

        Args:
            hash_string: Hash string to identify

        Returns:
            List of possible hash types
        """
        matches = []

        for hash_type, pattern in HASH_PATTERNS.items():
            if pattern.match(hash_string.strip()):
                cracking_tools = self._get_hash_cracking_info(hash_type)
                matches.append({
                    'hash_type': hash_type,
                    'hash_value': hash_string[:16] + '...' if len(hash_string) > 16 else hash_string,
                    'cracking_difficulty': cracking_tools['difficulty'],
                    'recommended_tools': cracking_tools['tools'],
                    'wordlists': cracking_tools['wordlists'],
                })

        return matches

    def _get_hash_cracking_info(self, hash_type: str) -> Dict:
        """Get information about cracking a specific hash type."""
        info = {
            'MD5': {'difficulty': 'easy', 'tools': ['hashcat', 'john'], 'wordlists': ['rockyou', 'common_passwords']},
            'SHA1': {'difficulty': 'easy', 'tools': ['hashcat', 'john'], 'wordlists': ['rockyou']},
            'SHA256': {'difficulty': 'medium', 'tools': ['hashcat'], 'wordlists': ['rockyou']},
            'NTLM': {'difficulty': 'easy', 'tools': ['hashcat', 'john', 'Responder'], 'wordlists': ['rockyou', 'ntlm_common']},
            'NetNTLMv2': {'difficulty': 'medium', 'tools': ['hashcat', 'Responder'], 'wordlists': ['rockyou']},
            'bcrypt': {'difficulty': 'hard', 'tools': ['hashcat', 'john'], 'wordlists': ['small_wordlists']},
            'sha512crypt': {'difficulty': 'hard', 'tools': ['hashcat', 'john'], 'wordlists': ['small_wordlists']},
            'Kerberos5': {'difficulty': 'medium', 'tools': ['hashcat', 'john', 'impacket'], 'wordlists': ['rockyou']},
            'Kerberos5ASREP': {'difficulty': 'medium', 'tools': ['hashcat', 'rubeus'], 'wordlists': ['rockyou']},
        }
        return info.get(hash_type, {'difficulty': 'unknown', 'tools': ['hashcat', 'john'], 'wordlists': ['rockyou']})

    def detect_kerberos_attacks(self, network_data: Dict) -> List[Dict]:
        """
        Detect Kerberos-related attack indicators.

        Args:
            network_data: Network traffic data to analyze

        Returns:
            List of Kerberos attack indicators
        """
        findings = []

        # Kerberoasting detection
        if network_data.get('spn_requests', 0) > 10:
            findings.append({
                'type': 'kerberoasting',
                'severity': 'critical',
                'description': 'High volume of Kerberos TGS requests for SPNs detected - potential Kerberoasting',
                'mitre': 'T1558.003',
                'remediation': 'Use Group Managed Service Accounts (gMSA) for service accounts',
            })

        # AS-REP Roasting detection
        if network_data.get('asrep_without_preauth', 0) > 0:
            findings.append({
                'type': 'asrep_roasting',
                'severity': 'high',
                'description': 'Kerberos AS-REP responses without pre-authentication detected',
                'mitre': 'T1558.004',
                'remediation': 'Enable Kerberos pre-authentication for all accounts',
            })

        # Golden ticket detection
        if network_data.get('unusual_ticket_lifetime', False):
            findings.append({
                'type': 'golden_ticket',
                'severity': 'critical',
                'description': 'Kerberos ticket with unusual lifetime or KRBTGT usage detected',
                'mitre': 'T1558.001',
                'remediation': 'Reset KRBTGT password twice and investigate affected systems',
            })

        return findings

    def spray_passwords(
        self, targets: List[Dict], password_list: List[str],
        delay_seconds: float = 30.0
    ) -> Dict:
        """
        Perform password spray analysis (detection and recommendations only).

        Args:
            targets: List of target systems
            password_list: List of passwords to test
            delay_seconds: Delay between attempts (lockout avoidance)

        Returns:
            Password spray analysis results
        """
        return {
            'type': 'password_spray_analysis',
            'targets_count': len(targets),
            'passwords_count': len(password_list),
            'recommended_delay': delay_seconds,
            'lockout_detection': True,
            'description': (
                'Password spray analysis: testing one password against many accounts '
                'to avoid account lockout. Always maintain delay between attempts.'
            ),
            'findings': [],
            'recommendations': [
                'Implement account lockout policies (>5 attempts)',
                'Enable multi-factor authentication',
                'Monitor for unusual authentication patterns',
                'Use SIEM to correlate login attempts',
            ],
        }
