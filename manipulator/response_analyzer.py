"""
Response Analyzer for vulnerability detection.
Analyzes HTTP responses to detect signs of successful exploitation.
"""
import re
import time
from typing import Dict, List, Optional, Tuple

# Minimum response delay (ms) to classify as a time-based injection.
# Set to 4500ms (4.5s) to account for typical 5-second sleep payloads
# while allowing a 0.5s margin for network jitter and processing overhead.
TIME_BASED_DELAY_THRESHOLD_MS = 4500


# SQL error signatures for different databases
SQL_ERROR_SIGNATURES = {
    'mysql': [
        r'you have an error in your sql syntax',
        r'warning: mysql_',
        r'mysql_fetch',
        r'mysql_num_rows',
        r'supplied argument is not a valid mysql',
        r'valid mysql result',
        r'column count doesn\'t match',
        r'table \'.*\' doesn\'t exist',
        r'unknown column',
        r'com\.mysql\.jdbc',
    ],
    'mssql': [
        r'microsoft ole db provider for sql server',
        r'odbc sql server driver',
        r'\[sql server\]',
        r'unclosed quotation mark after the character string',
        r'incorrect syntax near',
        r'microsoft jet database engine',
        r'syntax error converting',
        r'sql server native client',
    ],
    'postgresql': [
        r'pg_query\(\)',
        r'pg_exec\(\)',
        r'postgresql.*error',
        r'warning.*pg_',
        r'valid postgresql result',
        r'npgsql\.',
        r'psql\.pg',
        r'error.*position:',
    ],
    'oracle': [
        r'oracle.*driver',
        r'warning.*oci_',
        r'quoted string not properly terminated',
        r'ora-[0-9]{5}',
        r'oracle.*error',
        r'oracle.*exception',
    ],
    'sqlite': [
        r'sqlite[_\.]error',
        r'warning.*sqlite_',
        r'sqlite3::',
        r'\[sqlite\]',
    ],
}

# LFI/Path traversal signatures
LFI_SIGNATURES = [
    r'root:[x*]:0:0:',  # /etc/passwd
    r'\[boot loader\]',  # boot.ini
    r'\[operating systems\]',  # boot.ini
    r'for 16-bit app support',  # win.ini
    r'\[fonts\]',  # win.ini
    r'daemon:',  # /etc/passwd daemon entry
    r'nobody:',  # /etc/passwd nobody entry
    r'www-data:',  # web user in /etc/passwd
    r'<\?php',  # PHP source included
]

# XSS reflection markers
XSS_MARKERS = [
    'xss_test_marker_',
    'megido_xss_',
    'alert(1)',
    'prompt(1)',
    'confirm(1)',
]

# Command injection output signatures
CMD_INJECTION_SIGNATURES = [
    r'uid=\d+\(',  # Linux id command
    r'gid=\d+\(',
    r'root@',
    r'www-data@',
    r'\$\s',  # shell prompt
    r'Microsoft Windows \[Version',
    r'Directory of C:\\',
    r'Volume in drive',
]

# RCE markers
RCE_MARKERS = [
    'phpinfo()',
    'PHP Version',
    'System => ',
    'Loaded Configuration File',
]

# SSRF/XXE indicators
SSRF_SIGNATURES = [
    r'169\.254\.169\.254',  # AWS metadata
    r'metadata\.google\.internal',  # GCP metadata
    r'localhost',
    r'127\.0\.0\.1',
    r'::1',
    r'169\.254\.',
    r'192\.168\.',
    r'10\.',
    r'172\.(1[6-9]|2[0-9]|3[01])\.',
]

XXE_SIGNATURES = [
    r'root:[x*]:0:0:',
    r'\[boot loader\]',
    r'<?xml',
    r'<!DOCTYPE',
    r'ENTITY',
]


class ResponseAnalyzer:
    """Analyzes HTTP responses for signs of successful exploitation."""

    def __init__(self):
        self._compiled_sql = {}
        for db, patterns in SQL_ERROR_SIGNATURES.items():
            self._compiled_sql[db] = [re.compile(p, re.IGNORECASE) for p in patterns]

        self._compiled_lfi = [re.compile(p, re.IGNORECASE) for p in LFI_SIGNATURES]
        self._compiled_cmd = [re.compile(p, re.IGNORECASE) for p in CMD_INJECTION_SIGNATURES]
        self._compiled_ssrf = [re.compile(p, re.IGNORECASE) for p in SSRF_SIGNATURES]
        self._compiled_xxe = [re.compile(p, re.IGNORECASE) for p in XXE_SIGNATURES]

    def analyze(self, payload: str, response_body: str, response_status: int,
                response_headers: dict, response_time_ms: int,
                baseline_time_ms: int = 0, baseline_body: str = '') -> Dict:
        """
        Analyze a response for signs of vulnerability exploitation.

        Returns dict with keys:
          - is_successful: bool
          - vulnerability_type: str
          - detection_method: str
          - confidence: float (0.0-1.0)
          - evidence: str
          - severity: str
        """
        result = {
            'is_successful': False,
            'vulnerability_type': '',
            'detection_method': '',
            'confidence': 0.0,
            'evidence': '',
            'severity': 'info',
        }

        body_lower = response_body.lower() if response_body else ''

        # Check for SQL injection errors
        for db, patterns in self._compiled_sql.items():
            for pattern in patterns:
                m = pattern.search(body_lower)
                if m:
                    result.update({
                        'is_successful': True,
                        'vulnerability_type': 'SQLi',
                        'detection_method': 'error-based',
                        'confidence': 0.9,
                        'evidence': f'SQL error ({db}): ...{body_lower[max(0,m.start()-50):m.end()+50]}...',
                        'severity': 'critical',
                    })
                    return result

        # Check for LFI
        for pattern in self._compiled_lfi:
            m = pattern.search(response_body or '')
            if m:
                result.update({
                    'is_successful': True,
                    'vulnerability_type': 'LFI',
                    'detection_method': 'reflected',
                    'confidence': 0.95,
                    'evidence': f'File content detected: ...{response_body[max(0,m.start()-50):m.end()+50]}...',
                    'severity': 'high',
                })
                return result

        # Check for XSS reflection
        for marker in XSS_MARKERS:
            if marker in payload and marker in (response_body or ''):
                result.update({
                    'is_successful': True,
                    'vulnerability_type': 'XSS',
                    'detection_method': 'reflected',
                    'confidence': 0.85,
                    'evidence': 'XSS payload reflected unescaped in response',
                    'severity': 'high',
                })
                return result

        # Check if specific XSS payload is reflected unescaped
        if payload and response_body and len(payload) > 5:
            if '<script' in payload.lower() and '<script' in body_lower:
                if payload.lower()[:20] in body_lower:
                    result.update({
                        'is_successful': True,
                        'vulnerability_type': 'XSS',
                        'detection_method': 'reflected',
                        'confidence': 0.8,
                        'evidence': 'Script tag reflected in response',
                        'severity': 'high',
                    })
                    return result

        # Check for command injection output
        for pattern in self._compiled_cmd:
            m = pattern.search(response_body or '')
            if m:
                result.update({
                    'is_successful': True,
                    'vulnerability_type': 'Command Injection',
                    'detection_method': 'reflected',
                    'confidence': 0.9,
                    'evidence': f'Command output detected: ...{response_body[max(0,m.start()-20):m.end()+20]}...',
                    'severity': 'critical',
                })
                return result

        # Time-based detection
        if baseline_time_ms > 0:
            time_diff = response_time_ms - baseline_time_ms
            if time_diff >= TIME_BASED_DELAY_THRESHOLD_MS:
                result.update({
                    'is_successful': True,
                    'vulnerability_type': 'SQLi (Time-based)',
                    'detection_method': 'time-based',
                    'confidence': 0.75,
                    'evidence': f'Response delayed by {time_diff}ms (baseline: {baseline_time_ms}ms)',
                    'severity': 'critical',
                })
                return result

        # Check for XXE
        if '<!ENTITY' in (payload or '').upper():
            for pattern in self._compiled_xxe:
                m = pattern.search(response_body or '')
                if m:
                    result.update({
                        'is_successful': True,
                        'vulnerability_type': 'XXE',
                        'detection_method': 'reflected',
                        'confidence': 0.85,
                        'evidence': 'XML entity content in response',
                        'severity': 'high',
                    })
                    return result

        return result

    def check_waf_block(self, response_status: int, response_body: str) -> bool:
        """Detect if WAF blocked the request."""
        if response_status in (403, 406, 501):
            return True
        waf_patterns = [
            'access denied', 'blocked', 'security violation',
            'web application firewall', 'waf', 'request blocked',
            'attack detected',
        ]
        body_lower = (response_body or '').lower()
        return any(p in body_lower for p in waf_patterns)

    def check_rate_limit(self, response_status: int, response_body: str) -> bool:
        """Detect if we're being rate limited."""
        if response_status == 429:
            return True
        rl_patterns = ['too many requests', 'rate limit', 'slow down', 'try again later']
        body_lower = (response_body or '').lower()
        return any(p in body_lower for p in rl_patterns)
