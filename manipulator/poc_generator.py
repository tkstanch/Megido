"""
Proof of Concept Generator.
Generates detailed PoC reports, curl commands, and Python scripts for confirmed vulnerabilities.
"""
import json
from typing import Dict, Optional
from urllib.parse import quote


class PoCGenerator:
    """
    Generates comprehensive Proof of Concept artifacts for confirmed vulnerabilities.
    """

    SEVERITY_MAP = {
        'XSS': ('high', 7.5),
        'SQLi': ('critical', 9.8),
        'SQLi (Time-based Blind)': ('critical', 9.8),
        'SQLi (Time-based)': ('critical', 9.8),
        'LFI': ('high', 7.5),
        'RFI': ('critical', 9.0),
        'RCE': ('critical', 10.0),
        'Command Injection': ('critical', 9.8),
        'SSRF': ('high', 8.0),
        'XXE': ('high', 7.5),
        'CSRF': ('medium', 6.5),
        'Open Redirect': ('medium', 6.1),
        'Path Traversal': ('high', 7.5),
        'SSTI': ('critical', 9.0),
        'NoSQLi': ('critical', 9.0),
    }

    REMEDIATION_MAP = {
        'XSS': 'Implement output encoding/escaping. Use Content Security Policy (CSP). Validate and sanitize all user input. Use modern framework escaping features.',
        'SQLi': 'Use parameterized queries/prepared statements. Implement input validation. Use ORM frameworks. Apply principle of least privilege to database accounts.',
        'LFI': 'Validate and sanitize file path inputs. Use a whitelist of allowed files. Disable dangerous PHP functions. Avoid passing user input to file inclusion functions.',
        'RCE': 'Avoid executing system commands with user input. Use parameterized functions. Implement strict input validation. Apply principle of least privilege.',
        'Command Injection': 'Avoid shell execution with user input. Use language-native APIs instead of shell commands. Validate all inputs strictly.',
        'SSRF': 'Validate and whitelist URLs. Disable unnecessary URL schemes. Use network-level controls. Block access to internal resources.',
        'XXE': 'Disable external entity processing in XML parsers. Use less complex data formats like JSON. Keep XML processors updated.',
        'CSRF': 'Implement CSRF tokens. Use SameSite cookie attribute. Verify Origin/Referer headers. Use custom request headers for AJAX.',
        'SSTI': 'Never use user input directly in template strings. Use sandboxed template engines. Implement strict input validation.',
        'NoSQLi': 'Use parameterized queries. Validate and sanitize input. Apply type checking for expected data types.',
    }

    def generate(self, injection_point: Dict, payload: str, result: Dict) -> Dict:
        """
        Generate PoC artifacts for a confirmed vulnerability.

        Returns dict with poc_curl_command, poc_python_script, poc_report.
        """
        vuln_type = result.get('vulnerability_type', 'Unknown')
        severity_info = self.SEVERITY_MAP.get(vuln_type, ('medium', 5.0))
        severity, cvss = severity_info

        curl_cmd = self._generate_curl(result)
        python_script = self._generate_python_script(result)
        report = self._generate_report(
            injection_point=injection_point,
            payload=payload,
            result=result,
            vuln_type=vuln_type,
            severity=severity,
            cvss=cvss,
            curl_cmd=curl_cmd,
            python_script=python_script,
        )

        return {
            'poc_curl_command': curl_cmd,
            'poc_python_script': python_script,
            'poc_report': report,
            'severity': severity,
        }

    def _generate_curl(self, result: Dict) -> str:
        """Generate a curl command to reproduce the exploit."""
        method = result.get('request_method', 'GET').upper()
        url = result.get('request_url', '')
        headers = result.get('request_headers', {})
        body = result.get('request_body', '')

        parts = [f'curl -X {method}']

        skip_headers = {'User-Agent', 'Accept', 'Accept-Encoding', 'Connection'}
        for name, value in headers.items():
            if name not in skip_headers:
                parts.append(f"  -H '{name}: {value}'")

        if body and method in ('POST', 'PUT', 'PATCH'):
            parts.append(f"  --data '{body}'")

        parts.append(f"  '{url}'")

        return ' \\\n'.join(parts)

    def _generate_python_script(self, result: Dict) -> str:
        """Generate a Python requests script to reproduce the exploit."""
        method = result.get('request_method', 'GET').upper()
        url = result.get('request_url', '')
        headers = result.get('request_headers', {})
        body = result.get('request_body', '')

        headers_repr = json.dumps(headers, indent=4)

        script = f'''#!/usr/bin/env python3
"""
Megido Security - Proof of Concept
Vulnerability: {result.get('vulnerability_type', 'Unknown')}
Severity: {result.get('severity', 'unknown').upper()}
Detection: {result.get('detection_method', 'unknown')}
Confidence: {result.get('confidence', 0):.0%}
"""

import requests

url = {json.dumps(url)}
headers = {headers_repr}
'''

        if body and method in ('POST', 'PUT', 'PATCH'):
            script += f'\ndata = {json.dumps(body)}\n'
            script += f'\nresponse = requests.{method.lower()}(url, headers=headers, data=data)\n'
        else:
            script += f'\nresponse = requests.{method.lower()}(url, headers=headers)\n'

        script += '''
print(f"Status Code: {response.status_code}")
print(f"Response Time: {response.elapsed.total_seconds():.3f}s")
print("\\nResponse Body (first 1000 chars):")
print(response.text[:1000])
'''
        return script

    def _generate_report(self, injection_point: Dict, payload: str, result: Dict,
                          vuln_type: str, severity: str, cvss: float,
                          curl_cmd: str, python_script: str) -> str:
        """Generate a detailed text report."""
        remediation = self.REMEDIATION_MAP.get(vuln_type,
            'Review security best practices for this vulnerability type.')

        report = f"""
================================================================================
VULNERABILITY REPORT - Megido Security
================================================================================

VULNERABILITY TYPE: {vuln_type}
SEVERITY: {severity.upper()}
CVSS SCORE (Estimated): {cvss}/10.0
CONFIDENCE: {result.get('confidence', 0):.0%}
DETECTION METHOD: {result.get('detection_method', 'unknown')}

INJECTION POINT
---------------
URL: {injection_point.get('url', 'N/A')}
Parameter: {injection_point.get('parameter_name', 'N/A')}
Parameter Type: {injection_point.get('parameter_type', 'N/A')}
Location: {injection_point.get('injection_location', 'N/A')}
Original Value: {injection_point.get('original_value', 'N/A')}

PAYLOAD
-------
{payload}

HTTP REQUEST
------------
{result.get('request_method', 'N/A')} {result.get('request_url', 'N/A')}
Status Code: {result.get('response_status', 'N/A')}
Response Time: {result.get('response_time_ms', 0)}ms

EVIDENCE
--------
{result.get('evidence', 'N/A')}

IMPACT ASSESSMENT
-----------------
{_get_impact(vuln_type)}

REMEDIATION
-----------
{remediation}

REPRODUCTION
------------
curl command:
{curl_cmd}

================================================================================
"""
        return report.strip()


def _get_impact(vuln_type: str) -> str:
    impacts = {
        'XSS': "Attacker can execute arbitrary JavaScript in victim's browser, steal session cookies, perform actions on behalf of victim, or redirect to malicious sites.",
        'SQLi': 'Attacker can read/modify/delete database contents, bypass authentication, execute commands on the database server, and potentially gain full system access.',
        'LFI': 'Attacker can read sensitive files including configuration files, source code, credentials, and private keys.',
        'RCE': 'Attacker can execute arbitrary commands on the server with the privileges of the web server process.',
        'Command Injection': 'Attacker can execute arbitrary OS commands on the server.',
        'SSRF': 'Attacker can make the server perform requests to internal services, potentially accessing cloud metadata, internal APIs, or other restricted resources.',
        'XXE': 'Attacker can read local files, perform SSRF, or cause denial of service through entity expansion attacks.',
        'CSRF': 'Attacker can perform unauthorized actions on behalf of authenticated users.',
        'SSTI': 'Attacker can execute arbitrary code through the template engine, potentially leading to full server compromise.',
    }
    return impacts.get(vuln_type, 'Potential security vulnerability that may allow unauthorized access or data exposure.')
