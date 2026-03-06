"""
Bug Bounty Impact Analysis and PoC Report Generator

This module transforms raw vulnerability + exploit results into
submission-ready bug bounty reports for platforms like Bugcrowd and HackerOne.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Report generation constants
# ---------------------------------------------------------------------------

# CVSS score bump applied when exploitation has been verified
VERIFIED_SCORE_BUMP: float = 0.5

# Severity-based CVSS adjustments (offset from the vuln-type base score)
SEVERITY_CVSS_ADJUSTMENTS: Dict[str, float] = {
    'critical': 0.0,
    'high': 0.0,
    'medium': -1.5,
    'low': -3.0,
}

# Maximum number of payloads shown in the Steps to Reproduce section
MAX_PAYLOADS_IN_STEPS: int = 5

# Maximum number of payloads shown in the PoC Evidence section
MAX_PAYLOADS_IN_EVIDENCE: int = 10

# ---------------------------------------------------------------------------
# Impact mapping data
# ---------------------------------------------------------------------------

IMPACT_MAP: Dict[str, Dict[str, Any]] = {
    'xss': {
        'title_template': '{severity_adj} XSS on {url} Enables Account Takeover',
        'attacker_impact': [
            'Steal authenticated session cookies to take over victim accounts',
            'Capture credentials via fake login overlays injected into trusted pages',
            'Redirect users to phishing pages or malware-serving infrastructure',
            'Perform actions on behalf of the victim (CSRF via XSS)',
            'Deface the application or serve malicious content to all visitors',
        ],
        'business_impact': [
            'Account takeover leading to data breach',
            'Credential theft at scale',
            'Brand/reputation damage',
            'Regulatory/compliance violations (GDPR, PCI-DSS)',
        ],
        'cvss_base': 6.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N',
        'cwe': 'CWE-79',
        'owasp': 'A03:2021 – Injection',
        'scenario': (
            'An attacker crafts a malicious link containing the XSS payload. '
            'When an authenticated user clicks the link, their session token is '
            'exfiltrated to the attacker\'s server, granting full account access.'
        ),
    },
    'sqli': {
        'title_template': 'SQL Injection on {url} Allows Full Database Exfiltration',
        'attacker_impact': [
            'Dump the entire database contents including user credentials',
            'Bypass authentication controls',
            'Modify or delete database records',
            'In some configurations: execute OS commands via xp_cmdshell or UDF',
            'Read sensitive files from the server filesystem',
        ],
        'business_impact': [
            'Mass data breach exposing PII and credentials',
            'Complete authentication bypass (admin takeover)',
            'Financial and operational data exposure',
            'Regulatory fines (GDPR, CCPA, PCI-DSS)',
        ],
        'cvss_base': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-89',
        'owasp': 'A03:2021 – Injection',
        'scenario': (
            'An attacker injects SQL syntax into a vulnerable parameter, extracting '
            'all user records, hashed passwords, and sensitive application data '
            'directly from the database without authentication.'
        ),
    },
    'csrf': {
        'title_template': 'CSRF on {url} Enables Unauthorized State-Changing Actions',
        'attacker_impact': [
            'Change victim\'s email address or password without their knowledge',
            'Initiate fund transfers or purchases on behalf of the victim',
            'Add attacker-controlled accounts to privileged groups',
            'Delete or modify critical account data',
        ],
        'business_impact': [
            'Unauthorized account modifications',
            'Financial loss via forced transactions',
            'Privilege escalation',
        ],
        'cvss_base': 8.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
        'cwe': 'CWE-352',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker hosts a page that silently submits a state-changing request '
            'to the target application using the victim\'s existing session. When an '
            'authenticated user visits the attacker page, the action executes as them.'
        ),
    },
    'xxe': {
        'title_template': 'XXE Injection on {url} Enables Server File Read',
        'attacker_impact': [
            'Read arbitrary server files (e.g., /etc/passwd, application config, SSH keys)',
            'Perform SSRF attacks via the XML parser to probe internal services',
            'In some stacks: achieve remote code execution via XXE-to-SSRF chains',
            'Enumerate internal network topology',
        ],
        'business_impact': [
            'Credential and secret key exfiltration',
            'Internal infrastructure exposure',
            'Potential remote code execution',
        ],
        'cvss_base': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N',
        'cwe': 'CWE-611',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker submits an XML document with an external entity reference '
            'pointing to /etc/passwd. The server resolves the entity and returns '
            'the file contents in the response.'
        ),
    },
    'rce': {
        'title_template': 'Remote Code Execution on {url} — Full Server Compromise',
        'attacker_impact': [
            'Execute arbitrary OS commands with the privileges of the web server process',
            'Install persistent backdoors or reverse shells',
            'Pivot laterally to internal network hosts',
            'Access all secrets, keys, and data on the server',
            'Destroy or encrypt data (ransomware scenario)',
        ],
        'business_impact': [
            'Complete server compromise',
            'Lateral movement across the infrastructure',
            'Ransomware / data destruction risk',
            'Theft of all secrets, credentials, and customer data',
        ],
        'cvss_base': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-78',
        'owasp': 'A03:2021 – Injection',
        'scenario': (
            'An attacker sends a crafted request containing OS command syntax in a '
            'parameter that is unsafely passed to a system call. The server executes '
            'the injected command and returns its output to the attacker.'
        ),
    },
    'lfi': {
        'title_template': 'Local File Inclusion on {url} Enables Sensitive File Disclosure',
        'attacker_impact': [
            'Read sensitive configuration files containing credentials and API keys',
            'Disclose application source code for further vulnerability analysis',
            'Read /proc/self/environ or application log files for further exploitation',
            'Chain with log poisoning to achieve remote code execution',
        ],
        'business_impact': [
            'Credential and API key exfiltration',
            'Source code disclosure enabling deeper attacks',
            'Potential escalation to RCE via log poisoning',
        ],
        'cvss_base': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',
        'cwe': 'CWE-98',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker manipulates a file path parameter with directory traversal '
            'sequences (../../) to read /etc/passwd or application config files '
            'from the server filesystem.'
        ),
    },
    'rfi': {
        'title_template': 'Remote File Inclusion on {url} Enables Code Execution',
        'attacker_impact': [
            'Include and execute attacker-controlled code hosted on an external server',
            'Achieve full remote code execution with the privileges of the web process',
            'Install webshells, backdoors, or download additional malware',
        ],
        'business_impact': [
            'Remote code execution and server compromise',
            'Complete loss of confidentiality, integrity, and availability',
        ],
        'cvss_base': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-98',
        'owasp': 'A03:2021 – Injection',
        'scenario': (
            'An attacker provides a URL pointing to malicious code they control. '
            'The server fetches and executes the remote script, giving the attacker '
            'a webshell on the target.'
        ),
    },
    'open_redirect': {
        'title_template': 'Open Redirect on {url} Enables Phishing Attacks',
        'attacker_impact': [
            'Craft trusted-looking URLs that redirect victims to phishing pages',
            'Steal OAuth tokens via redirect_uri manipulation',
            'Bypass domain-allowlist filters in SSRF protection (redirect chain)',
        ],
        'business_impact': [
            'Credential theft via phishing leveraging trusted domain',
            'OAuth token theft enabling account takeover',
            'Possible SSRF escalation via redirect chain',
        ],
        'cvss_base': 6.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
        'cwe': 'CWE-601',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker sends a victim a legitimate-looking URL on the target domain '
            'with a manipulated redirect parameter pointing to an attacker-controlled '
            'phishing site that harvests credentials.'
        ),
    },
    'ssrf': {
        'title_template': 'SSRF on {url} Allows Internal Network Access and Metadata Theft',
        'attacker_impact': [
            'Access AWS/GCP/Azure instance metadata endpoint to steal cloud credentials',
            'Scan and probe internal services (databases, Kubernetes API, etc.)',
            'Bypass firewall rules to reach internal-only services',
            'Chain with RCE via internal service exploitation',
            'Exfiltrate data from internal APIs',
        ],
        'business_impact': [
            'Cloud credential theft enabling full cloud account takeover',
            'Internal service enumeration and exploitation',
            'Data exfiltration from internal systems',
        ],
        'cvss_base': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-918',
        'owasp': 'A10:2021 – Server-Side Request Forgery',
        'scenario': (
            'An attacker provides a URL pointing to http://169.254.169.254/latest/'
            'meta-data/iam/security-credentials/ in a parameter that causes the '
            'server to make an outbound request, returning AWS IAM credentials.'
        ),
    },
    'info_disclosure': {
        'title_template': 'Sensitive Information Disclosure on {url}',
        'attacker_impact': [
            'Obtain credentials, API keys, or tokens from exposed responses',
            'Map internal infrastructure from leaked stack traces or error messages',
            'Use disclosed data to refine further attacks',
        ],
        'business_impact': [
            'Credential exposure enabling account takeover or service abuse',
            'Reconnaissance data enabling more sophisticated attacks',
        ],
        'cvss_base': 5.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cwe': 'CWE-200',
        'owasp': 'A02:2021 – Cryptographic Failures',
        'scenario': (
            'An attacker triggers an application error that exposes internal file '
            'paths, database connection strings, or API keys in the response body '
            'or HTTP headers.'
        ),
    },
    'clickjacking': {
        'title_template': 'Clickjacking on {url} Enables UI Redress Attacks',
        'attacker_impact': [
            'Trick authenticated users into performing unintended actions',
            'Silently submit forms (account changes, transfers) via invisible overlays',
            'Harvest sensitive on-page content by overlaying a transparent iframe',
        ],
        'business_impact': [
            'Unauthorized account changes',
            'Financial transaction manipulation',
        ],
        'cvss_base': 4.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N',
        'cwe': 'CWE-1021',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker embeds the target page in a transparent iframe on a malicious '
            'site and tricks users into clicking buttons that trigger sensitive actions '
            'such as fund transfers or account setting changes.'
        ),
    },
    'js_hijacking': {
        'title_template': 'JavaScript/JSONP Hijacking on {url} Enables Data Theft',
        'attacker_impact': [
            'Steal sensitive user data returned in JSONP or array-literal responses',
            'Read cross-origin JSON data by overriding Array/Object constructors',
        ],
        'business_impact': [
            'User data theft including profile details, emails, and session tokens',
        ],
        'cvss_base': 6.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'cwe': 'CWE-346',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker hosts a page that includes the vulnerable JSONP endpoint '
            'as a script tag. The victim\'s browser executes the callback, passing '
            'their private data to the attacker\'s callback function.'
        ),
    },
    'idor': {
        'title_template': 'IDOR on {url} Allows Unauthorized Access to Any User\'s Data',
        'attacker_impact': [
            'Access, modify, or delete other users\' private data by changing an ID',
            'Escalate privileges by accessing admin objects',
            'Enumerate all objects to exfiltrate bulk user data',
        ],
        'business_impact': [
            'Mass data breach via bulk enumeration',
            'Account takeover via profile/credential modification',
            'Unauthorized data modification or deletion',
        ],
        'cvss_base': 8.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-639',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker changes the numeric ID in an API request from their own '
            'user ID to another user\'s ID. The server returns the other user\'s '
            'private profile data without checking authorization.'
        ),
    },
    'jwt': {
        'title_template': 'JWT Vulnerability on {url} Enables Authentication Bypass',
        'attacker_impact': [
            'Forge arbitrary JWT claims to impersonate any user including admins',
            'Bypass authentication entirely via algorithm confusion (alg:none)',
            'Escalate privileges by modifying the role/permission claims',
        ],
        'business_impact': [
            'Full authentication bypass',
            'Admin account takeover',
            'Privilege escalation',
        ],
        'cvss_base': 9.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-347',
        'owasp': 'A02:2021 – Cryptographic Failures',
        'scenario': (
            'An attacker crafts a JWT with alg:none or exploits a weak secret to '
            'sign a token with admin-level claims. The server accepts the forged '
            'token, granting full administrative access.'
        ),
    },
    'crlf': {
        'title_template': 'CRLF Injection on {url} Enables HTTP Response Splitting',
        'attacker_impact': [
            'Inject arbitrary HTTP headers into responses (e.g., Set-Cookie for session fixation)',
            'Split HTTP responses to perform cache poisoning',
            'Inject XSS payloads via injected Content-Type or response body',
        ],
        'business_impact': [
            'Session hijacking via cookie injection',
            'Cache poisoning serving malicious content',
            'XSS escalation via response splitting',
        ],
        'cvss_base': 6.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
        'cwe': 'CWE-113',
        'owasp': 'A03:2021 – Injection',
        'scenario': (
            'An attacker injects \\r\\n characters into a URL parameter that is '
            'reflected in a response header, splitting the response and injecting '
            'malicious headers that set a forged session cookie on victim browsers.'
        ),
    },
    'host_header': {
        'title_template': 'Host Header Injection on {url} Enables Password Reset Poisoning',
        'attacker_impact': [
            'Poison password reset links so the token is sent to an attacker-controlled domain',
            'Perform web cache poisoning by injecting a malicious Host header',
            'Internal network enumeration via the Host header',
        ],
        'business_impact': [
            'Account takeover via password reset token theft',
            'Cache poisoning affecting all users',
        ],
        'cvss_base': 8.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-644',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker manipulates the HTTP Host header when triggering a password '
            'reset for a victim account. The reset email contains a link pointing to '
            'the attacker\'s domain, and clicking it delivers the reset token to the attacker.'
        ),
    },
    'smuggling': {
        'title_template': 'HTTP Request Smuggling on {url} Enables Request Hijacking',
        'attacker_impact': [
            'Hijack other users\' requests to steal their session tokens',
            'Bypass front-end security controls and access restricted endpoints',
            'Perform web cache poisoning against all users via smuggled requests',
        ],
        'business_impact': [
            'Account takeover at scale via session token theft',
            'Security control bypass',
            'Cache poisoning affecting all users',
        ],
        'cvss_base': 9.0,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-444',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker exploits a discrepancy in how the front-end and back-end '
            'servers parse Transfer-Encoding and Content-Length headers, prepending '
            'a partial request to another user\'s request to steal their session.'
        ),
    },
    'deserialization': {
        'title_template': 'Insecure Deserialization on {url} Enables Remote Code Execution',
        'attacker_impact': [
            'Achieve remote code execution by deserializing malicious object graphs',
            'Escalate privileges via manipulated deserialized session objects',
            'Cause denial-of-service via billion-laughs-style deserialization bombs',
        ],
        'business_impact': [
            'Full server compromise via RCE',
            'Authentication and authorization bypass',
        ],
        'cvss_base': 8.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-502',
        'owasp': 'A08:2021 – Software and Data Integrity Failures',
        'scenario': (
            'An attacker crafts a malicious serialized payload using a known gadget '
            'chain and submits it in a cookie or POST body. The server deserializes '
            'it and executes arbitrary OS commands during object construction.'
        ),
    },
    'graphql': {
        'title_template': 'GraphQL Security Issue on {url} Allows Unauthorized Data Access',
        'attacker_impact': [
            'Enumerate the full schema via introspection to map all data objects',
            'Access unauthorized data via field-level authorization bypass',
            'Perform batch queries to bypass rate limiting and exfiltrate data at scale',
            'Trigger DoS via deeply nested circular queries',
        ],
        'business_impact': [
            'Data exfiltration and privacy violation',
            'Authorization bypass enabling privilege escalation',
            'Denial of service via query complexity abuse',
        ],
        'cvss_base': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-284',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker sends a GraphQL introspection query to map all available '
            'types and fields. They then craft targeted queries to extract sensitive '
            'data from objects they should not have access to.'
        ),
    },
    'websocket': {
        'title_template': 'WebSocket Security Issue on {url} Enables Real-Time Data Interception',
        'attacker_impact': [
            'Hijack WebSocket connections via Cross-Site WebSocket Hijacking (CSWSH)',
            'Intercept and manipulate real-time messages between client and server',
            'Access sensitive data streamed over unprotected WebSocket channels',
        ],
        'business_impact': [
            'Real-time data interception and manipulation',
            'Account takeover via CSWSH',
        ],
        'cvss_base': 6.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-1385',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker hosts a malicious web page that establishes a WebSocket '
            'connection to the target using the victim\'s session. Real-time '
            'application data is forwarded to the attacker over the hijacked channel.'
        ),
    },
    'cache_poisoning': {
        'title_template': 'Web Cache Poisoning on {url} Delivers Malicious Responses to All Users',
        'attacker_impact': [
            'Poison the cache with a malicious response that is served to all subsequent visitors',
            'Deliver XSS payloads or malicious redirects to users who never clicked a link',
            'Cause persistent denial of service by caching error responses',
        ],
        'business_impact': [
            'Mass XSS delivery at scale without per-user interaction',
            'Persistent service disruption for all users',
            'Brand damage from defaced cached pages',
        ],
        'cvss_base': 8.2,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
        'cwe': 'CWE-524',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker sends a request with an unkeyed header whose value is '
            'reflected in the response. The response is stored in the cache and '
            'served to all users who subsequently request the same resource.'
        ),
    },
    'cors': {
        'title_template': 'CORS Misconfiguration on {url} Allows Cross-Origin Data Theft',
        'attacker_impact': [
            'Read authenticated API responses from any origin via JavaScript',
            'Exfiltrate user data, API keys, or session tokens cross-origin',
            'Perform state-changing API calls cross-origin with credentials',
        ],
        'business_impact': [
            'Data exfiltration from authenticated sessions',
            'Account takeover via cross-origin credential exfiltration',
        ],
        'cvss_base': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-942',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker hosts a malicious page that makes credentialed cross-origin '
            'requests to the API. Because the server echoes the Origin header in '
            'Access-Control-Allow-Origin with allow-credentials:true, the browser '
            'exposes the response to the attacker\'s JavaScript.'
        ),
    },
    'email_rce': {
        'title_template': 'Email Field RCE on {url} — Full Server Compromise via Command Injection',
        'attacker_impact': [
            'Execute arbitrary OS commands through shell metacharacters in email input',
            'Install persistent backdoors or reverse shells on the server',
            'Access all secrets, credentials, and customer data on the server',
            'Pivot laterally to internal network hosts from the compromised server',
        ],
        'business_impact': [
            'Complete server compromise via unauthenticated input',
            'All server data (credentials, customer PII) exposed',
            'Lateral movement risk to internal infrastructure',
        ],
        'cvss_base': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-78',
        'owasp': 'A03:2021 – Injection',
        'scenario': (
            'An attacker injects a pipe-chained OS command into an email address field '
            '(e.g., test@x]||id||). The server passes the value unsafely to a shell '
            'command, executing the injected payload and returning its output.'
        ),
    },
    'ai_llm': {
        'title_template': 'AI/LLM Vulnerability on {url} Enables Prompt Injection or Data Exfiltration',
        'attacker_impact': [
            'Hijack LLM instructions via prompt injection to bypass safety controls',
            'Exfiltrate system prompts, training data, or other users\' conversation history',
            'Cause the LLM to perform unauthorized actions on behalf of the attacker',
            'Bypass content moderation and abuse AI-powered features',
        ],
        'business_impact': [
            'Intellectual property theft (system prompts, fine-tuning data)',
            'Brand damage from harmful or unintended AI-generated content',
            'Regulatory risk if PII is exfiltrated via the LLM',
        ],
        'cvss_base': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N',
        'cwe': 'CWE-77',
        'owasp': 'A03:2021 – Injection',
        'scenario': (
            'An attacker injects adversarial instructions into user-controlled input '
            'processed by an LLM, overriding the system prompt and causing the model '
            'to reveal confidential data or perform unintended operations.'
        ),
    },
    'dos': {
        'title_template': 'Denial of Service Vulnerability on {url} Causes Application Unavailability',
        'attacker_impact': [
            'Render the application unavailable to legitimate users',
            'Trigger resource exhaustion (CPU, memory, database connections)',
            'Amplify impact with low-bandwidth requests (algorithmic complexity attack)',
        ],
        'business_impact': [
            'Service outage and revenue loss',
            'SLA violations and customer churn',
            'Reputational damage from prolonged downtime',
        ],
        'cvss_base': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        'cwe': 'CWE-400',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker sends a crafted request that triggers resource-intensive '
            'processing (e.g., a deeply nested JSON payload, a ReDoS pattern, or an '
            'unauthenticated endpoint with no rate limiting). Repeated requests exhaust '
            'server resources and cause a complete outage for all users.'
        ),
    },
    'security_misconfig': {
        'title_template': 'Security Misconfiguration on {url} Enables Multiple Attack Vectors',
        'attacker_impact': [
            'Bypass Content-Security-Policy to execute arbitrary scripts (missing CSP header)',
            'Embed the page in a malicious iframe to perform clickjacking (missing X-Frame-Options)',
            'Trick browsers into executing scripts in uploaded files (missing X-Content-Type-Options)',
            'Downgrade HTTPS connections via mixed-content injection (missing HSTS header)',
            'Access sensitive resources cross-origin (missing or misconfigured CORS policy)',
        ],
        'business_impact': [
            'XSS and clickjacking attacks against authenticated users',
            'Session hijacking via downgrade to HTTP',
            'Regulatory non-compliance (PCI-DSS, GDPR require security headers)',
        ],
        'cvss_base': 5.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'cwe': 'CWE-16',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker exploits the absence of security headers to mount secondary '
            'attacks: injecting scripts (no CSP), framing the page invisibly (no '
            'X-Frame-Options), or forcing HTTP downgrades (no HSTS).'
        ),
    },
    'sensitive_data': {
        'title_template': 'Sensitive Data Exposure on {url} Leaks User or System Credentials',
        'attacker_impact': [
            'Obtain plaintext or weakly-hashed passwords from exposed data stores',
            'Access API keys, tokens, or secrets from responses or configuration files',
            'Harvest PII (names, emails, payment data) from unprotected endpoints',
        ],
        'business_impact': [
            'Regulatory fines under GDPR, CCPA, or PCI-DSS for unprotected PII',
            'Credential stuffing attacks using exposed passwords',
            'Direct financial fraud from exposed payment data',
        ],
        'cvss_base': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cwe': 'CWE-312',
        'owasp': 'A02:2021 – Cryptographic Failures',
        'scenario': (
            'An attacker accesses an unprotected API endpoint or storage location and '
            'retrieves sensitive data including user credentials, PII, or application '
            'secrets that are stored or transmitted without adequate protection.'
        ),
    },
    'weak_password': {
        'title_template': 'Weak Password Policy on {url} Enables Brute-Force Account Takeover',
        'attacker_impact': [
            'Brute-force or dictionary-attack user accounts due to minimal password requirements',
            'Exploit credential stuffing with leaked password databases',
            'Enumerate valid accounts via differential error messages',
        ],
        'business_impact': [
            'Mass account compromise via automated credential attacks',
            'Unauthorized access to user data and sensitive features',
            'Compliance violations (many standards mandate strong password policies)',
        ],
        'cvss_base': 6.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-521',
        'owasp': 'A07:2021 – Identification and Authentication Failures',
        'scenario': (
            'An attacker uses a dictionary of common passwords against the login endpoint. '
            'Because no minimum complexity or lockout policy is enforced, the attack '
            'succeeds and grants access to user accounts.'
        ),
    },
    'bac': {
        'title_template': 'Broken Access Control on {url} Allows Unauthorized Resource Access',
        'attacker_impact': [
            'Access resources and functions restricted to other users or roles',
            'Escalate from a regular user to an administrative role',
            'Read, modify, or delete other users\' private data',
            'Bypass authentication checks to reach protected endpoints',
        ],
        'business_impact': [
            'Unauthorized access to sensitive user and business data',
            'Privilege escalation enabling full administrative takeover',
            'Regulatory violations (GDPR, HIPAA, PCI-DSS)',
        ],
        'cvss_base': 8.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-284',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker modifies a request to access an endpoint or resource that '
            'should be restricted to admins or other users. The server fails to '
            'validate the caller\'s permissions and returns the protected data.'
        ),
    },
    'username_enum': {
        'title_template': 'Username Enumeration on {url} Enables Targeted Credential Attacks',
        'attacker_impact': [
            'Build a list of valid usernames/emails for targeted phishing or brute-force',
            'Confirm existence of specific accounts (e.g., executives, admins)',
            'Combine with credential stuffing to compromise enumerated accounts',
        ],
        'business_impact': [
            'Facilitates targeted brute-force and phishing campaigns',
            'Privacy violation by confirming user registration status',
        ],
        'cvss_base': 5.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'cwe': 'CWE-203',
        'owasp': 'A07:2021 – Identification and Authentication Failures',
        'scenario': (
            'An attacker submits login or password-reset requests with different '
            'usernames and observes differential responses (different error messages, '
            'status codes, or timing) to determine which accounts exist.'
        ),
    },
    'captcha_bypass': {
        'title_template': 'CAPTCHA Bypass on {url} Enables Automated Abuse at Scale',
        'attacker_impact': [
            'Automate credential stuffing attacks against login endpoints',
            'Perform large-scale spam or account registration without restriction',
            'Bypass rate-limiting controls protecting sensitive operations',
            'Execute brute-force attacks against password-protected resources',
        ],
        'business_impact': [
            'Mass automated account compromise via credential stuffing',
            'Infrastructure abuse and increased operational costs from bot traffic',
            'Spam and fake account creation degrading service quality',
        ],
        'cvss_base': 5.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        'cwe': 'CWE-307',
        'owasp': 'A07:2021 – Identification and Authentication Failures',
        'scenario': (
            'An attacker discovers that the CAPTCHA validation can be bypassed by '
            'omitting the CAPTCHA token, reusing a previously solved token, or using '
            'an audio/visual bypass. They automate requests to perform credential '
            'stuffing or brute-force attacks at scale.'
        ),
    },
    'unsafe_upload': {
        'title_template': 'Unsafe File Upload on {url} Enables Remote Code Execution',
        'attacker_impact': [
            'Upload a webshell disguised as an image or document to execute OS commands',
            'Deliver malware or phishing content to other users via the upload feature',
            'Overwrite critical application files by controlling the upload path',
        ],
        'business_impact': [
            'Remote code execution leading to full server compromise',
            'Malware distribution to application users',
            'Data destruction via malicious file overwrites',
        ],
        'cvss_base': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'cwe': 'CWE-434',
        'owasp': 'A04:2021 – Insecure Design',
        'scenario': (
            'An attacker uploads a PHP webshell with a .jpg extension. The server '
            'stores it in a web-accessible directory and executes it as PHP when '
            'requested, granting full command execution on the server.'
        ),
    },
    'subdomain_takeover': {
        'title_template': 'Subdomain Takeover on {url} Enables Phishing and Cookie Theft',
        'attacker_impact': [
            'Host attacker-controlled content on a trusted subdomain',
            'Steal session cookies scoped to the parent domain',
            'Conduct phishing attacks using a legitimate-looking URL',
            'Bypass CSP and CORS policies that allowlist the domain',
        ],
        'business_impact': [
            'Credential and session theft leveraging trusted brand identity',
            'CORS and CSP policy bypass enabling cross-domain attacks',
            'Reputational damage from attacker-controlled subdomain',
        ],
        'cvss_base': 8.1,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N',
        'cwe': 'CWE-350',
        'owasp': 'A05:2021 – Security Misconfiguration',
        'scenario': (
            'An attacker discovers a DNS CNAME record pointing to an unclaimed '
            'third-party service (e.g., GitHub Pages, Heroku). They register the '
            'service and serve attacker-controlled content from the victim\'s subdomain, '
            'stealing cookies or performing phishing.'
        ),
    },
    'exif_data': {
        'title_template': 'EXIF Geolocation Data Exposure on {url} Leaks User Location',
        'attacker_impact': [
            'Extract precise GPS coordinates revealing the user\'s home or work location',
            'Identify device model and operating system for targeted exploitation',
            'Track user movements over time via photo upload history',
        ],
        'business_impact': [
            'Privacy violation and potential physical safety risk to users',
            'GDPR/CCPA regulatory exposure for unstripped PII in media files',
        ],
        'cvss_base': 4.3,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
        'cwe': 'CWE-200',
        'owasp': 'A02:2021 – Cryptographic Failures',
        'scenario': (
            'An attacker downloads an image uploaded by another user and reads its EXIF '
            'metadata using a standard tool. The GPS coordinates in the metadata reveal '
            'the user\'s precise location at the time of upload.'
        ),
    },
    'api_key_exposure': {
        'title_template': 'API Key Exposure on {url} Enables Unauthorized Service Access',
        'attacker_impact': [
            'Use exposed API keys to access third-party services (AWS, Stripe, Twilio, etc.)',
            'Incur financial charges by abusing paid service quotas',
            'Access or exfiltrate data stored in connected third-party services',
            'Impersonate the application to third-party APIs for malicious purposes',
        ],
        'business_impact': [
            'Direct financial loss from unauthorized API usage charges',
            'Data breach via access to third-party service data',
            'Revocation of third-party service access disrupting business operations',
        ],
        'cvss_base': 8.6,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
        'cwe': 'CWE-798',
        'owasp': 'A02:2021 – Cryptographic Failures',
        'scenario': (
            'An attacker finds a hardcoded or exposed API key in a JavaScript file, '
            'public repository, or API response. They use the key to make authenticated '
            'requests to the third-party service, exfiltrating data or abusing paid '
            'service quotas.'
        ),
    },
    'other': {
        'title_template': 'Security Vulnerability Found on {url}',
        'attacker_impact': [
            'Exploit application-specific weakness to gain unauthorized access or data',
        ],
        'business_impact': [
            'Potential data breach, service disruption, or unauthorized access',
        ],
        'cvss_base': 5.0,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
        'cwe': 'CWE-284',
        'owasp': 'A01:2021 – Broken Access Control',
        'scenario': (
            'An attacker exploits a weakness in the application logic to perform '
            'an unauthorized operation or access protected resources.'
        ),
    },
    'crypto': {
        'title_template': '{severity_adj} SSL/TLS Cryptographic Weakness on {url} Enables Man-in-the-Middle Attacks',
        'attacker_impact': [
            'Perform man-in-the-middle (MITM) attacks to intercept encrypted traffic',
            'Decrypt sensitive data (credentials, session tokens, PII) in transit',
            'Tamper with application data without detection by the client',
            'Exploit expired or self-signed certificates to bypass browser trust warnings',
            'Downgrade TLS connections to deprecated protocol versions (TLSv1.0/1.1, SSLv3)',
            'Leverage weak cipher suites (RC4, 3DES, NULL, EXPORT) to decrypt captured traffic',
        ],
        'business_impact': [
            'Credential and session token theft from users on untrusted networks',
            'Regulatory non-compliance (PCI-DSS, HIPAA, GDPR mandate strong TLS)',
            'Reputational damage from browser security warnings on expired/self-signed certificates',
            'Loss of data confidentiality and integrity for all users of the affected service',
        ],
        'cvss_base': 7.4,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'cvss_vector_exploited': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
        'cwe': 'CWE-295, CWE-326, CWE-327',
        'owasp': 'A02:2021 – Cryptographic Failures',
        'scenario': (
            'An attacker on the same network (public Wi-Fi, rogue access point, BGP hijack) '
            'intercepts the TLS handshake. Because the server presents a weak, expired, or '
            'self-signed certificate, or accepts a deprecated protocol, the attacker can '
            'decrypt the traffic stream and extract authentication credentials or session tokens.'
        ),
    },
}

# Attack chain pairs — if both vulns are present in the same scan, note escalation
ATTACK_CHAIN_PAIRS: List[Tuple[str, str, str]] = [
    ('open_redirect', 'ssrf', 'Open Redirect can be chained with SSRF to bypass allowlist filters, '
     'enabling access to internal services or cloud metadata endpoints.'),
    ('xss', 'csrf', 'XSS can be used to exfiltrate CSRF tokens, making CSRF protections '
     'ineffective and enabling all CSRF attack scenarios.'),
    ('lfi', 'rce', 'LFI via log poisoning can be escalated to Remote Code Execution '
     'by injecting PHP/code into an accessible log file then including it.'),
    ('ssrf', 'rce', 'SSRF can be used to reach internal services (Redis, Memcached, '
     'Jenkins) and escalate to Remote Code Execution.'),
    ('info_disclosure', 'sqli', 'Information Disclosure may reveal database schema or '
     'technology stack details that make SQL Injection exploitation significantly easier.'),
    ('cors', 'xss', 'CORS misconfiguration combined with XSS on any subdomain enables '
     'full cross-origin data exfiltration from authenticated API sessions.'),
    ('host_header', 'cache_poisoning', 'Host Header Injection can be chained with Cache Poisoning '
     'to serve malicious responses to all users from the same cached entry.'),
    ('crlf', 'xss', 'CRLF Injection enabling response splitting can be escalated to '
     'XSS by injecting a malicious HTML body in the split response.'),
    ('jwt', 'idor', 'JWT vulnerability allowing claim manipulation combined with IDOR '
     'enables accessing other users\' data without knowing their IDs.'),
    ('open_redirect', 'xss', 'Open Redirect can facilitate XSS by redirecting victims '
     'to attacker-controlled pages that mimic the legitimate site.'),
]

SEVERITY_ADJECTIVES = {
    'critical': 'Critical',
    'high': 'High-Severity',
    'medium': 'Medium-Severity',
    'low': 'Low-Severity',
}

REMEDIATION_DEFAULTS: Dict[str, str] = {
    'xss': 'Encode all user-supplied data before rendering in HTML/JS context. '
           'Implement a strict Content-Security-Policy (CSP). Use context-aware output encoding.',
    'sqli': 'Use parameterized queries (prepared statements) for all database interactions. '
            'Never concatenate user input into SQL strings. Apply least-privilege DB accounts.',
    'csrf': 'Implement CSRF tokens (synchronizer token pattern) on all state-changing forms. '
            'Validate the Origin/Referer header as a defense-in-depth measure. '
            'Consider SameSite=Strict cookie attribute.',
    'xxe': 'Disable external entity processing in the XML parser. '
           'Use a whitelist approach for allowed XML features.',
    'rce': 'Avoid passing user-supplied data to OS commands. '
           'If required, use parameterized APIs and strict allowlists. '
           'Harden server configuration and apply principle of least privilege.',
    'lfi': 'Never incorporate user-controlled paths in file include operations. '
           'Use an allowlist of permitted paths. Chroot the web process.',
    'rfi': 'Disable allow_url_include in PHP configuration. '
           'Validate all file include paths against a strict allowlist.',
    'open_redirect': 'Validate redirect targets against an allowlist of permitted URLs/domains. '
                     'Avoid client-controllable redirect parameters entirely where possible.',
    'ssrf': 'Validate and restrict outgoing requests to an allowlist. '
            'Block access to internal IP ranges (169.254.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x). '
            'Disable unused URL scheme handlers.',
    'info_disclosure': 'Disable verbose error messages in production. '
                       'Remove debug endpoints and developer comments. '
                       'Strip sensitive headers from responses.',
    'clickjacking': 'Set the X-Frame-Options: DENY or SAMEORIGIN header. '
                    'Alternatively use Content-Security-Policy: frame-ancestors directive.',
    'js_hijacking': 'Prefix JSON responses with )]}\'\\n or use non-array top-level objects. '
                    'Require proper Content-Type headers and CSRF tokens on API endpoints.',
    'idor': 'Implement server-side authorization checks for every object access. '
            'Use indirect reference maps (opaque IDs) instead of sequential integers.',
    'jwt': 'Enforce strict algorithm validation (reject alg:none). '
           'Use strong signing keys (min 256-bit for HS256). '
           'Implement proper claim validation (exp, iss, aud).',
    'crlf': 'Sanitize user input by stripping or encoding \\r and \\n characters '
            'before including them in HTTP headers or response bodies.',
    'host_header': 'Maintain a strict whitelist of allowed Host header values. '
                   'Use absolute URLs with a hardcoded domain for password reset links.',
    'smuggling': 'Ensure front-end and back-end servers use consistent HTTP parsing. '
                 'Prefer HTTP/2 end-to-end. Reject ambiguous requests with both '
                 'Content-Length and Transfer-Encoding headers.',
    'deserialization': 'Avoid deserializing untrusted data. '
                       'If required, use type-safe deserialization with strict class allowlists. '
                       'Implement integrity checks on serialized data.',
    'graphql': 'Disable introspection in production. '
               'Implement field-level authorization. '
               'Apply query depth/complexity limits to prevent DoS.',
    'websocket': 'Validate the Origin header on WebSocket upgrade requests. '
                 'Require authentication tokens for WebSocket connections. '
                 'Use CSRF protection for the upgrade handshake.',
    'cache_poisoning': 'Identify all unkeyed inputs and include them in the cache key, '
                       'or strip them. Set appropriate Cache-Control: private/no-store headers '
                       'for dynamic or authenticated responses.',
    'cors': 'Define an explicit allowlist of trusted origins. '
            'Never use Access-Control-Allow-Origin: * with credentials. '
            'Validate the Origin header server-side against the allowlist.',
    'email_rce': 'Never pass user-supplied data to OS commands. '
                'Validate and reject email addresses containing shell metacharacters. '
                'Use a dedicated mail library instead of shelling out.',
    'ai_llm': 'Sanitize user input before passing it to LLM prompts. '
              'Use separate system and user context windows. '
              'Implement output validation and content filtering on LLM responses.',
    'dos': 'Implement rate limiting and request-size limits. '
           'Use asynchronous processing for resource-intensive operations. '
           'Apply query depth and complexity limits for data-driven endpoints.',
    'security_misconfig': 'Deploy a comprehensive security header policy: '
                          'Content-Security-Policy, X-Frame-Options: DENY, '
                          'X-Content-Type-Options: nosniff, Strict-Transport-Security, '
                          'and Referrer-Policy. Automate header audits in CI.',
    'sensitive_data': 'Encrypt sensitive data at rest and in transit. '
                      'Mask or omit sensitive fields in API responses. '
                      'Audit data flows to ensure PII is not logged or cached.',
    'weak_password': 'Enforce a minimum password length of 12 characters with complexity '
                     'requirements. Implement account lockout or exponential back-off. '
                     'Offer multi-factor authentication.',
    'bac': 'Implement server-side authorization checks on every request. '
           'Use a centralized access control framework. '
           'Apply least-privilege principles to all user roles.',
    'username_enum': 'Use identical error messages and response times for all '
                     'authentication failure scenarios. '
                     'Consider rate limiting and CAPTCHA on authentication endpoints.',
    'captcha_bypass': 'Validate CAPTCHA tokens server-side on every submission. '
                      'Invalidate tokens after a single use. '
                      'Consider upgrading to invisible reCAPTCHA v3 or hCaptcha.',
    'unsafe_upload': 'Validate file type by content (magic bytes), not extension. '
                     'Store uploaded files outside the web root. '
                     'Serve files through a proxy that sets a safe Content-Disposition header.',
    'subdomain_takeover': 'Audit DNS records regularly and remove dangling CNAMEs. '
                          'Claim or delete unused third-party service entries promptly. '
                          'Monitor for unclaimed DNS records in CI/CD pipelines.',
    'exif_data': 'Strip EXIF metadata from all user-uploaded images using a library '
                 'such as Pillow or ExifTool before storing or serving them.',
    'api_key_exposure': 'Rotate exposed API keys immediately. '
                        'Store secrets in environment variables or a secrets manager, never in code. '
                        'Audit public repositories and client-side bundles for hardcoded credentials.',
    'crypto': 'Renew SSL/TLS certificates before expiry and use certificates signed by a trusted CA. '
              'Ensure the certificate CN/SAN matches every hostname served. '
              'Disable deprecated protocols: SSLv2, SSLv3, TLSv1.0, and TLSv1.1; '
              'support only TLSv1.2 and TLSv1.3. '
              'Configure cipher suites to exclude weak algorithms (NULL, EXPORT, DES, RC4, MD5, anon, 3DES). '
              'Prefer AEAD cipher suites with forward secrecy (ECDHE-RSA-AES256-GCM-SHA384, etc.). '
              'Enable HTTP Strict Transport Security (HSTS) with a long max-age.',
    'other': 'Review and remediate the identified vulnerability following '
             'OWASP secure coding guidelines.',
}


# ---------------------------------------------------------------------------
# BountyReportGenerator class
# ---------------------------------------------------------------------------

class BountyReportGenerator:
    """
    Generates submission-ready bug bounty reports from vulnerability + exploit data.

    Supports Markdown format (for Bugcrowd/HackerOne) and JSON format (for
    programmatic access). Reports are stored back onto the Vulnerability model.
    """

    def __init__(self, vulnerability) -> None:
        """
        Args:
            vulnerability: A scanner.models.Vulnerability instance.
        """
        self.vuln = vulnerability
        self.vuln_type = vulnerability.vulnerability_type
        self.impact_data = IMPACT_MAP.get(self.vuln_type, IMPACT_MAP['other'])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, fmt: str = 'markdown') -> str:
        """
        Generate the full bounty report.

        Args:
            fmt: 'markdown' or 'json'

        Returns:
            Report as a string in the requested format.
        """
        report_data = self._build_report_data()
        if fmt == 'json':
            return json.dumps(report_data, indent=2)
        return self._render_markdown(report_data)

    def save(self, fmt: str = 'markdown') -> str:
        """
        Generate the report and persist it to vulnerability.bounty_report.

        Returns:
            The generated report string.
        """
        report = self.generate(fmt=fmt)
        self.vuln.bounty_report = report
        self.vuln.save(update_fields=['bounty_report'])
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_report_data(self) -> Dict[str, Any]:
        """Assemble all report sections into a structured dict."""
        vuln = self.vuln
        impact = self.impact_data

        cvss_score, cvss_vector = self._estimate_cvss()
        title = self._build_title()
        steps = self._build_steps_to_reproduce()
        poc_evidence = self._build_poc_evidence()
        attack_chains = self._detect_attack_chains()
        remediation = vuln.remediation or REMEDIATION_DEFAULTS.get(
            self.vuln_type, REMEDIATION_DEFAULTS['other']
        )

        return {
            'title': title,
            'severity': vuln.severity,
            'vulnerability_type': self.vuln_type,
            'url': vuln.url,
            'parameter': vuln.parameter,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'cwe': impact.get('cwe', 'CWE-284'),
            'owasp': impact.get('owasp', ''),
            'impact_statement': self._build_impact_statement(),
            'business_impact': impact.get('business_impact', []),
            'attack_scenario': impact.get('scenario', ''),
            'steps_to_reproduce': steps,
            'poc_evidence': poc_evidence,
            'remediation': remediation,
            'attack_chains': attack_chains,
            'references': self._build_references(),
            'exploited': vuln.exploited,
            'verified': vuln.verified,
        }

    def _build_title(self) -> str:
        """Return an impact-focused report title."""
        template = self.impact_data.get('title_template', 'Security Vulnerability on {url}')
        severity_adj = SEVERITY_ADJECTIVES.get(self.vuln.severity, self.vuln.severity.title())
        url_path = self.vuln.url
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.vuln.url)
            url_path = parsed.path or self.vuln.url
        except Exception:
            pass
        return template.format(severity_adj=severity_adj, url=url_path)

    def _build_impact_statement(self) -> str:
        """Build the 'As an attacker, I can…' statement."""
        impacts = self.impact_data.get('attacker_impact', [])
        if not impacts:
            return 'As an attacker, I can exploit this vulnerability to perform unauthorized actions.'
        lines = ['As an attacker, I can:']
        for item in impacts:
            lines.append(f'- {item}')
        return '\n'.join(lines)

    def _build_steps_to_reproduce(self) -> List[str]:
        """Extract numbered reproduction steps from exploit data."""
        vuln = self.vuln
        steps: List[str] = []

        # Try poc_steps_json first (structured data from plugins)
        if hasattr(vuln, 'poc_steps_json') and vuln.poc_steps_json:
            try:
                raw = vuln.poc_steps_json
                if isinstance(raw, str):
                    raw = json.loads(raw)
                if isinstance(raw, list):
                    return [str(s) for s in raw]
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        # Build steps from available evidence fields
        step_num = 1

        steps.append(f'{step_num}. Navigate to: `{vuln.url}`')
        step_num += 1

        if vuln.parameter:
            steps.append(
                f'{step_num}. Locate the `{vuln.parameter}` parameter '
                f'(in URL query string, POST body, or HTTP header).'
            )
            step_num += 1

        # Add HTTP traffic info if available
        if vuln.http_traffic:
            try:
                traffic = vuln.http_traffic
                if isinstance(traffic, str):
                    traffic = json.loads(traffic)
                if isinstance(traffic, dict):
                    req = traffic.get('request', '')
                    if req:
                        steps.append(
                            f'{step_num}. Send the following HTTP request:\n```\n{req}\n```'
                        )
                        step_num += 1
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        # Add payload information
        if vuln.successful_payloads:
            payloads = vuln.successful_payloads
            if isinstance(payloads, str):
                try:
                    payloads = json.loads(payloads)
                except (json.JSONDecodeError, ValueError):
                    payloads = [payloads]
            if payloads:
                payload_list = '\n'.join(f'  - `{p}`' for p in payloads[:MAX_PAYLOADS_IN_STEPS])
                steps.append(
                    f'{step_num}. Use one of the following confirmed payloads:\n{payload_list}'
                )
                step_num += 1

        # Add evidence observation
        if vuln.evidence:
            steps.append(
                f'{step_num}. Observe the vulnerability indicator in the response: '
                f'{vuln.evidence[:300]}'
            )
            step_num += 1

        if not steps:
            steps.append('1. Reproduce according to the evidence provided in the report.')

        return steps

    def _build_poc_evidence(self) -> str:
        """Build the Proof of Concept evidence section."""
        vuln = self.vuln
        parts: List[str] = []

        if vuln.proof_of_impact:
            parts.append(f'**Proof of Impact:**\n{vuln.proof_of_impact}')

        if vuln.evidence:
            parts.append(f'**Vulnerability Evidence:**\n{vuln.evidence}')

        if vuln.http_traffic:
            try:
                traffic = vuln.http_traffic
                if isinstance(traffic, str):
                    traffic = json.loads(traffic)
                if isinstance(traffic, dict):
                    req = traffic.get('request', '')
                    resp = traffic.get('response', '')
                    if req:
                        parts.append(f'**HTTP Request:**\n```http\n{req}\n```')
                    if resp:
                        parts.append(f'**HTTP Response (excerpt):**\n```http\n{str(resp)[:1000]}\n```')
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        if vuln.successful_payloads:
            payloads = vuln.successful_payloads
            if isinstance(payloads, str):
                try:
                    payloads = json.loads(payloads)
                except (json.JSONDecodeError, ValueError):
                    payloads = [payloads]
            if payloads:
                payload_str = '\n'.join(f'- `{p}`' for p in payloads[:MAX_PAYLOADS_IN_EVIDENCE])
                parts.append(f'**Confirmed Working Payloads:**\n{payload_str}')

        if vuln.exploit_result:
            parts.append(f'**Exploitation Output:**\n```\n{vuln.exploit_result[:1000]}\n```')

        if not parts:
            parts.append('Vulnerability detected via automated scanner. Manual reproduction '
                         'recommended using the steps above.')

        return '\n\n'.join(parts)

    def _estimate_cvss(self) -> Tuple[float, str]:
        """
        Return (score, vector_string) based on vuln type and exploitation status.
        If exploited/verified, use the higher exploited vector.
        """
        impact = self.impact_data
        if self.vuln.exploited or self.vuln.verified:
            score = impact.get('cvss_base', 5.0)
            vector = impact.get('cvss_vector_exploited', impact.get('cvss_vector', ''))
            # Bump score slightly for verified exploitation
            if self.vuln.verified:
                score = min(10.0, score + VERIFIED_SCORE_BUMP)
        else:
            score = impact.get('cvss_base', 5.0)
            vector = impact.get('cvss_vector', '')

        # Adjust score by severity if very different from expected
        adj = SEVERITY_CVSS_ADJUSTMENTS.get(self.vuln.severity, 0.0)
        score = max(0.0, min(10.0, score + adj))

        return round(score, 1), vector

    def _detect_attack_chains(self) -> List[str]:
        """
        Detect potential attack chains by checking for co-occurring vuln types in same scan.
        Returns list of chain description strings.
        """
        chains: List[str] = []
        try:
            sibling_types = set(
                self.vuln.scan.vulnerabilities
                .exclude(id=self.vuln.id)
                .values_list('vulnerability_type', flat=True)
            )
            for type_a, type_b, description in ATTACK_CHAIN_PAIRS:
                if self.vuln_type in (type_a, type_b):
                    other = type_b if self.vuln_type == type_a else type_a
                    if other in sibling_types:
                        chains.append(description)
        except Exception as exc:
            logger.debug('Attack chain detection failed: %s', exc)
        return chains

    def _build_references(self) -> List[str]:
        """Build CWE and OWASP reference list."""
        impact = self.impact_data
        refs: List[str] = []
        cwe = impact.get('cwe')
        if cwe:
            refs.append(f'https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-", "")}.html')
        owasp = impact.get('owasp', '')
        if owasp:
            refs.append(f'https://owasp.org/Top10/ ({owasp})')
        refs.append('https://owasp.org/www-project-web-security-testing-guide/')
        return refs

    def _render_markdown(self, data: Dict[str, Any]) -> str:
        """Render the report data as Markdown."""
        lines: List[str] = []

        lines.append(f'# {data["title"]}')
        lines.append('')
        lines.append(f'**Severity:** {data["severity"].upper()}  ')
        lines.append(f'**CVSS Score:** {data["cvss_score"]} ({data["cvss_vector"]})  ')
        lines.append(f'**CWE:** {data["cwe"]}  ')
        lines.append(f'**OWASP:** {data["owasp"]}  ')
        lines.append(f'**Affected URL:** `{data["url"]}`  ')
        if data.get('parameter'):
            lines.append(f'**Vulnerable Parameter:** `{data["parameter"]}`  ')
        lines.append(f'**Exploitation Confirmed:** {"Yes ✓" if data["exploited"] else "No"}  ')
        lines.append('')

        lines.append('## Impact Statement')
        lines.append('')
        lines.append(data['impact_statement'])
        lines.append('')

        lines.append('## Attack Scenario')
        lines.append('')
        lines.append(data['attack_scenario'])
        lines.append('')

        lines.append('## Steps to Reproduce')
        lines.append('')
        for step in data['steps_to_reproduce']:
            lines.append(step)
        lines.append('')

        lines.append('## Proof of Concept')
        lines.append('')
        lines.append(data['poc_evidence'])
        lines.append('')

        lines.append('## Business Impact')
        lines.append('')
        for item in data['business_impact']:
            lines.append(f'- {item}')
        lines.append('')

        if data.get('attack_chains'):
            lines.append('## Attack Chain Potential (Severity Escalation)')
            lines.append('')
            lines.append(
                '> **Note:** Multiple vulnerabilities detected in this scan that can be chained '
                'to escalate impact:'
            )
            lines.append('')
            for chain in data['attack_chains']:
                lines.append(f'- {chain}')
            lines.append('')

        lines.append('## Remediation')
        lines.append('')
        lines.append(data['remediation'])
        lines.append('')

        lines.append('## References')
        lines.append('')
        for ref in data['references']:
            lines.append(f'- {ref}')
        lines.append('')

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def generate_bounty_report(vuln_id: int, fmt: str = 'markdown') -> Optional[str]:
    """
    Generate a bounty report for a single vulnerability and save it.

    Args:
        vuln_id: Primary key of the Vulnerability model instance.
        fmt: 'markdown' or 'json'

    Returns:
        The report string, or None if the vulnerability does not exist.
    """
    try:
        from scanner.models import Vulnerability
        vuln = Vulnerability.objects.get(id=vuln_id)
    except Exception as exc:
        logger.error('generate_bounty_report: vulnerability %s not found: %s', vuln_id, exc)
        return None

    generator = BountyReportGenerator(vuln)
    return generator.save(fmt=fmt)


def generate_scan_bounty_reports(scan_id: int, fmt: str = 'markdown',
                                 exploited_only: bool = True) -> Dict[str, Any]:
    """
    Generate bounty reports for all (exploited) vulnerabilities in a scan.

    Args:
        scan_id: Primary key of the Scan model instance.
        fmt: 'markdown' or 'json'
        exploited_only: If True, only generate reports for successfully exploited vulns.

    Returns:
        Dict with 'generated', 'skipped', and 'reports' keys.
    """
    try:
        from scanner.models import Scan
        scan = Scan.objects.get(id=scan_id)
    except Exception as exc:
        logger.error('generate_scan_bounty_reports: scan %s not found: %s', scan_id, exc)
        return {'error': f'Scan {scan_id} not found', 'generated': 0, 'skipped': 0, 'reports': []}

    vulns = scan.vulnerabilities.all()
    if exploited_only:
        vulns = vulns.filter(exploited=True)

    generated = 0
    skipped = 0
    reports = []

    for vuln in vulns:
        try:
            generator = BountyReportGenerator(vuln)
            report = generator.save(fmt=fmt)
            generated += 1
            reports.append({'vulnerability_id': vuln.id, 'title': generator._build_title()})
        except Exception as exc:
            logger.error('Failed to generate report for vuln %s: %s', vuln.id, exc)
            skipped += 1

    return {
        'scan_id': scan_id,
        'generated': generated,
        'skipped': skipped,
        'reports': reports,
    }
