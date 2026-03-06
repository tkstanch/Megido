"""
Bug Bounty Vulnerability Classification Taxonomy

This module defines a comprehensive mapping of vulnerability types to bug bounty
priority classifications (P-levels). P-levels reflect typical bug bounty programme
severity ratings, where P1 is the most critical and P5 is informational.

Each entry stores two P-levels:
  - ``p_level_with_poc``    – priority when a working proof-of-concept exists
  - ``p_level_without_poc`` – priority for an unverified / theoretical finding
"""

from typing import Optional

# ---------------------------------------------------------------------------
# Taxonomy data
# ---------------------------------------------------------------------------

BOUNTY_TAXONOMY: dict = {
    # -----------------------------------------------------------------------
    # Injection
    # -----------------------------------------------------------------------
    'lfi': {
        'name': 'Injection File – Inclusion – Local (LFI)',
        'category': 'Injection',
        'p_level_with_poc': 'P1',
        'p_level_without_poc': 'P3',
        'description': (
            'Local File Inclusion allows an attacker to read arbitrary files '
            'from the server filesystem, potentially exposing credentials, '
            'source code, or other sensitive data.'
        ),
    },
    'xxe': {
        'name': 'Injection – XML External Entity Injection (XXE)',
        'category': 'Injection',
        'p_level_with_poc': 'P1',
        'p_level_without_poc': 'P2',
        'description': (
            'XML External Entity injection can be exploited to read internal '
            'files, perform SSRF, or cause denial of service via entity expansion.'
        ),
    },

    # -----------------------------------------------------------------------
    # Cross-Site Scripting
    # -----------------------------------------------------------------------
    'xss': {
        'name': 'Cross-Site Scripting (XSS) – Stored',
        'category': 'Cross-Site Scripting',
        'p_level_with_poc': 'P2',
        'p_level_without_poc': 'P3',
        'description': (
            'Stored XSS persists in the application and executes in the victim\'s '
            'browser when they view the affected page, enabling session hijacking, '
            'defacement, or phishing.'
        ),
    },

    # -----------------------------------------------------------------------
    # Security Misconfiguration – DNS / Subdomain Takeover
    # -----------------------------------------------------------------------
    'subdomain_takeover_high': {
        'name': (
            'Security Misconfiguration – DNS - With POC '
            '(High Impact Subdomain Takeover)'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P2',
        'p_level_without_poc': 'P3',
        'description': (
            'A dangling DNS record points to an unclaimed external resource that '
            'can be registered by an attacker, enabling phishing, cookie theft, or '
            'bypassing Content Security Policy.'
        ),
    },
    'subdomain_takeover': {
        'name': (
            'Security Misconfiguration – DNS - With POC '
            '(Basic Subdomain Takeover)'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P3',
        'p_level_without_poc': 'P4',
        'description': (
            'A DNS record points to a resource that can be claimed by an attacker '
            'with limited impact (e.g., static hosting with no privileged cookies).'
        ),
    },

    # -----------------------------------------------------------------------
    # Sensitive Data Exposure
    # -----------------------------------------------------------------------
    'weak_password_both': {
        'name': (
            'Sensitive Data Exposure – Weak Password Policy – Complexity, '
            'Both Length and Char Type Not Enforced'
        ),
        'category': 'Sensitive Data Exposure',
        'p_level_with_poc': 'P3',
        'p_level_without_poc': 'P5',
        'description': (
            'The application does not enforce minimum password length or character '
            'type diversity, significantly increasing the risk of brute-force attacks.'
        ),
    },
    'exif_data_auto': {
        'name': (
            'Sensitive Data Exposure – EXIF Geolocation Data Not Stripped '
            'From Uploaded Images – Automatic User Enumeration'
        ),
        'category': 'Sensitive Data Exposure',
        'p_level_with_poc': 'P3',
        'p_level_without_poc': 'P5',
        'description': (
            'Uploaded images retain GPS EXIF metadata and user information can be '
            'extracted automatically, leaking physical location data.'
        ),
    },
    'exif_data': {
        'name': (
            'Sensitive Data Exposure – EXIF Geolocation Data Not Stripped '
            'From Uploaded Images – Manual User Enumeration'
        ),
        'category': 'Sensitive Data Exposure',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'Uploaded images retain GPS EXIF metadata, requiring manual steps to '
            'enumerate affected users, leaking physical location data.'
        ),
    },
    'api_key_exposure': {
        'name': 'Sensitive Data Exposure – Private API Keys – No POC',
        'category': 'Sensitive Data Exposure',
        'p_level_with_poc': 'P1',
        'p_level_without_poc': 'P5',
        'description': (
            'Private API keys have been identified in the application but no '
            'working proof-of-concept demonstrating misuse has been provided.'
        ),
    },

    # -----------------------------------------------------------------------
    # Security Misconfiguration – Password / Account management
    # -----------------------------------------------------------------------
    'lack_password_confirm_email': {
        'name': (
            'Security Misconfiguration – Lack of Password Confirmation '
            '- Change Email Address'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The application does not require the current password before allowing '
            'a user to change their email address, enabling account takeover if a '
            'session is compromised.'
        ),
    },
    'lack_password_confirm_password': {
        'name': (
            'Security Misconfiguration – Lack of Password Confirmation '
            '- Change Password'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The application does not require the current password before setting '
            'a new one, enabling account takeover if a session is compromised.'
        ),
    },
    'lack_password_confirm_delete': {
        'name': (
            'Security Misconfiguration – Lack of Password Confirmation '
            '- Delete Account'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The application does not require password re-entry before deleting an '
            'account, enabling account destruction if a session is compromised.'
        ),
    },
    'unsafe_upload': {
        'name': (
            'Security Misconfiguration – Unsafe File Upload – No Antivirus'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The file upload endpoint does not scan uploaded files for malware, '
            'allowing distribution of malicious content to other users.'
        ),
    },
    'unsafe_upload_size': {
        'name': (
            'Security Misconfiguration – Unsafe File Upload – No Size Limit'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The file upload endpoint does not enforce a maximum file size, '
            'potentially enabling disk exhaustion or denial of service.'
        ),
    },
    'weak_password_length': {
        'name': (
            'Security Misconfiguration – Weak Password Policy – Complexity, '
            'Length Not Enforced'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The application does not enforce a minimum password length, '
            'allowing trivially short passwords.'
        ),
    },
    'weak_password': {
        'name': (
            'Security Misconfiguration – Weak Password Policy – Complexity, '
            'Char Type Not Enforced'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The application does not require a mix of character types '
            '(uppercase, digits, symbols) in passwords.'
        ),
    },
    'weak_reset_token': {
        'name': (
            'Security Misconfiguration – Weak Reset Password Policy – '
            'Token is Not Invalidated After Use'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'Password reset tokens remain valid after they have been used, '
            'enabling replay attacks.'
        ),
    },
    'captcha_bypass': {
        'name': (
            'Security Misconfiguration – Captcha Bypass – '
            'Implementation Vulnerability'
        ),
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The CAPTCHA implementation contains a vulnerability that allows it '
            'to be bypassed programmatically.'
        ),
    },

    # -----------------------------------------------------------------------
    # Missing Function Level Access Control / Enumeration
    # -----------------------------------------------------------------------
    'username_enum': {
        'name': (
            'Missing Function Level Access Control – '
            'Username Enumeration – Data Leak'
        ),
        'category': 'Missing Function Level Access Control',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'The application leaks whether a username or email is registered, '
            'facilitating targeted attacks.'
        ),
    },

    # -----------------------------------------------------------------------
    # Denial of Service
    # -----------------------------------------------------------------------
    'dos': {
        'name': (
            'Application-Level Denial-of-Service (DoS) – Low Impact and/or '
            'Medium Difficulty – Password Length DoS (Server-Side)'
        ),
        'category': 'Denial of Service',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'An attacker can send an extremely long password string to the '
            'authentication endpoint, causing excessive CPU/memory consumption '
            'during hashing and degrading service availability.'
        ),
    },

    # -----------------------------------------------------------------------
    # Broken Access Control
    # -----------------------------------------------------------------------
    'bac': {
        'name': (
            'Broken Access Control (BAC) - '
            'Username/Email Enumeration - Non-Brute Force'
        ),
        'category': 'Broken Access Control',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'A non-brute-force technique (e.g., differential error messages or '
            'timing side-channels) exposes whether a username or email is '
            'registered in the system.'
        ),
    },
    'security_misconfig': {
        'name': 'Security Misconfiguration',
        'category': 'Security Misconfiguration',
        'p_level_with_poc': 'P4',
        'p_level_without_poc': 'P5',
        'description': (
            'A generic security misconfiguration has been detected. Refer to '
            'specific findings for details.'
        ),
    },
    'sensitive_data': {
        'name': 'Sensitive Data Exposure',
        'category': 'Sensitive Data Exposure',
        'p_level_with_poc': 'P3',
        'p_level_without_poc': 'P5',
        'description': (
            'Sensitive information is exposed, such as credentials, private keys, '
            'or personally identifiable information.'
        ),
    },
}

# Vulnerability types that are DoS-related (used to filter when DoS is disabled)
_DOS_VULNERABILITY_TYPES: frozenset = frozenset({'dos'})


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_bounty_classification(vuln_type: str, verified: bool = False) -> Optional[str]:
    """Return the appropriate P-level for *vuln_type*.

    Args:
        vuln_type: The vulnerability type identifier (matches keys in
            ``BOUNTY_TAXONOMY`` and values in ``Vulnerability.VULNERABILITY_TYPES``).
        verified: If ``True``, return the *with-PoC* P-level; otherwise return
            the *without-PoC* P-level.

    Returns:
        A string such as ``'P1'``, ``'P2'``, … ``'P5'``, or ``None`` if the
        vulnerability type is not present in the taxonomy.
    """
    entry = BOUNTY_TAXONOMY.get(vuln_type)
    if entry is None:
        return None
    if verified:
        return entry['p_level_with_poc']
    return entry['p_level_without_poc']


def get_all_classifications() -> dict:
    """Return a copy of the full taxonomy dictionary."""
    return dict(BOUNTY_TAXONOMY)


def is_dos_vulnerability(vuln_type: str) -> bool:
    """Return ``True`` if *vuln_type* is a Denial-of-Service-related test.

    This helper is used to conditionally skip DoS-related plugins when the
    user has not explicitly opted in to DoS testing.

    Args:
        vuln_type: The vulnerability type identifier string.

    Returns:
        ``True`` when the type is DoS-related, ``False`` otherwise.
    """
    return vuln_type in _DOS_VULNERABILITY_TYPES
