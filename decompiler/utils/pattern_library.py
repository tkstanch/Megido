"""
Regex patterns for the decompiler app.

Comprehensive patterns for secret detection, API key formats,
vulnerability signatures, and malicious behavior indicators.
"""
import re

# --- Secret / API key patterns ---

PATTERNS_SECRETS = {
    'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'aws_secret_key': re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?[A-Za-z0-9/+=]{40}'),
    'google_api_key': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'stripe_key': re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'),
    'github_token': re.compile(r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}'),
    'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    'oauth_token': re.compile(r'(?i)oauth.{0,10}token.{0,10}[=:]\s*["\']?[A-Za-z0-9\-_.]{20,}'),
    'generic_password': re.compile(
        r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']'
    ),
    'generic_api_key': re.compile(
        r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9\-_.]{16,}["\']'
    ),
}

# --- Vulnerability patterns ---

PATTERNS_VULNERABILITIES = {
    'eval_with_input': re.compile(r'\beval\s*\([^)]*(?:request|input|user|param)', re.IGNORECASE),
    'inner_html': re.compile(r'\.innerHTML\s*[+]?='),
    'document_write': re.compile(r'document\.write\s*\('),
    'dangerously_set_html': re.compile(r'dangerouslySetInnerHTML'),
    'insecure_http': re.compile(r'http://(?!localhost|127\.0\.0\.1)'),
    'prototype_pollution': re.compile(r'__proto__\s*\[|constructor\s*\['),
    'redos': re.compile(r'\(\.\+\)\+|\(\.\*\)\+|\(\?:.*\)\+'),
    'java_reflection': re.compile(r'Class\.forName\s*\(|\.getMethod\s*\(|\.invoke\s*\('),
    'dotnet_reflection': re.compile(
        r'Assembly\.Load\s*\(|Activator\.CreateInstance\s*\('
    ),
    'js_eval': re.compile(r'\beval\s*\(|\bFunction\s*\('),
    'js_reflect': re.compile(r'Reflect\.apply\s*\(|\bwindow\s*\[\s*\w+\s*\]'),
}

# --- Malicious behavior patterns ---

PATTERNS_MALICIOUS = {
    'crypto_miner': re.compile(
        r'(?i)coinhive|cryptoloot|minero|webminer|miner\.start'
    ),
    'keylogger': re.compile(
        r'(?i)keydown|keyup|keypress.*(?:ajax|fetch|xmlhttprequest|send)'
    ),
    'clipboard_hijack': re.compile(
        r'(?i)navigator\.clipboard|document\.execCommand\s*\(\s*["\']copy'
    ),
    'ad_inject': re.compile(r'(?i)insertAdjacentHTML|appendChild.*(?:script|iframe)'),
    'exfiltration': re.compile(
        r'(?i)(?:fetch|ajax|xmlhttprequest).*(?:document\.cookie|localStorage)'
    ),
    'debugger_detect': re.compile(r'\bdebugger\b'),
    'timing_check': re.compile(r'performance\.now\s*\(\s*\)'),
}

# --- Obfuscation patterns ---

PATTERNS_OBFUSCATION = {
    'dean_edwards': re.compile(r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k'),
    'eval_encoded': re.compile(r'\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\('),
    'hex_string': re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}'),
    'unicode_escape': re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}'),
    'classloader': re.compile(r'ClassLoader|loadClass\s*\(', re.IGNORECASE),
}

# --- Network patterns ---

PATTERN_URL = re.compile(r'https?://[^\s"\'<>{}|\\^`\[\]]+')
PATTERN_WEBSOCKET = re.compile(r'wss?://[^\s"\'<>]+')
PATTERN_FETCH = re.compile(
    r'fetch\s*\(\s*["\']([^"\']+)["\']|fetch\s*\(\s*(\w+)'
)
PATTERN_XHR = re.compile(
    r'XMLHttpRequest|\.open\s*\(\s*["\']([A-Z]+)["\'],\s*["\']([^"\']+)["\']'
)
PATTERN_AXIOS = re.compile(r'axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']')
