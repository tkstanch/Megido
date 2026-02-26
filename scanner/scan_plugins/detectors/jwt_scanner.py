"""
JWT (JSON Web Token) Security Scanner Plugin

Detects JWT security vulnerabilities including:
- Algorithm confusion / alg:none attacks
- Weak signing algorithms (HS256 with short keys, RS256 → HS256 confusion)
- Missing expiration (exp) claim
- Key confusion attacks (RS256 → HS256)
- Sensitive data exposure in JWT claims
- JWTs detected in Authorization headers, cookies, and response bodies

CWE-347 (Improper Verification of Cryptographic Signature)
"""

import base64
import json
import logging
import re
from typing import Dict, List, Any, Optional, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# Regex to extract JWT-like strings (three base64url-encoded parts separated by dots)
_JWT_PATTERN = re.compile(
    r'\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)\b'
)

# Weak algorithms
_WEAK_ALGORITHMS = {'none', 'hs256', 'hs1'}

# Sensitive claim keys that should not be in JWTs (potential data exposure)
_SENSITIVE_CLAIM_KEYS = {
    'password', 'passwd', 'secret', 'credit_card', 'ssn',
    'api_key', 'apikey', 'private_key', 'access_token',
    'refresh_token', 'cvv', 'pin',
}

_REMEDIATION_ALG_NONE = (
    "Reject JWTs with 'alg: none'. The server must explicitly whitelist acceptable "
    "algorithms and refuse tokens that specify 'none' or variants ('NONE', 'None'). "
    "Always verify the signature server-side using a trusted key."
)

_REMEDIATION_WEAK_ALG = (
    "Use strong asymmetric algorithms such as RS256 or ES256 for JWTs that cross "
    "trust boundaries. If using HMAC (HS256), ensure the secret key is at least "
    "256 bits of high-entropy random data and is kept secret."
)

_REMEDIATION_NO_EXP = (
    "Always include an 'exp' (expiration time) claim in JWTs. Set a short expiry "
    "appropriate to the token's purpose (e.g., access tokens: 15 minutes, refresh "
    "tokens: hours/days with revocation support)."
)

_REMEDIATION_KEY_CONFUSION = (
    "Prevent RS256→HS256 key confusion by: (1) explicitly verifying the 'alg' "
    "header against the expected algorithm before signature verification, and "
    "(2) never using a public key as an HMAC secret. Use algorithm-aware JWT "
    "libraries and configure them with explicit algorithm allowlists."
)

_REMEDIATION_SENSITIVE_DATA = (
    "Do not store sensitive information in JWT claims. JWTs are base64-encoded and "
    "easily decoded without a key. Store only non-sensitive identifiers in the JWT "
    "and look up sensitive data server-side."
)


def _b64url_decode(data: str) -> bytes:
    """Decode a base64url-encoded string, adding padding as needed."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def _decode_jwt(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    """
    Decode a JWT without verifying its signature.

    Returns (header_dict, payload_dict, signature_b64) or None on failure.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


class JWTScannerPlugin(BaseScanPlugin):
    """
    JWT security scanner plugin.

    Extracts JWTs from Authorization headers, cookies, and response bodies,
    then analyses them for common security flaws.
    """

    @property
    def plugin_id(self) -> str:
        return 'jwt_scanner'

    @property
    def name(self) -> str:
        return 'JWT Security Scanner'

    @property
    def description(self) -> str:
        return (
            'Detects JWT security vulnerabilities including alg:none attacks, '
            'weak algorithms, missing expiry, key confusion, and sensitive data exposure'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['jwt']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for JWT security vulnerabilities.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl        (bool, default False)
                      timeout           (int,  default 10)
                      test_alg_none     (bool, default True)
                      test_no_exp       (bool, default True)
                      test_sensitive    (bool, default True)
                      test_weak_alg     (bool, default True)
                      test_key_confusion (bool, default True)

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping JWT scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            response = requests.get(url, timeout=timeout, verify=verify_ssl)

            # Collect JWTs from multiple sources
            tokens = self._extract_tokens(response)

            for token_source, token in tokens:
                decoded = _decode_jwt(token)
                if not decoded:
                    continue
                header, payload, signature = decoded
                findings.extend(
                    self._analyse_token(url, token, token_source, header, payload, config)
                )

        except requests.RequestException as exc:
            logger.error("Network error during JWT scan of %s: %s", url, exc)
        except Exception as exc:
            logger.error("Unexpected error during JWT scan of %s: %s", url, exc)

        # Deduplicate by (description prefix, url)
        seen: set = set()
        unique: List[VulnerabilityFinding] = []
        for f in findings:
            key = (f.description[:80], f.url)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        logger.info("JWT scan of %s – %d finding(s)", url, len(unique))
        return unique

    # ------------------------------------------------------------------
    # Token extraction
    # ------------------------------------------------------------------

    def _extract_tokens(self, response: 'requests.Response') -> List[Tuple[str, str]]:
        """
        Extract JWT tokens from the response headers, cookies, and body.

        Returns a list of (source_description, token_string) tuples.
        """
        tokens: List[Tuple[str, str]] = []

        # Authorization header in request echo / response
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            tokens.append(('Authorization header', auth_header[7:].strip()))

        # Cookies
        for cookie in response.cookies:
            match = _JWT_PATTERN.search(cookie.value)
            if match:
                tokens.append((f'Cookie: {cookie.name}', match.group(1)))

        # Response body
        for match in _JWT_PATTERN.finditer(response.text):
            tokens.append(('Response body', match.group(1)))

        return tokens

    # ------------------------------------------------------------------
    # Token analysis
    # ------------------------------------------------------------------

    def _analyse_token(
        self,
        url: str,
        token: str,
        source: str,
        header: Dict,
        payload: Dict,
        config: Dict[str, Any],
    ) -> List[VulnerabilityFinding]:
        """Run all configured checks against a single decoded JWT."""
        findings: List[VulnerabilityFinding] = []
        alg = str(header.get('alg', '')).lower()

        if config.get('test_alg_none', True) and alg == 'none':
            findings.append(VulnerabilityFinding(
                vulnerability_type='jwt',
                severity='critical',
                url=url,
                description=(
                    f'JWT with alg:none detected (source: {source}). '
                    'The token has no signature – any party can forge it.'
                ),
                evidence=(
                    f'Source: {source} | '
                    f'Header: {json.dumps(header)} | '
                    f'Payload: {json.dumps(payload)}'
                ),
                remediation=_REMEDIATION_ALG_NONE,
                confidence=0.95,
                cwe_id='CWE-347',
                verified=True,
            ))

        if config.get('test_weak_alg', True) and alg in _WEAK_ALGORITHMS and alg != 'none':
            findings.append(VulnerabilityFinding(
                vulnerability_type='jwt',
                severity='high',
                url=url,
                description=(
                    f'JWT uses weak signing algorithm "{header.get("alg")}" '
                    f'(source: {source}). HMAC-based algorithms are susceptible '
                    'to brute-force if the secret is short or predictable.'
                ),
                evidence=(
                    f'Source: {source} | '
                    f'Algorithm: {header.get("alg")} | '
                    f'Header: {json.dumps(header)}'
                ),
                remediation=_REMEDIATION_WEAK_ALG,
                confidence=0.85,
                cwe_id='CWE-347',
            ))

        if config.get('test_no_exp', True) and 'exp' not in payload:
            findings.append(VulnerabilityFinding(
                vulnerability_type='jwt',
                severity='medium',
                url=url,
                description=(
                    f'JWT missing "exp" (expiration) claim (source: {source}). '
                    'The token never expires and can be replayed indefinitely.'
                ),
                evidence=(
                    f'Source: {source} | '
                    f'Payload claims: {list(payload.keys())}'
                ),
                remediation=_REMEDIATION_NO_EXP,
                confidence=0.90,
                cwe_id='CWE-347',
            ))

        if config.get('test_key_confusion', True) and alg in ('rs256', 'rs384', 'rs512'):
            findings.append(VulnerabilityFinding(
                vulnerability_type='jwt',
                severity='high',
                url=url,
                description=(
                    f'JWT uses RSA algorithm "{header.get("alg")}" (source: {source}). '
                    'Verify the server rejects tokens where "alg" has been switched '
                    'to HS256 (RS256→HS256 key confusion attack).'
                ),
                evidence=(
                    f'Source: {source} | '
                    f'Algorithm: {header.get("alg")} | '
                    f'Header: {json.dumps(header)}'
                ),
                remediation=_REMEDIATION_KEY_CONFUSION,
                confidence=0.65,
                cwe_id='CWE-347',
            ))

        if config.get('test_sensitive', True):
            exposed = [k for k in payload if k.lower() in _SENSITIVE_CLAIM_KEYS]
            if exposed:
                findings.append(VulnerabilityFinding(
                    vulnerability_type='jwt',
                    severity='medium',
                    url=url,
                    description=(
                        f'JWT payload contains potentially sensitive claim(s): '
                        f'{", ".join(exposed)} (source: {source}).'
                    ),
                    evidence=(
                        f'Source: {source} | '
                        f'Sensitive claims found: {exposed} | '
                        f'Full payload: {json.dumps(payload)}'
                    ),
                    remediation=_REMEDIATION_SENSITIVE_DATA,
                    confidence=0.80,
                    cwe_id='CWE-347',
                ))

        return findings

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for JWT scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'test_alg_none': True,
            'test_no_exp': True,
            'test_sensitive': True,
            'test_weak_alg': True,
            'test_key_confusion': True,
        }
