"""
Insecure Deserialization Detector Plugin

Detects insecure deserialization vulnerabilities by identifying serialized
object signatures in URL parameters, cookies, request bodies, and headers.

Covers Java (ObjectInputStream), Python (pickle), and PHP (unserialize).

CWE-502 (Deserialization of Untrusted Data)
"""

import base64
import logging
import re
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Serialized object signatures
# ---------------------------------------------------------------------------

# Java: ObjectInputStream magic bytes (0xACED 0x0005), often base64-encoded
_JAVA_MAGIC_BYTES = b'\xac\xed\x00\x05'
_JAVA_MAGIC_B64_PREFIXES = (
    'rO0',    # standard base64 of \xac\xed\x00\x05
    '/w0',    # urlsafe base64 variant
)

# Python pickle opcodes – MARK, GLOBAL, REDUCE all indicate a pickle stream
_PYTHON_PICKLE_OPCODES = re.compile(rb'[\x80-\x8c][\x00-\x05]|[cgidlp]')

# PHP serialised strings: s:N:"..."; a:N:{...} O:N:"..."
_PHP_SERIAL_RE = re.compile(
    r'(?:^|[&;])(?:[a-zA-Z_][a-zA-Z0-9_]*)='
    r'(?:s:\d+:"[^"]*";|a:\d+:\{|O:\d+:"[^"]*":\d+:\{|b:[01];|i:\d+;|d:\d+(?:\.\d+)?;)',
    re.MULTILINE,
)

# Simpler pattern for PHP serialised data in parameter values
_PHP_SERIAL_SIMPLE_RE = re.compile(
    r'^(?:s:\d+:".*?";|a:\d+:\{|O:\d+:"[^"]*":\d+:\{|i:\d+;|b:[01];)',
    re.DOTALL,
)

_REMEDIATION = (
    "Never deserialize data from untrusted sources without validation. "
    "Use safe serialization formats (JSON, XML with schema validation) rather "
    "than language-native serialization where possible. If native serialization "
    "is required, implement integrity checks (HMAC signatures) before deserializing. "
    "Use deserialization filters (Java: ObjectInputFilter; PHP: allowed_classes) "
    "to restrict which classes can be instantiated. Monitor for deserialization "
    "gadget chains using tools such as ysoserial."
)


class DeserializationDetectorPlugin(BaseScanPlugin):
    """
    Insecure deserialization detection plugin.

    Analyses GET/POST parameters, cookies, and common headers for serialized
    object signatures from Java, Python (pickle), and PHP.
    """

    @property
    def plugin_id(self) -> str:
        return 'deserialization_detector'

    @property
    def name(self) -> str:
        return 'Insecure Deserialization Detector'

    @property
    def description(self) -> str:
        return (
            'Detects insecure deserialization vulnerabilities by identifying '
            'Java, Python pickle, and PHP serialized object signatures in '
            'parameters, cookies, and headers'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['deserialization']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for insecure deserialization indicators.

        Args:
            url:    Target URL.
            config: Optional dict with keys:
                      verify_ssl (bool, default False)
                      timeout    (int,  default 10)

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping deserialization scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)

            response = requests.get(url, timeout=timeout, verify=verify_ssl)

            # Analyse query parameters
            from urllib.parse import parse_qs, urlparse
            qs_params = parse_qs(urlparse(url).query)
            for param, values in qs_params.items():
                for value in values:
                    finding = self._check_value(url, f'GET parameter: {param}', value)
                    if finding:
                        findings.append(finding)

            # Analyse cookies received from the server
            for cookie in response.cookies:
                finding = self._check_value(url, f'Cookie: {cookie.name}', cookie.value)
                if finding:
                    findings.append(finding)

            # Analyse response body for echoed serialized data
            body_finding = self._check_response_body(url, response.text)
            if body_finding:
                findings.append(body_finding)

        except requests.RequestException as exc:
            logger.error("Network error during deserialization scan of %s: %s", url, exc)
        except Exception as exc:
            logger.error("Unexpected error during deserialization scan of %s: %s", url, exc)

        logger.info("Deserialization scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _check_value(
        self, url: str, location: str, value: str
    ) -> Optional[VulnerabilityFinding]:
        """Check a string value for serialized object signatures."""
        if not value:
            return None

        # Attempt to base64-decode and check for Java magic bytes
        java_finding = self._detect_java(url, location, value)
        if java_finding:
            return java_finding

        # Check for Python pickle signatures (raw or base64)
        pickle_finding = self._detect_pickle(url, location, value)
        if pickle_finding:
            return pickle_finding

        # Check for PHP serialized data
        php_finding = self._detect_php(url, location, value)
        if php_finding:
            return php_finding

        return None

    def _detect_java(
        self, url: str, location: str, value: str
    ) -> Optional[VulnerabilityFinding]:
        """Detect Java serialized objects (ObjectInputStream magic bytes)."""
        # Direct check for base64 prefix of magic bytes
        if any(value.startswith(prefix) for prefix in _JAVA_MAGIC_B64_PREFIXES):
            return VulnerabilityFinding(
                vulnerability_type='deserialization',
                severity='critical',
                url=url,
                description=(
                    f'Java serialized object detected in {location}. '
                    'If deserialized server-side without validation, this is '
                    'exploitable for remote code execution via gadget chains.'
                ),
                evidence=(
                    f'Location: {location} | '
                    f'Value prefix: {value[:32]!r} | '
                    f'Signature: Java ObjectInputStream magic bytes (base64: rO0…)'
                ),
                remediation=_REMEDIATION,
                confidence=0.90,
                cwe_id='CWE-502',
            )

        # Try decoding and checking raw bytes
        try:
            decoded = base64.b64decode(value + '==')
            if decoded.startswith(_JAVA_MAGIC_BYTES):
                return VulnerabilityFinding(
                    vulnerability_type='deserialization',
                    severity='critical',
                    url=url,
                    description=(
                        f'Java serialized object detected in {location} '
                        '(base64-decoded). Potential remote code execution risk.'
                    ),
                    evidence=(
                        f'Location: {location} | '
                        f'Decoded magic bytes: {decoded[:4].hex()}'
                    ),
                    remediation=_REMEDIATION,
                    confidence=0.90,
                    cwe_id='CWE-502',
                )
        except Exception:
            pass

        return None

    def _detect_pickle(
        self, url: str, location: str, value: str
    ) -> Optional[VulnerabilityFinding]:
        """Detect Python pickle streams (raw or base64-encoded)."""
        # Try base64-decoding first
        for attempt in [value, value + '==']:
            try:
                decoded = base64.b64decode(attempt)
                if len(decoded) > 2 and _PYTHON_PICKLE_OPCODES.match(decoded):
                    return VulnerabilityFinding(
                        vulnerability_type='deserialization',
                        severity='critical',
                        url=url,
                        description=(
                            f'Python pickle stream detected in {location}. '
                            'Deserializing untrusted pickle data allows arbitrary '
                            'code execution.'
                        ),
                        evidence=(
                            f'Location: {location} | '
                            f'Decoded byte prefix: {decoded[:8].hex()}'
                        ),
                        remediation=_REMEDIATION,
                        confidence=0.85,
                        cwe_id='CWE-502',
                    )
            except Exception:
                pass

        return None

    def _detect_php(
        self, url: str, location: str, value: str
    ) -> Optional[VulnerabilityFinding]:
        """Detect PHP serialized data patterns."""
        if _PHP_SERIAL_SIMPLE_RE.match(value):
            return VulnerabilityFinding(
                vulnerability_type='deserialization',
                severity='critical',
                url=url,
                description=(
                    f'PHP serialized data detected in {location}. '
                    'If passed to unserialize() without validation, this may '
                    'allow object injection or remote code execution via POP chains.'
                ),
                evidence=(
                    f'Location: {location} | '
                    f'Value preview: {value[:64]!r}'
                ),
                remediation=_REMEDIATION,
                confidence=0.85,
                cwe_id='CWE-502',
            )
        return None

    def _check_response_body(
        self, url: str, body: str
    ) -> Optional[VulnerabilityFinding]:
        """Check the response body for echoed serialized data patterns."""
        if not body:
            return None
        if _PHP_SERIAL_RE.search(body):
            return VulnerabilityFinding(
                vulnerability_type='deserialization',
                severity='high',
                url=url,
                description=(
                    'PHP serialized data pattern found in response body. '
                    'The application may be exposing serialized objects that '
                    'could be manipulated and re-submitted.'
                ),
                evidence=(
                    f'PHP serialized object pattern detected in response body at {url}'
                ),
                remediation=_REMEDIATION,
                confidence=0.70,
                cwe_id='CWE-502',
            )
        return None

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for deserialization scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
