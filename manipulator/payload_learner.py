"""
Self-Learning Payload Database.
Handles payload import, auto-classification, effectiveness tracking, and deduplication.
"""
import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Maximum character length used for auto-generated payload names in the DB
PAYLOAD_NAME_MAX_LENGTH = 50

CLASSIFICATION_PATTERNS = {
    'XSS': [
        r'<script', r'javascript:', r'onerror=', r'onload=', r'alert\(', r'prompt\(',
        r'confirm\(', r'<svg', r'<img.*on', r'&#', r'&lt;script',
    ],
    'SQLi': [
        r"'\s*or\s*", r"'\s*and\s*", r'union\s+select', r'select\s+.*from',
        r'insert\s+into', r'drop\s+table', r'--\s*$', r';\s*--',
        r'1=1', r"1'\s*=\s*'1", r'sleep\(\d+\)', r'waitfor\s+delay',
        r'pg_sleep', r'benchmark\(',
    ],
    'LFI': [
        r'\.\./\.\./', r'\.\.\\', r'/etc/passwd', r'/etc/shadow',
        r'php://filter', r'php://input', r'data://', r'expect://',
        r'file://', r'/proc/self',
    ],
    'RCE': [
        r'system\(', r'exec\(', r'shell_exec\(', r'passthru\(',
        r'popen\(', r'proc_open\(', r'\$\{.*\}', r'`.*`',
        r'Runtime\.exec', r'os\.system', r'subprocess\.',
    ],
    'Command Injection': [
        r';\s*\w+', r'\|\s*\w+', r'&&\s*\w+', r'\|\|\s*\w+',
        r'`\w+`', r'\$\(.*\)', r'ping\s+-[cn]', r'whoami', r'id\s*$',
        r'cat\s+/', r'ls\s+-',
    ],
    'SSRF': [
        r'http://localhost', r'http://127\.', r'http://169\.254\.',
        r'file://', r'dict://', r'gopher://', r'http://0\.0\.0\.0',
        r'@localhost', r'@127\.', r'metadata\.google', r'169\.254\.169\.254',
    ],
    'XXE': [
        r'<!ENTITY', r'<!DOCTYPE.*\[', r'SYSTEM\s+"', r'PUBLIC\s+"',
        r'file:///etc', r'php://filter.*convert',
    ],
    'SSTI': [
        r'\{\{.*\}\}', r'\{%.*%\}', r'\${.*}', r'#\{.*\}',
        r'__class__', r'__mro__', r'__subclasses__',
        r'7\*7', r'49', r'config\.items',
    ],
    'Open Redirect': [
        r'http[s]?://', r'//[a-z]', r'url=http', r'redirect=http',
        r'next=http', r'return=http', r'goto=http',
    ],
    'CSRF': [
        r'<form.*action=', r'fetch\(', r'XMLHttpRequest', r'\.send\(',
        r'csrf', r'xsrf',
    ],
    'LDAP Injection': [
        r'\*\)\(', r'\|\(', r'&\(', r'!\(', r'objectClass=',
        r'cn=.*,', r'dc=',
    ],
    'Path Traversal': [
        r'%2e%2e', r'%252e', r'\.\./', r'\.\.\\',
    ],
    'CRLF Injection': [
        r'%0d%0a', r'%0a', r'\\r\\n', r'Content-Type:',
        r'Set-Cookie:', r'Location:',
    ],
}


class PayloadLearner:
    """
    Self-learning payload management system.
    Handles classification, import, deduplication, and effectiveness tracking.
    """

    def __init__(self):
        self._compiled_patterns = {}
        for vuln_type, patterns in CLASSIFICATION_PATTERNS.items():
            self._compiled_patterns[vuln_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def classify_payload(self, payload_text: str) -> str:
        """
        Auto-classify a payload into a vulnerability type.
        Returns the most likely vulnerability type or 'Unknown'.
        """
        scores = {}
        for vuln_type, patterns in self._compiled_patterns.items():
            score = sum(1 for p in patterns if p.search(payload_text))
            if score > 0:
                scores[vuln_type] = score

        if not scores:
            return 'Unknown'

        return max(scores, key=scores.get)

    def parse_payload_list(self, text: str) -> List[str]:
        """
        Parse a text block into individual payloads (one per line).
        Filters out comments and empty lines.
        """
        payloads = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                payloads.append(line)
        return payloads

    def deduplicate(self, payloads: List[str]) -> List[str]:
        """Remove duplicate payloads while preserving order."""
        seen = set()
        result = []
        for p in payloads:
            normalized = p.strip().lower()
            if normalized not in seen:
                seen.add(normalized)
                result.append(p)
        return result

    def import_payloads(self, text: str, vuln_type_override: Optional[str] = None) -> Dict:
        """
        Import payloads from a text block.

        Returns dict with:
          - payloads: list of (payload_text, classified_vuln_type) tuples
          - total: int
          - by_type: dict mapping vuln_type -> count
        """
        raw_payloads = self.parse_payload_list(text)
        deduped = self.deduplicate(raw_payloads)

        result_payloads = []
        by_type = {}

        for payload in deduped:
            if vuln_type_override:
                vuln_type = vuln_type_override
            else:
                vuln_type = self.classify_payload(payload)

            result_payloads.append((payload, vuln_type))
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        return {
            'payloads': result_payloads,
            'total': len(result_payloads),
            'by_type': by_type,
        }

    def update_effectiveness(self, payload_id: int, success: bool) -> None:
        """Update the effectiveness/success rate of a payload."""
        from .models import Payload
        try:
            payload = Payload.objects.get(id=payload_id)
            if success:
                payload.success_rate = min(100, payload.success_rate + 5)
            else:
                payload.success_rate = max(0, payload.success_rate - 1)
            payload.save(update_fields=['success_rate'])
        except Exception as e:
            logger.debug(f"Failed to update payload effectiveness: {e}")

    def get_top_payloads(self, vuln_type_name: str, limit: int = 20) -> List:
        """Get the most effective payloads for a vulnerability type."""
        from .models import Payload
        return list(
            Payload.objects.filter(vulnerability__name=vuln_type_name)
            .order_by('-success_rate', '-created_at')[:limit]
        )

    def save_imported_payloads(self, payloads: List[Tuple[str, str]],
                                source_name: str = 'Imported') -> Dict:
        """
        Save imported payloads to the database.
        Returns dict with saved count and skipped count.
        """
        from .models import Payload, VulnerabilityType

        saved = 0
        skipped = 0

        for payload_text, vuln_type_name in payloads:
            try:
                vuln_type, _ = VulnerabilityType.objects.get_or_create(
                    name=vuln_type_name,
                    defaults={
                        'description': f'Auto-created for imported payload',
                        'category': 'injection',
                        'severity': 'high',
                    }
                )

                exists = Payload.objects.filter(
                    vulnerability=vuln_type,
                    payload_text=payload_text
                ).exists()

                if exists:
                    skipped += 1
                    continue

                Payload.objects.create(
                    vulnerability=vuln_type,
                    name=payload_text[:PAYLOAD_NAME_MAX_LENGTH] + ('...' if len(payload_text) > PAYLOAD_NAME_MAX_LENGTH else ''),
                    payload_text=payload_text,
                    description=f'Imported from {source_name}',
                    is_custom=True,
                    submitted_by='import',
                )
                saved += 1
            except Exception as e:
                logger.warning(f"Failed to save payload '{payload_text[:30]}': {e}")
                skipped += 1

        return {'saved': saved, 'skipped': skipped}
