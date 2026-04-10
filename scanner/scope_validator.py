"""
Scope Validator for the Megido Vulnerability Scanner.

Validates a target URL against a ProgramScope instance to ensure scans
respect bug bounty program rules and authorized penetration testing boundaries.
"""

import urllib.parse
from typing import Optional


def _extract_hostname(url: str) -> str:
    """Return the hostname (lowercased) from a URL string, or the raw string if unparseable."""
    try:
        parsed = urllib.parse.urlparse(url)
        return (parsed.hostname or url).lower()
    except Exception:
        return url.lower()


def _domain_matches(hostname: str, pattern: str) -> bool:
    """
    Return True if *hostname* matches *pattern*.

    Patterns may be:
    - Exact domain names: ``"example.com"``
    - Wildcard subdomains: ``"*.example.com"``  (matches any single-level sub)
    - Full URLs — only the hostname portion is extracted before comparison.

    Matching is case-insensitive. Wildcard patterns only match a single level
    of subdomain (e.g. ``*.example.com`` matches ``sub.example.com`` but NOT
    ``a.b.example.com``).
    """
    hostname = hostname.lower()
    pattern_host = _extract_hostname(pattern)

    # Handle wildcard subdomain patterns like *.example.com
    if pattern_host.startswith('*.'):
        base = pattern_host[2:]  # everything after '*.'
        # hostname must end with '.base' and have exactly one extra label
        if hostname == base:
            return False
        if hostname.endswith('.' + base):
            prefix = hostname[:-(len(base) + 1)]  # strip the trailing .base
            # Allow only a single label (no extra dots in prefix)
            return '.' not in prefix
        return False

    return hostname == pattern_host


def _is_domain_in_list(url: str, domain_list: list) -> bool:
    """Return True if the URL's hostname matches any entry in *domain_list*."""
    if not domain_list:
        return False
    hostname = _extract_hostname(url)
    return any(_domain_matches(hostname, pattern) for pattern in domain_list)


class ScopeValidator:
    """
    Validates a target URL against a :class:`~scanner.models.ProgramScope` instance.

    Usage::

        scope = ProgramScope.objects.get(id=scope_id)
        validator = ScopeValidator(target_url, scope)
        result = validator.validate()
        # result = {
        #     'is_valid': True/False,
        #     'violations': [...],
        #     'warnings': [...],
        # }
    """

    def __init__(self, target_url: str, program_scope=None):
        self.target_url = target_url
        self.program_scope = program_scope

    def validate(self, requested_vuln_types: Optional[list] = None) -> dict:
        """
        Validate the target URL (and optionally requested vulnerability types) against
        the program scope.

        Args:
            requested_vuln_types: Optional list of vulnerability type keys
                (from VULNERABILITY_TYPE_CHOICES) to check against allowed/disallowed
                lists.  Pass ``None`` or an empty list to skip vuln-type checks.

        Returns:
            dict with keys:
            - ``is_valid`` (bool)
            - ``violations`` (list of str) — rule violations that block the scan
            - ``warnings`` (list of str) — non-blocking advisory notices
        """
        violations = []
        warnings = []

        if self.program_scope is None:
            warnings.append(
                'No program scope defined — scanning without scope restrictions.'
            )
            return {'is_valid': True, 'violations': violations, 'warnings': warnings}

        scope = self.program_scope
        url = self.target_url

        # 1. In-scope check
        in_scope = scope.in_scope_domains
        if in_scope:
            if not _is_domain_in_list(url, in_scope):
                violations.append(
                    f'Target "{url}" is not within the in-scope domains: {in_scope}'
                )

        # 2. Out-of-scope check
        out_of_scope = scope.out_of_scope_domains
        if out_of_scope and _is_domain_in_list(url, out_of_scope):
            violations.append(
                f'Target "{url}" matches an out-of-scope domain: {out_of_scope}'
            )

        # 3. Vulnerability type checks
        if requested_vuln_types:
            allowed = scope.allowed_vulnerability_types or []
            disallowed = scope.disallowed_vulnerability_types or []

            for vtype in requested_vuln_types:
                # If an explicit allowed list exists and the type is not in it
                if allowed and vtype not in allowed:
                    violations.append(
                        f'Vulnerability type "{vtype}" is not in the allowed list: {allowed}'
                    )
                # If the type is explicitly disallowed
                if disallowed and vtype in disallowed:
                    violations.append(
                        f'Vulnerability type "{vtype}" is explicitly disallowed by the program scope.'
                    )

        # 4. Rate limiting advisory
        if scope.max_requests_per_second is not None:
            warnings.append(
                f'Rate limit enforced: maximum {scope.max_requests_per_second} requests/second.'
            )

        # 5. Testing window advisory
        if scope.testing_window_start and scope.testing_window_end:
            warnings.append(
                f'Testing window: {scope.testing_window_start} – {scope.testing_window_end}.'
            )

        is_valid = len(violations) == 0
        return {'is_valid': is_valid, 'violations': violations, 'warnings': warnings}
