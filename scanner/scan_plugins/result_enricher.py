"""
Scan Result Enricher

Post-detection enrichment of :class:`~scanner.scan_plugins.base_scan_plugin.VulnerabilityFinding`
objects with additional context:

- CVSS v3.1 base score estimation by vulnerability type and severity
- CWE ID mapping
- Remediation guidance tailored to the detected technology stack
- Risk-score adjustment when a WAF is active (lower exploitability)
- External reference links (OWASP, CWE, NVD)
- False-positive flags based on detected server technology

All methods are pure (no network calls) and operate only on the data already
present in the finding and the target fingerprint produced by
:class:`~scanner.scan_plugins.fingerprinter.TargetFingerprinter`.
"""

import logging
from typing import Dict, List, Any, Optional

from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CVSS base-score estimates keyed by (vuln_type, severity)
# When severity is not found for a type the generic-severity fallback is used.
# ---------------------------------------------------------------------------
_CVSS_TABLE: Dict[str, Dict[str, float]] = {
    'xss':                  {'critical': 8.8,  'high': 6.1,  'medium': 5.4, 'low': 3.1},
    'sqli':                 {'critical': 9.8,  'high': 8.8,  'medium': 6.5, 'low': 4.3},
    'csrf':                 {'critical': 9.6,  'high': 8.8,  'medium': 6.5, 'low': 4.3},
    'xxe':                  {'critical': 9.8,  'high': 7.5,  'medium': 5.3, 'low': 3.1},
    'rce':                  {'critical': 9.8,  'high': 8.1,  'medium': 6.3, 'low': 4.2},
    'lfi':                  {'critical': 8.6,  'high': 7.5,  'medium': 5.5, 'low': 3.5},
    'rfi':                  {'critical': 9.8,  'high': 8.1,  'medium': 6.3, 'low': 4.2},
    'open_redirect':        {'critical': 6.1,  'high': 5.4,  'medium': 4.7, 'low': 3.1},
    'ssrf':                 {'critical': 9.8,  'high': 7.5,  'medium': 5.0, 'low': 3.5},
    'info_disclosure':      {'critical': 7.5,  'high': 5.3,  'medium': 4.3, 'low': 2.7},
    'clickjacking':         {'critical': 6.1,  'high': 5.4,  'medium': 4.7, 'low': 3.1},
    'js_hijacking':         {'critical': 8.8,  'high': 6.5,  'medium': 5.0, 'low': 3.1},
    'idor':                 {'critical': 9.1,  'high': 7.5,  'medium': 5.4, 'low': 3.5},
    'jwt':                  {'critical': 9.1,  'high': 7.5,  'medium': 5.4, 'low': 3.1},
    'crlf':                 {'critical': 8.2,  'high': 6.1,  'medium': 5.0, 'low': 3.1},
    'host_header':          {'critical': 8.1,  'high': 6.5,  'medium': 5.3, 'low': 3.1},
    'smuggling':            {'critical': 9.0,  'high': 7.5,  'medium': 5.9, 'low': 3.7},
    'deserialization':      {'critical': 9.8,  'high': 8.1,  'medium': 6.3, 'low': 4.2},
    'graphql':              {'critical': 7.5,  'high': 6.3,  'medium': 5.0, 'low': 3.1},
    'websocket':            {'critical': 8.1,  'high': 6.5,  'medium': 5.0, 'low': 3.1},
    'cache_poisoning':      {'critical': 8.0,  'high': 7.2,  'medium': 5.8, 'low': 3.5},
    'cors':                 {'critical': 8.8,  'high': 7.5,  'medium': 5.4, 'low': 3.1},
    'email_rce':            {'critical': 9.8,  'high': 8.1,  'medium': 6.3, 'low': 4.2},
    'ai_llm':               {'critical': 7.5,  'high': 6.3,  'medium': 5.0, 'low': 3.1},
    'dos':                  {'critical': 7.5,  'high': 6.5,  'medium': 5.3, 'low': 3.5},
    'security_misconfig':   {'critical': 9.8,  'high': 7.5,  'medium': 5.3, 'low': 3.1},
    'sensitive_data':       {'critical': 7.5,  'high': 6.5,  'medium': 5.0, 'low': 3.1},
    'weak_password':        {'critical': 9.8,  'high': 7.5,  'medium': 5.3, 'low': 3.1},
    'bac':                  {'critical': 9.1,  'high': 8.1,  'medium': 5.4, 'low': 3.5},
    'username_enum':        {'critical': 5.3,  'high': 4.3,  'medium': 3.7, 'low': 2.7},
    'captcha_bypass':       {'critical': 5.3,  'high': 4.3,  'medium': 3.7, 'low': 2.7},
    'unsafe_upload':        {'critical': 9.8,  'high': 8.1,  'medium': 6.3, 'low': 4.2},
    'subdomain_takeover':   {'critical': 9.1,  'high': 7.5,  'medium': 5.4, 'low': 3.5},
    'exif_data':            {'critical': 4.3,  'high': 3.5,  'medium': 2.7, 'low': 1.8},
    'api_key_exposure':     {'critical': 9.1,  'high': 7.5,  'medium': 5.4, 'low': 3.5},
    'other':                {'critical': 7.5,  'high': 5.5,  'medium': 4.0, 'low': 2.5},
}

# Generic CVSS fallback by severity only
_CVSS_SEVERITY_FALLBACK: Dict[str, float] = {
    'critical': 9.0,
    'high': 7.5,
    'medium': 5.0,
    'low': 3.0,
}

# ---------------------------------------------------------------------------
# CWE mappings
# ---------------------------------------------------------------------------
_CWE_MAP: Dict[str, str] = {
    'xss':                'CWE-79',
    'sqli':               'CWE-89',
    'csrf':               'CWE-352',
    'xxe':                'CWE-611',
    'rce':                'CWE-78',
    'lfi':                'CWE-98',
    'rfi':                'CWE-98',
    'open_redirect':      'CWE-601',
    'ssrf':               'CWE-918',
    'info_disclosure':    'CWE-200',
    'clickjacking':       'CWE-1021',
    'js_hijacking':       'CWE-829',
    'idor':               'CWE-639',
    'jwt':                'CWE-287',
    'crlf':               'CWE-93',
    'host_header':        'CWE-20',
    'smuggling':          'CWE-444',
    'deserialization':    'CWE-502',
    'graphql':            'CWE-20',
    'websocket':          'CWE-20',
    'cache_poisoning':    'CWE-345',
    'cors':               'CWE-942',
    'email_rce':          'CWE-78',
    'ai_llm':             'CWE-20',
    'dos':                'CWE-400',
    'security_misconfig': 'CWE-16',
    'sensitive_data':     'CWE-200',
    'weak_password':      'CWE-521',
    'bac':                'CWE-284',
    'username_enum':      'CWE-204',
    'captcha_bypass':     'CWE-307',
    'unsafe_upload':      'CWE-434',
    'subdomain_takeover': 'CWE-284',
    'exif_data':          'CWE-200',
    'api_key_exposure':   'CWE-522',
    'other':              'CWE-20',
}

# ---------------------------------------------------------------------------
# External references
# ---------------------------------------------------------------------------
_REFERENCES: Dict[str, List[str]] = {
    'xss':              ['https://owasp.org/www-community/attacks/xss/', 'https://cwe.mitre.org/data/definitions/79.html'],
    'sqli':             ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cwe.mitre.org/data/definitions/89.html'],
    'csrf':             ['https://owasp.org/www-community/attacks/csrf', 'https://cwe.mitre.org/data/definitions/352.html'],
    'xxe':              ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing', 'https://cwe.mitre.org/data/definitions/611.html'],
    'rce':              ['https://owasp.org/www-community/attacks/Code_Injection', 'https://cwe.mitre.org/data/definitions/78.html'],
    'lfi':              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion', 'https://cwe.mitre.org/data/definitions/98.html'],
    'rfi':              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion', 'https://cwe.mitre.org/data/definitions/98.html'],
    'open_redirect':    ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html', 'https://cwe.mitre.org/data/definitions/601.html'],
    'ssrf':             ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery', 'https://cwe.mitre.org/data/definitions/918.html'],
    'info_disclosure':  ['https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure', 'https://cwe.mitre.org/data/definitions/200.html'],
    'clickjacking':     ['https://owasp.org/www-community/attacks/Clickjacking', 'https://cwe.mitre.org/data/definitions/1021.html'],
    'js_hijacking':     ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion', 'https://cwe.mitre.org/data/definitions/829.html'],
    'idor':             ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References', 'https://cwe.mitre.org/data/definitions/639.html'],
    'jwt':              ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html', 'https://cwe.mitre.org/data/definitions/287.html'],
    'crlf':             ['https://owasp.org/www-community/vulnerabilities/CRLF_Injection', 'https://cwe.mitre.org/data/definitions/93.html'],
    'host_header':      ['https://portswigger.net/web-security/host-header', 'https://cwe.mitre.org/data/definitions/20.html'],
    'smuggling':        ['https://portswigger.net/web-security/request-smuggling', 'https://cwe.mitre.org/data/definitions/444.html'],
    'deserialization':  ['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data', 'https://cwe.mitre.org/data/definitions/502.html'],
    'graphql':          ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
    'websocket':        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets'],
    'cache_poisoning':  ['https://portswigger.net/web-security/web-cache-poisoning', 'https://cwe.mitre.org/data/definitions/345.html'],
    'cors':             ['https://owasp.org/www-community/vulnerabilities/CORS_OriginHeaderScrutiny', 'https://cwe.mitre.org/data/definitions/942.html'],
    'email_rce':        ['https://owasp.org/www-community/attacks/Code_Injection', 'https://cwe.mitre.org/data/definitions/78.html'],
    'ai_llm':           ['https://owasp.org/www-project-top-10-for-large-language-model-applications/'],
    'dos':              ['https://owasp.org/www-community/attacks/Denial_of_Service', 'https://cwe.mitre.org/data/definitions/400.html'],
    'security_misconfig': ['https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration', 'https://cwe.mitre.org/data/definitions/16.html'],
    'sensitive_data':   ['https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure', 'https://cwe.mitre.org/data/definitions/200.html'],
    'weak_password':    ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html', 'https://cwe.mitre.org/data/definitions/521.html'],
    'bac':              ['https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control', 'https://cwe.mitre.org/data/definitions/284.html'],
    'username_enum':    ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account', 'https://cwe.mitre.org/data/definitions/204.html'],
    'captcha_bypass':   ['https://owasp.org/www-community/vulnerabilities/Improper_Test_Automation', 'https://cwe.mitre.org/data/definitions/307.html'],
    'unsafe_upload':    ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload', 'https://cwe.mitre.org/data/definitions/434.html'],
    'subdomain_takeover': ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover', 'https://cwe.mitre.org/data/definitions/284.html'],
    'exif_data':        ['https://cwe.mitre.org/data/definitions/200.html'],
    'api_key_exposure': ['https://owasp.org/www-project-api-security/', 'https://cwe.mitre.org/data/definitions/522.html'],
    'other':            ['https://owasp.org/www-project-top-ten/'],
}

# ---------------------------------------------------------------------------
# Remediation hints per technology
# ---------------------------------------------------------------------------
_REMEDIATION_TECH_HINTS: Dict[str, Dict[str, str]] = {
    'wordpress': {
        'xss':   'Keep WordPress core, themes, and plugins updated. Use a Content Security Policy.',
        'sqli':  'Use WordPress $wpdb->prepare() for all database queries.',
        'rfi':   'Disable allow_url_include in PHP and ensure WordPress plugins are from trusted sources.',
    },
    'php': {
        'xss':   'Use htmlspecialchars() with ENT_QUOTES for all output and set CSP headers.',
        'sqli':  'Use PDO or MySQLi with prepared statements and parameterised queries.',
        'lfi':   'Never pass user input to file system functions; use a whitelist of allowed paths.',
        'rfi':   'Set allow_url_include=Off and allow_url_fopen=Off in php.ini.',
    },
    'asp.net': {
        'xss':   'Use AntiXSS library and set ValidateRequest to true. Encode all output with HttpUtility.HtmlEncode.',
        'sqli':  'Use parameterised queries via ADO.NET or Entity Framework.',
    },
    'node.js': {
        'xss':   'Use a templating engine that auto-escapes output (e.g. Handlebars, Nunjucks). Set helmet CSP middleware.',
        'sqli':  'Use an ORM (Sequelize, Knex) with parameterised queries and never concatenate user input into SQL.',
    },
    'django': {
        'xss':   'Django auto-escapes template output; avoid mark_safe() unless absolutely necessary.',
        'sqli':  'Use Django ORM queries; avoid raw() with unparameterised user data.',
        'csrf':  'Ensure {% csrf_token %} is included in all forms and CsrfViewMiddleware is enabled.',
    },
}


class ResultEnricher:
    """Enrich vulnerability findings with additional context.

    Enrichment is applied after the detection phase and is non-destructive —
    it only *adds* information to findings; it never removes or modifies
    existing evidence.

    Usage::

        enricher = ResultEnricher()
        enriched = enricher.enrich(finding, target_fingerprint)
    """

    def enrich(
        self,
        finding: VulnerabilityFinding,
        target_fingerprint: Optional[Dict[str, Any]] = None,
    ) -> VulnerabilityFinding:
        """Add context to a finding based on target fingerprint.

        Populates (if not already set):
        - ``cvss_score`` — estimated CVSS v3.1 base score
        - ``cwe_id``     — CWE identifier
        - ``references`` — external links
        - ``attack_complexity`` — CVSS attack-complexity estimate

        Adjusts:
        - ``remediation`` — appended technology-specific guidance
        - ``false_positive_risk`` — flagged for certain tech/vuln combos

        Args:
            finding: The :class:`VulnerabilityFinding` to enrich.
            target_fingerprint: Dict returned by
                :class:`~scanner.scan_plugins.fingerprinter.TargetFingerprinter`.
                May be ``None`` — enrichment then operates without tech context.

        Returns:
            The same *finding* instance (mutated in place and returned for
            chaining convenience).
        """
        fingerprint = target_fingerprint or {}
        vuln_type = finding.vulnerability_type

        # CVSS score
        if finding.cvss_score is None:
            finding.cvss_score = self._get_cvss_estimate(vuln_type, finding.severity)

        # CWE ID
        if not finding.cwe_id:
            finding.cwe_id = self._get_cwe_mapping(vuln_type)

        # External references
        if not finding.references:
            finding.references = self._get_references(vuln_type)

        # Attack complexity
        if finding.attack_complexity is None:
            finding.attack_complexity = self._get_attack_complexity(vuln_type)

        # Technology-specific remediation — append only if not already applied.
        # We use a sentinel marker format ("[<hint>]") so exact-match detection
        # is reliable, avoiding the false-positive substring issue where a
        # shorter hint could match unrelated text.
        technologies: List[str] = fingerprint.get('technologies', [])
        tech_hint = self._get_tech_remediation(vuln_type, technologies)
        sentinel = f"[{tech_hint}]"
        if tech_hint and sentinel not in finding.remediation:
            finding.remediation = f"{finding.remediation}  {sentinel}"

        # False-positive flagging
        if not finding.false_positive_risk:
            fp_hint = self._check_false_positive_risk(vuln_type, technologies)
            if fp_hint:
                finding.false_positive_risk = fp_hint

        logger.debug(
            "Enriched finding: type=%s cvss=%.1f cwe=%s",
            vuln_type,
            finding.cvss_score or 0.0,
            finding.cwe_id or 'n/a',
        )
        return finding

    # ------------------------------------------------------------------
    # CVSS estimation
    # ------------------------------------------------------------------

    def _get_cvss_estimate(self, vuln_type: str, severity: str) -> float:
        """Estimate CVSS v3.1 base score from vulnerability type and severity.

        Args:
            vuln_type: Vulnerability type identifier (e.g. ``'xss'``).
            severity: Severity string (``'low'``, ``'medium'``, ``'high'``,
                      ``'critical'``).

        Returns:
            float: Estimated CVSS base score (0.0–10.0).
        """
        sev = (severity or 'medium').lower()
        type_scores = _CVSS_TABLE.get(vuln_type)
        if type_scores:
            score = type_scores.get(sev)
            if score is not None:
                return score
        return _CVSS_SEVERITY_FALLBACK.get(sev, 5.0)

    # ------------------------------------------------------------------
    # CWE mapping
    # ------------------------------------------------------------------

    def _get_cwe_mapping(self, vuln_type: str) -> Optional[str]:
        """Map vulnerability type to CWE ID.

        Args:
            vuln_type: Vulnerability type identifier.

        Returns:
            CWE ID string (e.g. ``'CWE-79'``) or ``None`` if unmapped.
        """
        return _CWE_MAP.get(vuln_type)

    # ------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------

    def _get_references(self, vuln_type: str) -> List[str]:
        """Get external references for the given vulnerability type.

        Args:
            vuln_type: Vulnerability type identifier.

        Returns:
            List of URL strings.
        """
        return list(_REFERENCES.get(vuln_type, _REFERENCES.get('other', [])))

    # ------------------------------------------------------------------
    # Attack complexity
    # ------------------------------------------------------------------

    def _get_attack_complexity(self, vuln_type: str) -> str:
        """Estimate CVSS attack complexity for the vulnerability type.

        Args:
            vuln_type: Vulnerability type identifier.

        Returns:
            ``'low'`` or ``'high'``.
        """
        high_complexity_types = {
            'csrf', 'jwt', 'cache_poisoning', 'smuggling', 'xxe',
            'deserialization', 'ai_llm', 'graphql', 'websocket',
        }
        return 'high' if vuln_type in high_complexity_types else 'low'

    # ------------------------------------------------------------------
    # Technology-specific remediation
    # ------------------------------------------------------------------

    def _get_tech_remediation(
        self, vuln_type: str, technologies: List[str]
    ) -> Optional[str]:
        """Return technology-specific remediation guidance if available.

        Args:
            vuln_type: Vulnerability type identifier.
            technologies: List of detected technology names.

        Returns:
            Guidance string or ``None``.
        """
        for tech in technologies:
            tech_lower = tech.lower()
            hints = _REMEDIATION_TECH_HINTS.get(tech_lower, {})
            hint = hints.get(vuln_type)
            if hint:
                return hint
        return None

    # ------------------------------------------------------------------
    # False-positive detection
    # ------------------------------------------------------------------

    def _check_false_positive_risk(
        self, vuln_type: str, technologies: List[str]
    ) -> Optional[str]:
        """Flag potential false positives based on technology context.

        Args:
            vuln_type: Vulnerability type identifier.
            technologies: List of detected technology names.

        Returns:
            Human-readable false-positive risk note, or ``None``.
        """
        # CSRF findings on API-only endpoints often lack session cookies
        if vuln_type == 'csrf' and 'node.js' in technologies:
            return (
                'CSRF may be a false positive for stateless JSON APIs that '
                'do not use session cookies.'
            )
        # Clickjacking findings on login pages with frame-busting JS
        if vuln_type == 'clickjacking' and 'wordpress' in technologies:
            return (
                'Verify that no frame-busting JavaScript is in use before '
                'confirming this clickjacking finding.'
            )
        return None
