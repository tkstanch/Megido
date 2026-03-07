"""
Bounty Report Generator for SQL Injection findings.

Takes a BugReport (and its linked SQLInjectionResult) and produces a complete,
platform-ready vulnerability report with auto-calculated CVSS v3.1 score, CWE
mapping, and formatted sections for HackerOne, Bugcrowd, Intigriti, or custom.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CVSS v3.1 metric mappings
# ---------------------------------------------------------------------------

# Injection-type → (attack_vector, attack_complexity, privileges_required,
#                   user_interaction, scope, confidentiality, integrity,
#                   availability) abbreviated values used in the vector string.
# Values follow CVSS v3.1 notation.

_CVSS_AV_N = "N"   # Network
_CVSS_AC_L = "L"   # Low
_CVSS_AC_H = "H"   # High
_CVSS_PR_N = "N"   # None
_CVSS_PR_L = "L"   # Low
_CVSS_UI_N = "N"   # None
_CVSS_UI_R = "R"   # Required
_CVSS_S_U = "U"    # Unchanged
_CVSS_S_C = "C"    # Changed
_CVSS_C_H = "H"    # High
_CVSS_C_L = "L"    # Low
_CVSS_C_N = "N"    # None

# (AV, AC, PR, UI, S, C, I, A) → base score approximations per injection type
_INJECTION_CVSS_PARAMS: Dict[str, Tuple] = {
    'error_based':    (_CVSS_AV_N, _CVSS_AC_L, _CVSS_PR_N, _CVSS_UI_N, _CVSS_S_U, _CVSS_C_H, _CVSS_C_H, _CVSS_C_N),
    'union_based':    (_CVSS_AV_N, _CVSS_AC_L, _CVSS_PR_N, _CVSS_UI_N, _CVSS_S_C, _CVSS_C_H, _CVSS_C_H, _CVSS_C_N),
    'boolean_based':  (_CVSS_AV_N, _CVSS_AC_L, _CVSS_PR_N, _CVSS_UI_N, _CVSS_S_U, _CVSS_C_H, _CVSS_C_L, _CVSS_C_N),
    'time_based':     (_CVSS_AV_N, _CVSS_AC_H, _CVSS_PR_N, _CVSS_UI_N, _CVSS_S_U, _CVSS_C_H, _CVSS_C_L, _CVSS_C_L),
    'stacked_queries':(_CVSS_AV_N, _CVSS_AC_L, _CVSS_PR_L, _CVSS_UI_N, _CVSS_S_C, _CVSS_C_H, _CVSS_C_H, _CVSS_C_H),
}

# Pre-computed approximate CVSS base scores for the above configurations.
# Scores reflect the high-impact nature of SQL injection in each variant:
# union_based and stacked_queries score near-maximum due to full data access
# and potential for write/execute operations. time_based blind scores lower
# due to reduced immediate confidentiality impact.
_INJECTION_BASE_SCORES: Dict[str, float] = {
    'error_based': 9.8,
    'union_based': 10.0,
    'boolean_based': 8.6,
    'time_based': 7.5,
    'stacked_queries': 9.9,
}

# CWE mapping per injection type
_CWE_MAP: Dict[str, str] = {
    'error_based': 'CWE-89',
    'union_based': 'CWE-89',
    'boolean_based': 'CWE-89',
    'time_based': 'CWE-89',
    'stacked_queries': 'CWE-89',
}

# Estimated bounty ranges by CVSS score band
_BOUNTY_RANGES = [
    (9.0, 10.0, '$3,000–$15,000'),
    (7.0, 8.9,  '$1,000–$5,000'),
    (4.0, 6.9,  '$250–$1,500'),
    (0.0, 3.9,  '$50–$300'),
]

# Platform-specific Markdown/formatting hints
_PLATFORM_HEADERS: Dict[str, str] = {
    'hackerone': '## ',
    'bugcrowd':  '## ',
    'intigriti': '### ',
    'custom':    '## ',
}


class BountyReportGenerator:
    """Generate a complete, bounty-ready impact report for a BugReport.

    Args:
        bug_report: A BugReport model instance.
        result: The linked SQLInjectionResult model instance.
        platform: One of ``'hackerone'``, ``'bugcrowd'``, ``'intigriti'``, ``'custom'``.
    """

    def __init__(self, bug_report: Any, result: Any, platform: str = 'hackerone'):
        self.bug_report = bug_report
        self.result = result
        self.platform = platform

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> Dict[str, Any]:
        """Run all generators and return a dict ready for BountyImpactReport creation.

        Returns keys matching BountyImpactReport model fields:
            cvss_score, cvss_vector, cwe_id, impact_summary, technical_details,
            reproduction_steps, business_impact, remediation,
            ready_to_submit_report, estimated_bounty_range,
            submission_platform_template.
        """
        injection_type = getattr(self.result, 'injection_type', 'error_based') or 'error_based'
        cvss_score = self._calc_cvss_score(injection_type)
        cvss_vector = self._build_cvss_vector(injection_type)
        cwe_id = _CWE_MAP.get(injection_type, 'CWE-89')
        estimated_bounty_range = self._estimate_bounty_range(cvss_score)

        impact_summary = self._build_impact_summary()
        technical_details = self._build_technical_details()
        reproduction_steps = self._build_reproduction_steps()
        business_impact = self._build_business_impact(cvss_score)
        remediation = self._build_remediation()
        full_report = self._build_full_report(
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_id=cwe_id,
            impact_summary=impact_summary,
            technical_details=technical_details,
            reproduction_steps=reproduction_steps,
            business_impact=business_impact,
            remediation=remediation,
            estimated_bounty_range=estimated_bounty_range,
        )

        return {
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'cwe_id': cwe_id,
            'impact_summary': impact_summary,
            'technical_details': technical_details,
            'reproduction_steps': reproduction_steps,
            'business_impact': business_impact,
            'remediation': remediation,
            'ready_to_submit_report': full_report,
            'estimated_bounty_range': estimated_bounty_range,
            'submission_platform_template': self.platform,
        }

    # ------------------------------------------------------------------
    # Score / vector helpers
    # ------------------------------------------------------------------

    def _calc_cvss_score(self, injection_type: str) -> float:
        base = _INJECTION_BASE_SCORES.get(injection_type, 7.5)
        # Boost slightly if exploitation was confirmed
        if getattr(self.result, 'is_exploitable', False):
            base = min(base + 0.2, 10.0)
        # Reduce if confidence is low (proportional penalty: -2.0 at confidence=0)
        confidence = getattr(self.result, 'confidence_score', 0.7)
        if confidence < 0.5:
            penalty = (0.5 - confidence) / 0.5 * 2.0  # 0 to 2.0 as confidence goes 0.5→0
            base = max(base - penalty, 0.0)
        return round(base, 1)

    def _build_cvss_vector(self, injection_type: str) -> str:
        params = _INJECTION_CVSS_PARAMS.get(
            injection_type,
            (_CVSS_AV_N, _CVSS_AC_L, _CVSS_PR_N, _CVSS_UI_N, _CVSS_S_U, _CVSS_C_H, _CVSS_C_H, _CVSS_C_N),
        )
        av, ac, pr, ui, s, c, i, a = params
        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    def _estimate_bounty_range(self, cvss_score: float) -> str:
        for low, high, label in _BOUNTY_RANGES:
            if low <= cvss_score <= high:
                return label
        return '$50–$300'

    # ------------------------------------------------------------------
    # Report section builders
    # ------------------------------------------------------------------

    def _build_impact_summary(self) -> str:
        r = self.result
        param = getattr(r, 'vulnerable_parameter', 'unknown')
        injection_type = getattr(r, 'injection_type', 'SQL injection')
        url = getattr(getattr(r, 'task', None), 'target_url', 'unknown') if hasattr(r, 'task') else 'unknown'
        db_type = getattr(r, 'database_type', '') or 'unknown'
        exploitable = getattr(r, 'is_exploitable', False)

        summary = (
            f"A {injection_type.replace('_', '-')} SQL injection vulnerability was identified "
            f"in the '{param}' parameter of {url}. "
        )
        if exploitable:
            db_ver = getattr(r, 'database_version', '') or ''
            db_user = getattr(r, 'current_user', '') or ''
            summary += (
                f"The vulnerability is fully exploitable: "
                f"database type is {db_type}"
                + (f", version {db_ver}" if db_ver else "")
                + (f", running as user '{db_user}'" if db_user else "")
                + ". An attacker could read, modify, or delete arbitrary data."
            )
        else:
            summary += (
                f"The database appears to be {db_type}. "
                "An attacker could potentially extract sensitive data or compromise database integrity."
            )
        return summary

    def _build_technical_details(self) -> str:
        r = self.result
        lines = [
            f"**Vulnerability Type:** SQL Injection ({getattr(r, 'injection_type', 'N/A').replace('_', ' ').title()})",
            f"**Vulnerable Parameter:** {getattr(r, 'vulnerable_parameter', 'N/A')}",
            f"**Parameter Location:** {getattr(r, 'parameter_type', 'GET')}",
            f"**Database Type:** {getattr(r, 'database_type', 'unknown') or 'unknown'}",
            f"**Severity:** {getattr(r, 'severity', 'critical')}",
            f"**Confidence Score:** {getattr(r, 'confidence_score', 0.7):.0%}",
            "",
            f"**Test Payload:**",
            f"```",
            getattr(r, 'test_payload', 'N/A'),
            "```",
            "",
            f"**Detection Evidence:**",
            getattr(r, 'detection_evidence', 'N/A'),
        ]
        if getattr(r, 'database_version', ''):
            lines.append(f"\n**Database Version:** {r.database_version}")
        if getattr(r, 'current_database', ''):
            lines.append(f"**Current Database:** {r.current_database}")
        if getattr(r, 'current_user', ''):
            lines.append(f"**Database User:** {r.current_user}")
        tables = getattr(r, 'extracted_tables', None)
        if tables:
            lines.append(f"**Extracted Tables:** {', '.join(tables[:10])}")
        return "\n".join(lines)

    def _build_reproduction_steps(self) -> str:
        r = self.result
        # Prefer stored reproduction_steps from DiscoveryScanner
        stored = getattr(r, 'reproduction_steps', '') or ''
        if stored.strip():
            return stored
        task = getattr(r, 'task', None)
        url = getattr(task, 'target_url', 'TARGET_URL') if task else 'TARGET_URL'
        method = getattr(task, 'http_method', 'GET') if task else 'GET'
        param = getattr(r, 'vulnerable_parameter', 'PARAM')
        payload = getattr(r, 'test_payload', "' OR '1'='1")
        steps = (
            f"1. Open a web browser or HTTP proxy tool (e.g. Burp Suite).\n"
            f"2. Send the following {method} request:\n\n"
            f"   URL: {url}\n"
            f"   Parameter: {param}\n"
            f"   Payload: {payload}\n\n"
            f"3. Observe the response for SQL error messages or behavioral differences.\n"
            f"4. The response will confirm SQL injection via the detection evidence above."
        )
        return steps

    def _build_business_impact(self, cvss_score: float) -> str:
        r = self.result
        exploitable = getattr(r, 'is_exploitable', False)
        severity = getattr(r, 'severity', 'critical')

        impact = (
            f"This SQL injection vulnerability carries a CVSS score of {cvss_score:.1f} ({severity.upper()}). "
        )
        if exploitable:
            impact += (
                "Full exploitation was demonstrated, giving an attacker unrestricted read access "
                "to the database. This could lead to:\n\n"
                "- **Data breach:** Exfiltration of all database tables, including PII, "
                "credentials, and sensitive records.\n"
                "- **Authentication bypass:** Extraction of password hashes or session tokens "
                "enabling account takeover.\n"
                "- **Regulatory consequences:** Potential violations of GDPR, PCI-DSS, or HIPAA "
                "if personal or financial data is compromised.\n"
                "- **Reputational damage:** Public disclosure could severely impact customer trust."
            )
        else:
            impact += (
                "Even without confirmed exploitation, the vulnerability allows an attacker to "
                "infer database structure through behavioral differences, potentially enabling "
                "targeted data extraction, credential theft, or privilege escalation."
            )
        return impact

    def _build_remediation(self) -> str:
        injection_type = getattr(self.result, 'injection_type', '') or ''
        base = (
            "**Immediate Actions:**\n"
            "1. Replace all dynamic SQL string concatenation with parameterised queries "
            "(prepared statements).\n"
            "2. Apply the principle of least privilege to the database account used by the "
            "application – restrict to SELECT/INSERT/UPDATE on required tables only.\n"
            "3. Implement an input validation layer that rejects or sanitises unexpected characters.\n\n"
            "**Long-term Hardening:**\n"
            "4. Adopt an ORM (Object-Relational Mapper) to abstract raw SQL away from "
            "application code.\n"
            "5. Enable a Web Application Firewall (WAF) with SQL injection signatures as a "
            "defence-in-depth layer.\n"
            "6. Conduct regular DAST/SAST scans and include SQL injection in your security "
            "regression test suite.\n\n"
            "**References:**\n"
            "- OWASP SQL Injection Prevention Cheat Sheet: "
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html\n"
            "- CWE-89: Improper Neutralisation of Special Elements used in an SQL Command: "
            "https://cwe.mitre.org/data/definitions/89.html"
        )
        if 'time_based' in injection_type or 'boolean' in injection_type:
            base += (
                "\n\n**Note (Blind SQLi):** Even though the database output is not directly "
                "visible, blind injection allows full data extraction through inference. "
                "Parameterised queries are the only reliable fix."
            )
        return base

    def _build_full_report(
        self,
        cvss_score: float,
        cvss_vector: str,
        cwe_id: str,
        impact_summary: str,
        technical_details: str,
        reproduction_steps: str,
        business_impact: str,
        remediation: str,
        estimated_bounty_range: str,
    ) -> str:
        h = _PLATFORM_HEADERS.get(self.platform, '## ')
        br = self.bug_report
        r = self.result
        task = getattr(r, 'task', None)
        url = getattr(task, 'target_url', 'unknown') if task else 'unknown'
        severity = getattr(r, 'severity', 'critical').upper()
        title = getattr(br, 'title', f"SQL Injection in {getattr(r, 'vulnerable_parameter', 'parameter')}")

        sections = [
            f"# {title}",
            "",
            f"**Severity:** {severity}  ",
            f"**CVSS v3.1 Score:** {cvss_score:.1f}  ",
            f"**CVSS Vector:** `{cvss_vector}`  ",
            f"**CWE:** {cwe_id}  ",
            f"**Estimated Bounty:** {estimated_bounty_range}  ",
            f"**Bug ID:** {getattr(br, 'bug_id', 'N/A')}",
            "",
            f"{h}Summary",
            "",
            impact_summary,
            "",
            f"{h}Vulnerability Details",
            "",
            technical_details,
            "",
            f"{h}Steps to Reproduce",
            "",
            reproduction_steps,
            "",
            f"{h}Impact",
            "",
            business_impact,
            "",
            f"{h}Proof of Concept",
            "",
            f"**Target URL:** {url}",
            f"**Vulnerable Parameter:** {getattr(r, 'vulnerable_parameter', 'N/A')}",
            f"**Payload Used:**",
            "```",
            getattr(r, 'test_payload', 'N/A'),
            "```",
            f"**Detection Evidence:**",
            getattr(r, 'detection_evidence', 'N/A'),
            "",
            f"{h}Remediation Recommendations",
            "",
            remediation,
            "",
            f"{h}References",
            "",
            f"- OWASP Top 10 – A03:2021 Injection: https://owasp.org/Top10/A03_2021-Injection/",
            f"- {cwe_id}: https://cwe.mitre.org/data/definitions/89.html",
        ]

        return "\n".join(sections)
