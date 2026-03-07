"""
Tests for ImpactAnalyzer and RealImpact.

Covers impact analysis for each supported vulnerability type plus the
generic fallback, CIA triad population, CVSS vector assignment, and
submittable report generation.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.impact_analyzer import ImpactAnalyzer, RealImpact


analyzer = ImpactAnalyzer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _analyze(vuln_type, **kwargs):
    return analyzer.analyze_impact(vuln_type, kwargs)


# ---------------------------------------------------------------------------
# RealImpact dataclass
# ---------------------------------------------------------------------------

class TestRealImpact:
    def test_to_dict_returns_dict(self):
        impact = RealImpact(vulnerability_type="XSS", cvss_score=6.1)
        d = impact.to_dict()
        assert isinstance(d, dict)
        assert d["vulnerability_type"] == "XSS"
        assert d["cvss_score"] == 6.1


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

class TestXSSImpact:
    def test_basic_reflected_xss(self):
        impact = _analyze("xss")
        assert impact.vulnerability_type == "xss"
        assert impact.cwe_id == "CWE-79"
        assert impact.cvss_score > 0
        assert "xss" in impact.cvss_vector.lower() or "CVSS" in impact.cvss_vector

    def test_xss_alias_cross_site_scripting(self):
        impact = _analyze("cross-site scripting")
        assert impact.cwe_id == "CWE-79"

    def test_stored_xss_worm_propagation(self):
        impact = _analyze("xss", xss_type="stored")
        assert impact.technical_impact["worm_propagation_possible"] is True
        assert impact.business_impact == "critical"

    def test_reflected_xss_without_session_cookie(self):
        impact = _analyze("xss", xss_type="reflected", session_cookie_present=False)
        assert impact.technical_impact["session_hijack_possible"] is False

    def test_xss_with_http_only_cookies(self):
        impact = _analyze("xss", cookie_flags={"http_only": True})
        assert impact.technical_impact["cookie_theft_possible"] is False

    def test_xss_without_http_only_cookies(self):
        impact = _analyze("xss", cookie_flags={"http_only": False})
        assert impact.technical_impact["cookie_theft_possible"] is True

    def test_xss_submittable_report_contains_cvss(self):
        impact = _analyze("xss")
        assert "CVSS" in impact.submittable_report

    def test_xss_affected_scope_all_visitors_for_stored(self):
        impact = _analyze("xss", xss_type="stored")
        assert impact.technical_impact["affected_users_scope"] == "all-visitors"

    def test_xss_affected_scope_self_only_for_reflected(self):
        impact = _analyze("xss", xss_type="reflected", authenticated_endpoint=False)
        assert impact.technical_impact["affected_users_scope"] == "self-only"


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

class TestSQLiImpact:
    def test_basic_sqli(self):
        impact = _analyze("sqli")
        assert impact.cwe_id == "CWE-89"
        assert impact.cvss_score >= 9.0

    def test_sqli_alias_sql_injection(self):
        impact = _analyze("sql injection")
        assert impact.cwe_id == "CWE-89"

    def test_sqli_with_root_db_user_privilege_escalation(self):
        impact = _analyze("sqli", db_user="root")
        assert impact.technical_impact["privilege_escalation_possible"] is True

    def test_sqli_mssql_rce_possible(self):
        impact = _analyze("sqli", database_type="MSSQL", db_user="sa")
        assert impact.technical_impact["rce_possible"] is True
        assert impact.business_impact == "critical"

    def test_sqli_mysql_rce_not_possible_without_root(self):
        impact = _analyze("sqli", database_type="MySQL", db_user="webapp")
        assert impact.technical_impact["rce_possible"] is False

    def test_sqli_full_dump_always_possible(self):
        impact = _analyze("sqli")
        assert impact.technical_impact["full_database_dump_possible"] is True

    def test_sqli_remediation_is_immediate(self):
        impact = _analyze("sqli")
        assert impact.remediation_priority == "immediate"


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

class TestSSRFImpact:
    def test_basic_ssrf(self):
        impact = _analyze("ssrf")
        assert impact.cwe_id == "CWE-918"

    def test_ssrf_with_cloud_metadata(self):
        impact = _analyze("ssrf", cloud_metadata={"iam": "arn:aws:iam::123456789012:role/admin"})
        assert impact.technical_impact["cloud_metadata_accessible"] is True
        assert impact.business_impact == "critical"

    def test_ssrf_with_credentials_in_metadata(self):
        impact = _analyze(
            "ssrf",
            cloud_metadata={"credentials": {"aws_access_key": "AKIA..."}}
        )
        assert impact.technical_impact["credential_theft_possible"] is True

    def test_ssrf_with_scanned_hosts(self):
        impact = _analyze(
            "ssrf",
            scanned_hosts=[{"host": "10.0.0.1", "port": 22, "open": True}]
        )
        assert impact.technical_impact["internal_network_access"] is True
        assert "10.0.0.1:22" in impact.technical_impact["internal_services_discovered"]

    def test_ssrf_port_scanning_always_possible(self):
        impact = _analyze("ssrf")
        assert impact.technical_impact["port_scanning_possible"] is True


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------

class TestXXEImpact:
    def test_basic_xxe(self):
        impact = _analyze("xxe")
        assert impact.cwe_id == "CWE-611"

    def test_xxe_with_files_read(self):
        impact = _analyze("xxe", files_read=["/etc/passwd", "/etc/shadow"])
        assert impact.technical_impact["file_read_possible"] is True
        assert "/etc/passwd" in impact.technical_impact["files_readable"]

    def test_xxe_ssrf_chaining(self):
        impact = _analyze("xxe", ssrf_via_xxe=True)
        assert impact.technical_impact["ssrf_via_xxe"] is True

    def test_xxe_dos_possible(self):
        impact = _analyze("xxe", dos_possible=True)
        assert impact.technical_impact["dos_possible"] is True
        assert impact.affected_cia["availability"] == "high"

    def test_xxe_no_files_read_is_medium_business_impact(self):
        impact = _analyze("xxe")
        assert impact.business_impact == "medium"


# ---------------------------------------------------------------------------
# Clickjacking
# ---------------------------------------------------------------------------

class TestClickjackingImpact:
    def test_basic_clickjacking(self):
        impact = _analyze("clickjacking")
        assert impact.cwe_id == "CWE-1021"

    def test_clickjacking_with_auth_actions(self):
        impact = _analyze("clickjacking", sensitive_actions=["password change", "login"])
        assert impact.technical_impact["authentication_actions_exposed"] is True
        assert impact.business_impact == "high"

    def test_clickjacking_with_financial_actions(self):
        impact = _analyze("clickjacking", sensitive_actions=["fund transfer", "payment"])
        assert impact.technical_impact["financial_actions_exposed"] is True

    def test_clickjacking_no_sensitive_actions_is_medium(self):
        impact = _analyze("clickjacking", sensitive_actions=[])
        assert impact.business_impact == "medium"


# ---------------------------------------------------------------------------
# Security Misconfiguration
# ---------------------------------------------------------------------------

class TestSecurityMisconfigImpact:
    def test_basic_security_misconfig(self):
        impact = _analyze("security misconfiguration")
        assert impact.cwe_id == "CWE-16"

    def test_missing_csp_xss_risk_elevated(self):
        impact = _analyze(
            "security_misconfiguration",
            missing_headers=["Content-Security-Policy", "X-Frame-Options"]
        )
        assert impact.technical_impact["xss_risk_elevated"] is True
        assert impact.technical_impact["clickjacking_risk"] is True

    def test_missing_hsts_transport_security_risk(self):
        impact = _analyze(
            "security_misconfiguration",
            missing_headers=["Strict-Transport-Security"]
        )
        assert impact.technical_impact["transport_security_risk"] is True

    def test_server_header_information_disclosure(self):
        impact = _analyze(
            "security_misconfiguration",
            server_header="Apache/2.4.51",
            missing_headers=[]
        )
        assert any("Apache" in s for s in impact.technical_impact["information_disclosure"])

    def test_many_missing_headers_is_high_business_impact(self):
        impact = _analyze(
            "security_misconfiguration",
            missing_headers=[
                "Content-Security-Policy",
                "X-Frame-Options",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
            ]
        )
        assert impact.business_impact == "high"


# ---------------------------------------------------------------------------
# Generic fallback
# ---------------------------------------------------------------------------

class TestGenericFallback:
    def test_unknown_type_uses_fallback(self):
        impact = _analyze("some_unknown_vuln")
        assert impact.cvss_score > 0
        assert "manual assessment" in impact.impact_summary.lower()

    def test_generic_fallback_includes_evidence(self):
        impact = _analyze("some_unknown_vuln", payload="test123")
        assert "test123" in str(impact.technical_impact)


# ---------------------------------------------------------------------------
# Submittable report
# ---------------------------------------------------------------------------

class TestSubmittableReport:
    def test_report_contains_vulnerability_type(self):
        impact = _analyze("xss")
        assert "xss" in impact.submittable_report.lower()

    def test_report_contains_cia(self):
        impact = _analyze("sqli")
        assert "Confidentiality" in impact.submittable_report

    def test_report_contains_remediation_priority(self):
        impact = _analyze("sqli")
        assert "Remediation" in impact.submittable_report


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
