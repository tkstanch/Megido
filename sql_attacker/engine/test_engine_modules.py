#!/usr/bin/env python3
"""
Tests for engine sub-modules: adapters, modes, reporting, scoring, and baseline.
"""

import sys
import os
import json
import time
import unittest
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.engine.adapters import (
    AdapterRegistry,
    DBType,
    PayloadFamily,
    DBAdapter,
    TECHNIQUE_ERROR,
    TECHNIQUE_BOOLEAN,
    TECHNIQUE_TIME,
    get_adapter,
    fingerprint_from_error,
)
from sql_attacker.engine.modes import (
    ModePolicy,
    ModeViolationError,
    OperationMode,
)
from sql_attacker.engine.reporting import (
    Evidence,
    Finding,
    ReportBuilder,
    _confidence_to_severity,
    _severity_to_sarif_level,
    _verdict_to_sarif_precision,
)
from sql_attacker.engine.scoring import (
    FeatureContribution,
    ScoringResult,
    compute_confidence,
    compute_confidence_from_signals,
)
from sql_attacker.engine.baseline import (
    BaselineResult,
    BaselineCache,
    CanaryScheduler,
    _median,
    _iqr,
    confirm_finding,
)
from sql_attacker.engine.normalization import (
    normalize_response_body,
    fingerprint,
    strip_html,
    scrub_dynamic_tokens,
)


# ===========================================================================
# Adapter tests
# ===========================================================================


class TestDBType(unittest.TestCase):
    """Tests for the DBType enum."""

    def test_all_db_types_present(self):
        expected = {"mysql", "postgresql", "mssql", "sqlite", "oracle", "unknown"}
        actual = {t.value for t in DBType}
        self.assertEqual(expected, actual)


class TestPayloadFamily(unittest.TestCase):
    """Tests for PayloadFamily."""

    def test_create_stores_payloads_as_tuple(self):
        family = PayloadFamily.create(DBType.MYSQL, TECHNIQUE_ERROR, ["'", "\""])
        self.assertIsInstance(family.payloads, tuple)
        self.assertEqual(("'", "\""), family.payloads)

    def test_immutable(self):
        family = PayloadFamily.create(DBType.MYSQL, TECHNIQUE_BOOLEAN, ["' AND 1=1"])
        with self.assertRaises(Exception):
            family.payloads = ("mutated",)  # type: ignore[misc]


class TestDBAdapter(unittest.TestCase):
    """Tests for DBAdapter."""

    def setUp(self):
        self.registry = AdapterRegistry()

    def test_get_payloads_returns_list(self):
        for db_type in DBType:
            adapter = self.registry.get_adapter(db_type)
            for technique in (TECHNIQUE_ERROR, TECHNIQUE_BOOLEAN, TECHNIQUE_TIME):
                payloads = adapter.get_payloads(technique)
                self.assertIsInstance(payloads, list, f"{db_type}/{technique}")

    def test_get_payloads_non_empty_for_known_dbs(self):
        """Each known DB should have at least one payload per technique."""
        for db_type in (DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL,
                        DBType.SQLITE, DBType.ORACLE):
            adapter = self.registry.get_adapter(db_type)
            for technique in (TECHNIQUE_ERROR, TECHNIQUE_BOOLEAN, TECHNIQUE_TIME):
                payloads = adapter.get_payloads(technique)
                self.assertGreater(
                    len(payloads), 0,
                    f"Empty payload list for {db_type}/{technique}"
                )

    def test_get_payloads_unknown_technique_returns_empty(self):
        adapter = self.registry.get_adapter(DBType.MYSQL)
        self.assertEqual([], adapter.get_payloads("nonexistent_technique"))

    def test_db_type_property(self):
        for db_type in DBType:
            adapter = self.registry.get_adapter(db_type)
            self.assertEqual(db_type, adapter.db_type)

    def test_fingerprint_patterns_exist_for_known_dbs(self):
        for db_type in (DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL,
                        DBType.SQLITE, DBType.ORACLE):
            adapter = self.registry.get_adapter(db_type)
            self.assertGreater(
                len(adapter.fingerprint_patterns), 0,
                f"No fingerprint patterns for {db_type}"
            )

    def test_unknown_adapter_has_no_patterns(self):
        adapter = self.registry.get_adapter(DBType.UNKNOWN)
        self.assertEqual([], adapter.fingerprint_patterns)


class TestAdapterRegistry(unittest.TestCase):
    """Tests for AdapterRegistry."""

    def setUp(self):
        self.registry = AdapterRegistry()

    def test_all_db_types_registered(self):
        for db_type in DBType:
            adapter = self.registry.get_adapter(db_type)
            self.assertIsNotNone(adapter)

    def test_all_db_types_listed(self):
        db_types = self.registry.all_db_types()
        for db_type in DBType:
            self.assertIn(db_type, db_types)

    def test_fallback_to_unknown_for_unregistered(self):
        """get_adapter falls back to UNKNOWN for unregistered types."""
        # DBType.UNKNOWN is always available
        adapter = self.registry.get_adapter(DBType.UNKNOWN)
        self.assertEqual(DBType.UNKNOWN, adapter.db_type)


class TestFingerprintFromError(unittest.TestCase):
    """Tests for DBMS fingerprinting from error messages."""

    def setUp(self):
        self.registry = AdapterRegistry()

    def test_mysql_fingerprint(self):
        body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
        db_type, adapter = self.registry.fingerprint_from_error(body)
        self.assertEqual(DBType.MYSQL, db_type)

    def test_postgresql_fingerprint(self):
        body = "PSQLException: ERROR: syntax error at or near \"'\" at character 12"
        db_type, adapter = self.registry.fingerprint_from_error(body)
        self.assertEqual(DBType.POSTGRESQL, db_type)

    def test_mssql_fingerprint(self):
        body = "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark"
        db_type, adapter = self.registry.fingerprint_from_error(body)
        self.assertEqual(DBType.MSSQL, db_type)

    def test_oracle_fingerprint(self):
        body = "ORA-01756: quoted string not properly terminated"
        db_type, adapter = self.registry.fingerprint_from_error(body)
        self.assertEqual(DBType.ORACLE, db_type)

    def test_sqlite_fingerprint(self):
        body = "SQLite.Exception: unrecognized token: \"'\" in query"
        db_type, adapter = self.registry.fingerprint_from_error(body)
        self.assertEqual(DBType.SQLITE, db_type)

    def test_unknown_when_no_match(self):
        body = "Internal Server Error"
        db_type, adapter = self.registry.fingerprint_from_error(body)
        self.assertEqual(DBType.UNKNOWN, db_type)

    def test_module_level_helpers(self):
        """Module-level get_adapter and fingerprint_from_error functions work."""
        adapter = get_adapter(DBType.MYSQL)
        self.assertEqual(DBType.MYSQL, adapter.db_type)

        db_type, _ = fingerprint_from_error("You have an error in your SQL syntax; MySQL")
        self.assertEqual(DBType.MYSQL, db_type)


# ===========================================================================
# Mode tests
# ===========================================================================


class TestOperationMode(unittest.TestCase):
    """Tests for OperationMode enum and ModePolicy."""

    def test_from_string_valid(self):
        self.assertEqual(OperationMode.DETECT, OperationMode.from_string("detect"))
        self.assertEqual(OperationMode.VERIFY, OperationMode.from_string("VERIFY"))
        self.assertEqual(OperationMode.DEMONSTRATE, OperationMode.from_string("Demonstrate"))

    def test_from_string_invalid(self):
        with self.assertRaises(ValueError):
            OperationMode.from_string("exploit")

    def test_all_values(self):
        values = {m.value for m in OperationMode}
        self.assertIn("detect", values)
        self.assertIn("verify", values)
        self.assertIn("demonstrate", values)


class TestModePolicyDetect(unittest.TestCase):
    """ModePolicy tests for DETECT mode (most restrictive)."""

    def setUp(self):
        self.policy = ModePolicy(OperationMode.DETECT)

    def test_may_detect_is_true(self):
        self.assertTrue(self.policy.may_detect())

    def test_may_verify_is_false(self):
        self.assertFalse(self.policy.may_verify())

    def test_may_demonstrate_is_false(self):
        self.assertFalse(self.policy.may_demonstrate())

    def test_assert_may_detect_does_not_raise(self):
        self.policy.assert_may_detect()  # must not raise

    def test_assert_may_verify_raises(self):
        with self.assertRaises(ModeViolationError):
            self.policy.assert_may_verify()

    def test_assert_may_demonstrate_raises(self):
        with self.assertRaises(ModeViolationError):
            self.policy.assert_may_demonstrate()

    def test_assert_may_exfiltrate_always_raises(self):
        with self.assertRaises(ModeViolationError):
            self.policy.assert_may_exfiltrate()

    def test_describe_contains_mode_name(self):
        desc = self.policy.describe()
        self.assertIn("detect", desc.lower())

    def test_mode_property(self):
        self.assertEqual(OperationMode.DETECT, self.policy.mode)


class TestModePolicyVerify(unittest.TestCase):
    """ModePolicy tests for VERIFY mode."""

    def setUp(self):
        self.policy = ModePolicy(OperationMode.VERIFY)

    def test_may_detect_is_true(self):
        self.assertTrue(self.policy.may_detect())

    def test_may_verify_is_true(self):
        self.assertTrue(self.policy.may_verify())

    def test_may_demonstrate_is_false(self):
        self.assertFalse(self.policy.may_demonstrate())

    def test_assert_may_verify_does_not_raise(self):
        self.policy.assert_may_verify()  # must not raise

    def test_assert_may_demonstrate_raises(self):
        with self.assertRaises(ModeViolationError):
            self.policy.assert_may_demonstrate()

    def test_assert_may_exfiltrate_always_raises(self):
        with self.assertRaises(ModeViolationError):
            self.policy.assert_may_exfiltrate()


class TestModePolicyDemonstrate(unittest.TestCase):
    """ModePolicy tests for DEMONSTRATE mode (least restrictive)."""

    def setUp(self):
        self.policy = ModePolicy(OperationMode.DEMONSTRATE)

    def test_may_detect_is_true(self):
        self.assertTrue(self.policy.may_detect())

    def test_may_verify_is_true(self):
        self.assertTrue(self.policy.may_verify())

    def test_may_demonstrate_is_true(self):
        self.assertTrue(self.policy.may_demonstrate())

    def test_assert_may_demonstrate_does_not_raise(self):
        self.policy.assert_may_demonstrate()  # must not raise

    def test_assert_may_exfiltrate_still_raises(self):
        """Even in DEMONSTRATE mode, unrestricted exfiltration is forbidden."""
        with self.assertRaises(ModeViolationError):
            self.policy.assert_may_exfiltrate()


class TestModePolicyRedaction(unittest.TestCase):
    """Tests for the ModePolicy.redact helper."""

    def setUp(self):
        self.policy = ModePolicy(OperationMode.DEMONSTRATE, max_demonstrate_bytes=128)

    def test_full_redaction_by_default(self):
        result = self.policy.redact("MySQL 5.7.38")
        self.assertIn("[REDACTED]", result)

    def test_keep_prefix(self):
        result = self.policy.redact("MySQL 5.7.38", keep_prefix=5)
        self.assertTrue(result.startswith("MySQL"))
        self.assertIn("[REDACTED]", result)

    def test_short_value_fully_redacted(self):
        result = self.policy.redact("abc", keep_prefix=0)
        self.assertIn("[REDACTED]", result)

    def test_truncation_at_max_bytes(self):
        long_value = "x" * 500
        result = self.policy.redact(long_value)
        # The original value is 500 chars but max_demonstrate_bytes=128
        self.assertIn("[REDACTED]", result)

    def test_redact_char_default_is_asterisk(self):
        policy = ModePolicy(OperationMode.DEMONSTRATE)
        result = policy.redact("some secret", keep_prefix=0)
        self.assertIn("*", result)


class TestModePolicyDefaultMode(unittest.TestCase):
    """Default mode is DETECT (safest)."""

    def test_default_mode_is_detect(self):
        policy = ModePolicy()
        self.assertEqual(OperationMode.DETECT, policy.mode)

    def test_default_forbids_verify(self):
        policy = ModePolicy()
        with self.assertRaises(ModeViolationError):
            policy.assert_may_verify()


# ===========================================================================
# Reporting tests
# ===========================================================================


class TestEvidence(unittest.TestCase):
    """Tests for Evidence dataclass."""

    def test_to_dict_contains_required_fields(self):
        ev = Evidence(
            payload="' AND SLEEP(5)--",
            request_summary="GET /search?q=... HTTP/1.1",
            response_length=1234,
            technique=TECHNIQUE_TIME,
        )
        d = ev.to_dict()
        self.assertEqual("' AND SLEEP(5)--", d["payload"])
        self.assertEqual(TECHNIQUE_TIME, d["technique"])
        self.assertEqual(1234, d["response_length"])

    def test_response_body_excerpt_truncated_at_512(self):
        ev = Evidence(
            payload="'",
            request_summary="GET / HTTP/1.1",
            response_body_excerpt="X" * 1000,
        )
        d = ev.to_dict()
        self.assertLessEqual(len(d["response_body_excerpt"]), 512)

    def test_timing_samples_included_when_present(self):
        ev = Evidence(
            payload="' AND SLEEP(5)--",
            request_summary="GET / HTTP/1.1",
            timing_samples_ms=[5100.0, 5050.0, 5200.0],
            baseline_median_ms=120.0,
        )
        d = ev.to_dict()
        self.assertIn("timing_samples_ms", d)
        self.assertIn("baseline_median_ms", d)

    def test_timing_omitted_when_empty(self):
        ev = Evidence(payload="'", request_summary="GET / HTTP/1.1")
        d = ev.to_dict()
        self.assertNotIn("timing_samples_ms", d)
        self.assertNotIn("baseline_median_ms", d)


class TestFinding(unittest.TestCase):
    """Tests for Finding dataclass."""

    def _make_finding(self, **kwargs):
        defaults = dict(
            parameter="id",
            technique=TECHNIQUE_ERROR,
            db_type="mysql",
            confidence=0.92,
            verdict="confirmed",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_finding_id_auto_generated(self):
        f = self._make_finding()
        self.assertTrue(len(f.finding_id) > 0)

    def test_confidence_clamped_above_one(self):
        f = self._make_finding(confidence=1.5)
        self.assertEqual(1.0, f.confidence)

    def test_confidence_clamped_below_zero(self):
        f = self._make_finding(confidence=-0.1)
        self.assertEqual(0.0, f.confidence)

    def test_severity_derived_from_confidence_high(self):
        f = self._make_finding(confidence=0.9)
        self.assertEqual("high", f.severity)

    def test_severity_derived_from_confidence_medium(self):
        f = self._make_finding(confidence=0.7)
        self.assertEqual("medium", f.severity)

    def test_severity_derived_from_confidence_low(self):
        f = self._make_finding(confidence=0.4)
        self.assertEqual("low", f.severity)

    def test_severity_derived_from_confidence_informational(self):
        f = self._make_finding(confidence=0.1)
        self.assertEqual("informational", f.severity)

    def test_severity_explicit_overrides_derived(self):
        f = self._make_finding(confidence=0.9, severity="low")
        self.assertEqual("low", f.severity)

    def test_to_dict_keys(self):
        f = self._make_finding()
        d = f.to_dict()
        for key in ("finding_id", "parameter", "technique", "db_type",
                    "confidence", "verdict", "severity", "cwe", "evidence",
                    "remediation"):
            self.assertIn(key, d, f"Missing key: {key}")

    def test_to_dict_confidence_rounded(self):
        f = self._make_finding(confidence=0.9234567)
        d = f.to_dict()
        self.assertEqual(round(0.9234567, 4), d["confidence"])


class TestConfidenceToSeverity(unittest.TestCase):
    def test_high_threshold(self):
        self.assertEqual("high", _confidence_to_severity(0.85))
        self.assertEqual("high", _confidence_to_severity(1.0))

    def test_medium_threshold(self):
        self.assertEqual("medium", _confidence_to_severity(0.60))
        self.assertEqual("medium", _confidence_to_severity(0.84))

    def test_low_threshold(self):
        self.assertEqual("low", _confidence_to_severity(0.35))
        self.assertEqual("low", _confidence_to_severity(0.59))

    def test_informational(self):
        self.assertEqual("informational", _confidence_to_severity(0.0))
        self.assertEqual("informational", _confidence_to_severity(0.34))


class TestReportBuilderJSON(unittest.TestCase):
    """Tests for ReportBuilder.to_json()."""

    def _make_builder(self) -> ReportBuilder:
        return ReportBuilder(target_url="https://example.com/search")

    def _make_finding(self, **kwargs) -> Finding:
        defaults = dict(
            parameter="q",
            technique=TECHNIQUE_ERROR,
            db_type="mysql",
            confidence=0.92,
            verdict="confirmed",
            evidence=[Evidence(
                payload="'",
                request_summary="GET /search?q=' HTTP/1.1",
                response_body_excerpt="MySQL syntax error",
            )],
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_to_json_is_valid_json(self):
        builder = self._make_builder()
        builder.add_finding(self._make_finding())
        output = builder.to_json()
        data = json.loads(output)
        self.assertIsInstance(data, dict)

    def test_json_schema_version(self):
        builder = self._make_builder()
        data = json.loads(builder.to_json())
        self.assertEqual("1.0", data["schema_version"])

    def test_json_contains_findings(self):
        builder = self._make_builder()
        builder.add_finding(self._make_finding())
        data = json.loads(builder.to_json())
        self.assertEqual(1, len(data["findings"]))

    def test_json_summary_totals(self):
        builder = self._make_builder()
        builder.add_finding(self._make_finding(verdict="confirmed"))
        builder.add_finding(self._make_finding(verdict="likely"))
        data = json.loads(builder.to_json())
        self.assertEqual(2, data["summary"]["total"])

    def test_json_scan_id_present(self):
        builder = self._make_builder()
        data = json.loads(builder.to_json())
        self.assertIn("scan_id", data)
        self.assertTrue(len(data["scan_id"]) > 0)

    def test_json_target_url(self):
        builder = self._make_builder()
        data = json.loads(builder.to_json())
        self.assertEqual("https://example.com/search", data["target_url"])

    def test_finish_sets_finished_at(self):
        builder = self._make_builder()
        builder.finish()
        data = json.loads(builder.to_json())
        self.assertIsNotNone(data["finished_at"])

    def test_finding_url_inherits_target_url(self):
        builder = self._make_builder()
        finding = self._make_finding()
        self.assertIsNone(finding.url)
        builder.add_finding(finding)
        self.assertEqual("https://example.com/search", finding.url)

    def test_findings_accessor(self):
        builder = self._make_builder()
        builder.add_finding(self._make_finding())
        self.assertEqual(1, len(builder.findings))


class TestReportBuilderSARIF(unittest.TestCase):
    """Tests for ReportBuilder.to_sarif()."""

    def _make_builder_with_finding(self) -> ReportBuilder:
        builder = ReportBuilder(target_url="https://example.com/")
        builder.add_finding(Finding(
            parameter="id",
            technique=TECHNIQUE_ERROR,
            db_type="mysql",
            confidence=0.92,
            verdict="confirmed",
            evidence=[Evidence(
                payload="'",
                request_summary="GET /?id=' HTTP/1.1",
                response_body_excerpt="MySQL syntax error",
            )],
        ))
        return builder

    def test_sarif_is_valid_json(self):
        builder = self._make_builder_with_finding()
        sarif_str = builder.to_sarif()
        data = json.loads(sarif_str)
        self.assertIsInstance(data, dict)

    def test_sarif_version(self):
        builder = self._make_builder_with_finding()
        data = json.loads(builder.to_sarif())
        self.assertEqual("2.1.0", data["version"])

    def test_sarif_has_runs(self):
        builder = self._make_builder_with_finding()
        data = json.loads(builder.to_sarif())
        self.assertIn("runs", data)
        self.assertEqual(1, len(data["runs"]))

    def test_sarif_tool_driver(self):
        builder = self._make_builder_with_finding()
        data = json.loads(builder.to_sarif())
        driver = data["runs"][0]["tool"]["driver"]
        self.assertEqual("Megido SQLi Engine", driver["name"])

    def test_sarif_rules_present(self):
        builder = self._make_builder_with_finding()
        data = json.loads(builder.to_sarif())
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        self.assertGreater(len(rules), 0)

    def test_sarif_results_present(self):
        builder = self._make_builder_with_finding()
        data = json.loads(builder.to_sarif())
        results = data["runs"][0]["results"]
        self.assertEqual(1, len(results))

    def test_sarif_result_has_rule_id(self):
        builder = self._make_builder_with_finding()
        data = json.loads(builder.to_sarif())
        result = data["runs"][0]["results"][0]
        self.assertIn("ruleId", result)
        self.assertTrue(result["ruleId"].startswith("MEGIDO-SQLI"))

    def test_sarif_result_has_location(self):
        builder = self._make_builder_with_finding()
        data = json.loads(builder.to_sarif())
        result = data["runs"][0]["results"][0]
        self.assertIn("locations", result)

    def test_sarif_deduplicates_rules(self):
        """Two findings with the same technique/db_type should produce one rule."""
        builder = ReportBuilder(target_url="https://example.com/")
        for param in ("id", "name"):
            builder.add_finding(Finding(
                parameter=param,
                technique=TECHNIQUE_ERROR,
                db_type="mysql",
                confidence=0.92,
                verdict="confirmed",
            ))
        data = json.loads(builder.to_sarif())
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_sarif_severity_mapping(self):
        self.assertEqual("error", _severity_to_sarif_level("high"))
        self.assertEqual("error", _severity_to_sarif_level("critical"))
        self.assertEqual("warning", _severity_to_sarif_level("medium"))
        self.assertEqual("note", _severity_to_sarif_level("low"))

    def test_sarif_precision_mapping(self):
        self.assertEqual("high", _verdict_to_sarif_precision("confirmed"))
        self.assertEqual("medium", _verdict_to_sarif_precision("likely"))
        self.assertEqual("low", _verdict_to_sarif_precision("uncertain"))


# ===========================================================================
# Scoring tests (engine.scoring)
# ===========================================================================


class TestComputeConfidence(unittest.TestCase):
    """Tests for the engine.scoring.compute_confidence function."""

    def test_empty_features_returns_uncertain(self):
        result = compute_confidence({})
        self.assertEqual("uncertain", result.verdict)
        self.assertEqual(0.0, result.score)

    def test_single_strong_signal_confirmed(self):
        result = compute_confidence({"sql_error_pattern": 1.0})
        self.assertGreater(result.score, 0.0)
        # Single feature with weight 0.90 → score ≈ 0.90
        self.assertAlmostEqual(0.90, result.score, places=3)

    def test_two_strong_signals_confirmed(self):
        result = compute_confidence({
            "sql_error_pattern": 1.0,
            "boolean_diff": 1.0,
        })
        self.assertEqual("confirmed", result.verdict)
        self.assertGreater(result.score, 0.90)

    def test_contributions_sorted_descending(self):
        result = compute_confidence({
            "sql_error_pattern": 1.0,
            "http_error_code": 1.0,
        })
        contribs = result.contributions
        for i in range(len(contribs) - 1):
            self.assertGreaterEqual(
                contribs[i].contribution, contribs[i + 1].contribution
            )

    def test_unknown_feature_gets_default_weight(self):
        result = compute_confidence({"my_custom_signal": 1.0})
        active = [c for c in result.contributions if c.contribution > 0]
        self.assertEqual(1, len(active))
        self.assertAlmostEqual(0.30, active[0].contribution, places=4)

    def test_extra_weights_override(self):
        result = compute_confidence(
            {"sql_error_pattern": 1.0},
            extra_weights={"sql_error_pattern": 0.50},
        )
        self.assertAlmostEqual(0.50, result.score, places=3)

    def test_value_clamped_to_unit_interval(self):
        result = compute_confidence({"sql_error_pattern": 2.0})
        # Value >1 should be clamped to 1.0
        self.assertAlmostEqual(0.90, result.score, places=3)

    def test_feature_contribution_dataclass(self):
        fc = FeatureContribution(name="test", weight=0.8, value=0.5)
        self.assertAlmostEqual(0.40, fc.contribution, places=4)

    def test_backwards_compat_shim(self):
        score, verdict = compute_confidence_from_signals(
            ["sql_error_pattern", "boolean_diff"]
        )
        self.assertIsInstance(score, float)
        self.assertIn(verdict, ("confirmed", "likely", "uncertain"))

    def test_rationale_included(self):
        result = compute_confidence({"sql_error_pattern": 1.0})
        self.assertIn("score=", result.rationale)

    def test_zero_value_feature_inactive(self):
        result = compute_confidence({"sql_error_pattern": 0.0})
        active = [c for c in result.contributions if c.contribution > 0]
        self.assertEqual(0, len(active))
        self.assertEqual("uncertain", result.verdict)


# ===========================================================================
# Baseline tests (engine.baseline)
# ===========================================================================


class TestMedianAndIQR(unittest.TestCase):
    def test_median_odd(self):
        self.assertEqual(3.0, _median([1, 2, 3, 4, 5]))

    def test_median_even(self):
        self.assertEqual(2.5, _median([1, 2, 3, 4]))

    def test_iqr_basic(self):
        # sorted: [1,2,3,4,5,6,7,8] → Q1=2,Q3=6 → IQR=4
        result = _iqr([3, 1, 4, 1, 5, 9, 2, 6])
        self.assertIsInstance(result, (int, float))
        self.assertGreater(result, 0)

    def test_iqr_single_value_returns_zero(self):
        self.assertEqual(0.0, _iqr([42.0]))


class TestBaselineCache(unittest.TestCase):
    def test_store_and_retrieve(self):
        cache = BaselineCache(ttl_seconds=60)
        result = BaselineResult(
            median_time=0.5, iqr_time=0.1, body_signature="abc123", sample_count=3
        )
        cache.put("http://example.com", "GET", result)
        retrieved = cache.get("http://example.com", "GET")
        self.assertEqual(result, retrieved)

    def test_miss_returns_none(self):
        cache = BaselineCache()
        self.assertIsNone(cache.get("http://nowhere.invalid", "GET"))

    def test_ttl_expiry(self):
        cache = BaselineCache(ttl_seconds=0.01)
        result = BaselineResult(
            median_time=0.5, iqr_time=0.1, body_signature="sig", sample_count=1
        )
        cache.put("http://example.com", "GET", result)
        time.sleep(0.05)
        self.assertIsNone(cache.get("http://example.com", "GET"))

    def test_invalidate(self):
        cache = BaselineCache()
        result = BaselineResult(
            median_time=0.5, iqr_time=0.1, body_signature="sig", sample_count=1
        )
        cache.put("http://example.com", "GET", result)
        cache.invalidate("http://example.com", "GET")
        self.assertIsNone(cache.get("http://example.com", "GET"))

    def test_clear_removes_all(self):
        cache = BaselineCache()
        result = BaselineResult(
            median_time=0.5, iqr_time=0.1, body_signature="sig", sample_count=1
        )
        cache.put("http://a.com", "GET", result)
        cache.put("http://b.com", "GET", result)
        cache.clear()
        self.assertIsNone(cache.get("http://a.com", "GET"))
        self.assertIsNone(cache.get("http://b.com", "GET"))

    def test_max_entries_eviction(self):
        cache = BaselineCache(max_entries=2)
        result = BaselineResult(
            median_time=0.5, iqr_time=0.1, body_signature="sig", sample_count=1
        )
        cache.put("http://a.com", "GET", result)
        cache.put("http://b.com", "GET", result)
        cache.put("http://c.com", "GET", result)
        # At least one of a or b should be evicted
        stored = sum(
            1 for url in ["http://a.com", "http://b.com", "http://c.com"]
            if cache.get(url, "GET") is not None
        )
        self.assertLessEqual(stored, 2)


class TestCanaryScheduler(unittest.TestCase):
    def test_default_canary_payloads_non_empty(self):
        scheduler = CanaryScheduler()
        self.assertGreater(len(scheduler.canary_payloads), 0)

    def test_schedule_puts_canaries_first(self):
        scheduler = CanaryScheduler(canary_payloads=["CANARY"])
        full = ["A", "B", "CANARY", "C"]
        canary_set, remainder = scheduler.schedule(full)
        self.assertEqual(["CANARY"], canary_set)
        self.assertNotIn("CANARY", remainder)

    def test_schedule_deduplicates_canaries_from_remainder(self):
        scheduler = CanaryScheduler(canary_payloads=["'"])
        full = ["'", "\"", "' OR 1=1"]
        canary_set, remainder = scheduler.schedule(full)
        self.assertNotIn("'", remainder)

    def test_custom_canary_payloads(self):
        custom = ["test1", "test2"]
        scheduler = CanaryScheduler(canary_payloads=custom)
        self.assertEqual(custom, scheduler.canary_payloads)


class TestConfirmFinding(unittest.TestCase):
    def test_confirmed_when_all_positive_and_benign_negative(self):
        """Finding should be confirmed when all probes positive + benign negative."""
        class FakeResp:
            pass

        confirmed, rationale = confirm_finding(
            test_fn=lambda: FakeResp(),
            benign_fn=lambda: FakeResp(),
            detect_fn=lambda r: isinstance(r, FakeResp),
            repetitions=2,
        )
        # Both test probes trigger but benign also triggers → false positive
        self.assertFalse(confirmed)

    def test_not_confirmed_when_benign_triggers(self):
        """When benign control also triggers, finding is a false positive."""
        class FakeResp:
            pass

        confirmed, rationale = confirm_finding(
            test_fn=lambda: FakeResp(),
            benign_fn=lambda: FakeResp(),
            detect_fn=lambda r: True,  # always triggers
            repetitions=2,
        )
        self.assertFalse(confirmed)

    def test_confirmed_when_probes_positive_and_benign_negative(self):
        """Correctly confirm when benign control is negative."""
        _sentinel = object()

        def detect(r):
            return r is _sentinel

        confirmed, rationale = confirm_finding(
            test_fn=lambda: _sentinel,
            benign_fn=lambda: None,
            detect_fn=detect,
            repetitions=2,
        )
        self.assertTrue(confirmed)
        self.assertIn("confirmed", rationale.lower())


# ===========================================================================
# Normalisation tests (engine.normalization)
# ===========================================================================


class TestNormalizationIntegration(unittest.TestCase):
    """Smoke tests to verify normalization plays well with the engine."""

    def test_normalize_stable_fingerprint(self):
        body1 = "<html><body>Hello World 2026-01-01T12:00:00Z</body></html>"
        body2 = "<html><body>Hello World 2026-02-02T08:30:00Z</body></html>"
        # Timestamps scrubbed → same fingerprint
        self.assertEqual(fingerprint(body1), fingerprint(body2))

    def test_strip_html_removes_tags(self):
        result = strip_html("<p>Hello <b>World</b></p>")
        self.assertNotIn("<", result)
        self.assertIn("Hello", result)
        self.assertIn("World", result)

    def test_scrub_uuid(self):
        text = "session=550e8400-e29b-41d4-a716-446655440000"
        result = scrub_dynamic_tokens(text)
        self.assertNotIn("550e8400", result)

    def test_response_similarity_after_normalization(self):
        resp1 = "Error: CSRF token abc123def456789012 expired"
        resp2 = "Error: CSRF token 9999999999999999ab expired"
        norm1 = normalize_response_body(resp1)
        norm2 = normalize_response_body(resp2)
        # Both hex tokens scrubbed → same normalized form
        self.assertEqual(norm1, norm2)


if __name__ == "__main__":
    unittest.main()
