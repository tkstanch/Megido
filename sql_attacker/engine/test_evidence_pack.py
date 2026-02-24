#!/usr/bin/env python3
"""
Tests for EvidencePack, TimingStats, RequestSpec, LocalFileStorage,
VerificationProfile, and the new ScanConfig safety fields.

Covers:
  - TimingStats computation (median, mean, stddev)
  - RequestSpec secret redaction in to_dict()
  - EvidencePack construction and to_dict() round-trip
  - EvidencePack JSON save / load round-trip
  - Curl and Python repro script generation with secret redaction
  - LocalFileStorage save / load / list_all / delete
  - VerificationProfile enum and profile_to_mode mapping
  - ScanConfig global_request_cap and error_spike_abort_threshold validation
  - ScanConfig new inject_path_segments / inject_graphql_vars flags
  - Time-based jitter stats: stddev correctly reflects sample spread
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.engine.evidence_pack import (
    EvidencePack,
    RequestSpec,
    TimingStats,
    _redact,
    _redact_dict,
)
from sql_attacker.engine.storage import LocalFileStorage
from sql_attacker.engine.modes import (
    ModeViolationError,
    OperationMode,
    VerificationProfile,
)
from sql_attacker.engine.config import ScanConfig


# ===========================================================================
# TimingStats tests
# ===========================================================================


class TestTimingStats(unittest.TestCase):
    """TimingStats must compute correct descriptive statistics."""

    def test_single_sample(self):
        ts = TimingStats(samples_ms=[100.0])
        self.assertAlmostEqual(ts.median_ms, 100.0)
        self.assertAlmostEqual(ts.mean_ms, 100.0)
        self.assertAlmostEqual(ts.stddev_ms, 0.0)
        self.assertAlmostEqual(ts.min_ms, 100.0)
        self.assertAlmostEqual(ts.max_ms, 100.0)

    def test_multiple_samples(self):
        ts = TimingStats(samples_ms=[100.0, 200.0, 150.0])
        self.assertAlmostEqual(ts.median_ms, 150.0)
        self.assertAlmostEqual(ts.mean_ms, 150.0)
        self.assertGreater(ts.stddev_ms, 0.0)
        self.assertAlmostEqual(ts.min_ms, 100.0)
        self.assertAlmostEqual(ts.max_ms, 200.0)

    def test_empty_samples(self):
        ts = TimingStats(samples_ms=[])
        self.assertEqual(ts.median_ms, 0.0)
        self.assertEqual(ts.mean_ms, 0.0)
        self.assertEqual(ts.stddev_ms, 0.0)

    def test_to_dict_keys(self):
        ts = TimingStats(samples_ms=[50.0, 60.0, 55.0])
        d = ts.to_dict()
        for key in ("samples_ms", "median_ms", "mean_ms", "stddev_ms", "min_ms", "max_ms"):
            self.assertIn(key, d)

    def test_from_dict_round_trip(self):
        ts = TimingStats(samples_ms=[80.0, 90.0, 100.0])
        d = ts.to_dict()
        ts2 = TimingStats.from_dict(d)
        self.assertEqual(ts2.samples_ms, ts.samples_ms)
        self.assertAlmostEqual(ts2.median_ms, ts.median_ms)

    def test_high_jitter_reflected_in_stddev(self):
        """Wide spread of timing samples must produce high stddev."""
        ts = TimingStats(samples_ms=[10.0, 5000.0, 25.0, 4800.0])
        self.assertGreater(ts.stddev_ms, 500.0, "High jitter should yield large stddev")

    def test_low_jitter_reflected_in_stddev(self):
        """Tightly clustered samples must produce low stddev."""
        ts = TimingStats(samples_ms=[100.0, 101.0, 99.5, 100.5])
        self.assertLess(ts.stddev_ms, 5.0, "Low jitter should yield small stddev")


# ===========================================================================
# RequestSpec redaction tests
# ===========================================================================


class TestRequestSpecRedaction(unittest.TestCase):
    """RequestSpec.to_dict() must redact sensitive header/cookie values."""

    def test_authorization_header_redacted(self):
        req = RequestSpec(
            method="GET",
            url="https://example.com/api",
            headers={"Authorization": "Bearer supersecrettoken123"},
        )
        d = req.to_dict()
        self.assertEqual(d["headers"]["Authorization"], "<REDACTED>")

    def test_cookie_values_redacted(self):
        req = RequestSpec(
            url="https://example.com/api",
            cookies={"session": "abc123xyz"},
        )
        d = req.to_dict()
        self.assertTrue(
            all(v == "<REDACTED>" for v in d["cookies"].values()),
            "All cookie values must be redacted",
        )

    def test_api_key_header_redacted(self):
        req = RequestSpec(
            url="https://example.com/api",
            headers={"X-Api-Key": "my-secret-api-key"},
        )
        d = req.to_dict()
        self.assertEqual(d["headers"]["X-Api-Key"], "<REDACTED>")

    def test_non_sensitive_headers_preserved(self):
        req = RequestSpec(
            url="https://example.com/api",
            headers={"Content-Type": "application/json", "Accept": "text/html"},
        )
        d = req.to_dict()
        self.assertEqual(d["headers"]["Content-Type"], "application/json")
        self.assertEqual(d["headers"]["Accept"], "text/html")

    def test_empty_headers_omitted(self):
        req = RequestSpec(url="https://example.com/api")
        d = req.to_dict()
        self.assertNotIn("headers", d)
        self.assertNotIn("cookies", d)

    def test_from_dict_round_trip(self):
        req = RequestSpec(
            method="POST",
            url="https://example.com/login",
            params={"next": "/dashboard"},
            headers={"Content-Type": "application/json"},
            body='{"username": "test"}',
        )
        req2 = RequestSpec.from_dict(req.to_dict())
        self.assertEqual(req2.method, req.method)
        self.assertEqual(req2.url, req.url)


# ===========================================================================
# EvidencePack construction and serialisation tests
# ===========================================================================


class TestEvidencePackConstruction(unittest.TestCase):
    """EvidencePack must be constructable and serialisable."""

    def _make_pack(self, finding_id: str = "test-finding-001") -> EvidencePack:
        return EvidencePack(
            finding_id=finding_id,
            url="https://example.com/search",
            request=RequestSpec(
                method="GET",
                url="https://example.com/search",
                params={"q": "' OR 1=1--"},
                headers={"Accept": "text/html"},
            ),
            baseline_signature="aabbcc112233",
            mutated_signature="ddeeff445566",
            diff_summary={
                "changed": True,
                "ratio": 0.42,
                "length_delta": 312,
                "summary": "Substantial difference detected.",
            },
            timing_stats=TimingStats(samples_ms=[120.0, 118.5, 122.0]),
            payload_ids=["sqli-bool-001"],
            deterministic_seed=42,
            parameter="q",
            parameter_location="query_param",
            technique="boolean",
            db_type="mysql",
        )

    def test_construction_succeeds(self):
        pack = self._make_pack()
        self.assertEqual(pack.finding_id, "test-finding-001")
        self.assertIsNotNone(pack.timing_stats)

    def test_to_dict_contains_required_keys(self):
        pack = self._make_pack()
        d = pack.to_dict()
        for key in (
            "schema_version", "finding_id", "url", "request",
            "baseline_signature", "mutated_signature", "diff_summary",
            "timing_stats", "payload_ids", "deterministic_seed",
            "captured_at", "parameter", "technique", "db_type", "repro",
        ):
            self.assertIn(key, d, f"Missing key: {key}")

    def test_to_dict_repro_keys(self):
        pack = self._make_pack()
        repro = pack.to_dict()["repro"]
        self.assertIn("curl", repro)
        self.assertIn("python", repro)

    def test_schema_version(self):
        pack = self._make_pack()
        self.assertEqual(pack.to_dict()["schema_version"], "1.0")

    def test_json_serialisable(self):
        pack = self._make_pack()
        raw = json.dumps(pack.to_dict())
        self.assertIsInstance(raw, str)
        parsed = json.loads(raw)
        self.assertEqual(parsed["finding_id"], "test-finding-001")


# ===========================================================================
# EvidencePack JSON round-trip (save / load)
# ===========================================================================


class TestEvidencePackPersistence(unittest.TestCase):
    """EvidencePack.save() / EvidencePack.load() must be a lossless round-trip."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="megido_ep_test_")

    def _make_pack(self, finding_id: str = "round-trip-001") -> EvidencePack:
        return EvidencePack(
            finding_id=finding_id,
            url="https://target.example.com/item/42",
            request=RequestSpec(
                method="POST",
                url="https://target.example.com/item/42",
                params={},
                headers={"Content-Type": "application/json"},
                json_data={"id": "' OR 1=1--"},
            ),
            baseline_signature="baseline_sig_abc",
            mutated_signature="mutated_sig_def",
            diff_summary={"changed": True, "ratio": 0.3, "length_delta": 500},
            timing_stats=TimingStats(samples_ms=[200.0, 210.0, 205.0]),
            payload_ids=["sqli-err-mysql-001", "sqli-err-mysql-002"],
            deterministic_seed=99,
            parameter="id",
            parameter_location="json_param",
            technique="error",
            db_type="mysql",
        )

    def test_save_creates_file(self):
        pack = self._make_pack()
        path = os.path.join(self._tmpdir, "ep.json")
        pack.save(path)
        self.assertTrue(os.path.exists(path))

    def test_load_after_save(self):
        pack = self._make_pack()
        path = os.path.join(self._tmpdir, "ep_rt.json")
        pack.save(path)
        loaded = EvidencePack.load(path)
        self.assertEqual(loaded.finding_id, pack.finding_id)
        self.assertEqual(loaded.url, pack.url)
        self.assertEqual(loaded.baseline_signature, pack.baseline_signature)
        self.assertEqual(loaded.mutated_signature, pack.mutated_signature)
        self.assertEqual(loaded.deterministic_seed, pack.deterministic_seed)
        self.assertEqual(loaded.payload_ids, pack.payload_ids)
        self.assertEqual(loaded.parameter, pack.parameter)
        self.assertEqual(loaded.technique, pack.technique)
        self.assertEqual(loaded.db_type, pack.db_type)

    def test_load_timing_stats(self):
        pack = self._make_pack()
        path = os.path.join(self._tmpdir, "ep_timing.json")
        pack.save(path)
        loaded = EvidencePack.load(path)
        self.assertIsNotNone(loaded.timing_stats)
        self.assertEqual(loaded.timing_stats.samples_ms, [200.0, 210.0, 205.0])

    def test_load_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            EvidencePack.load("/tmp/does_not_exist_xyz_megido.json")

    def test_parent_dirs_created(self):
        pack = self._make_pack()
        nested = os.path.join(self._tmpdir, "a", "b", "c", "ep.json")
        pack.save(nested)
        self.assertTrue(os.path.exists(nested))


# ===========================================================================
# Repro script redaction tests
# ===========================================================================


class TestReproScriptRedaction(unittest.TestCase):
    """Curl and Python repro scripts must not expose sensitive values."""

    def _make_pack_with_auth(self) -> EvidencePack:
        return EvidencePack(
            finding_id="auth-pack-001",
            url="https://api.example.com/users",
            request=RequestSpec(
                method="GET",
                url="https://api.example.com/users",
                params={"id": "1' AND 1=1--"},
                headers={
                    "Authorization": "Bearer mysupersecrettoken",
                    "X-Api-Key": "deadbeef1234",
                    "Accept": "application/json",
                },
                cookies={"session": "sessionvalue123"},
            ),
            baseline_signature="base_sig",
            mutated_signature="muta_sig",
            diff_summary={"changed": True},
        )

    def test_curl_redacts_auth_header(self):
        pack = self._make_pack_with_auth()
        curl = pack.to_curl()
        self.assertNotIn("mysupersecrettoken", curl)
        self.assertNotIn("deadbeef1234", curl)
        self.assertIn("<REDACTED>", curl)

    def test_curl_redacts_cookie(self):
        pack = self._make_pack_with_auth()
        curl = pack.to_curl()
        self.assertNotIn("sessionvalue123", curl)

    def test_python_repro_redacts_auth_header(self):
        pack = self._make_pack_with_auth()
        script = pack.to_python_repro()
        self.assertNotIn("mysupersecrettoken", script)
        self.assertNotIn("deadbeef1234", script)

    def test_python_repro_redacts_cookie(self):
        pack = self._make_pack_with_auth()
        script = pack.to_python_repro()
        self.assertNotIn("sessionvalue123", script)

    def test_python_repro_contains_url(self):
        pack = self._make_pack_with_auth()
        script = pack.to_python_repro()
        self.assertIn("api.example.com", script)

    def test_python_repro_is_runnable_syntax(self):
        """The generated Python script must at least parse without SyntaxErrors."""
        pack = self._make_pack_with_auth()
        script = pack.to_python_repro()
        # compile() will raise SyntaxError if the script is malformed
        compile(script, "<repro>", "exec")


# ===========================================================================
# LocalFileStorage tests
# ===========================================================================


class TestLocalFileStorage(unittest.TestCase):
    """LocalFileStorage CRUD operations."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="megido_storage_test_")
        self._store = LocalFileStorage(self._tmpdir)

    def _make_pack(self, finding_id: str) -> EvidencePack:
        return EvidencePack(
            finding_id=finding_id,
            url="https://example.com/test",
            request=RequestSpec(url="https://example.com/test"),
            baseline_signature="bsig",
            mutated_signature="msig",
            diff_summary={"changed": False},
        )

    def test_save_returns_path(self):
        pack = self._make_pack("storage-001")
        path = self._store.save(pack)
        self.assertTrue(os.path.exists(path))

    def test_load_by_finding_id(self):
        pack = self._make_pack("storage-002")
        self._store.save(pack)
        loaded = self._store.load("storage-002")
        self.assertEqual(loaded.finding_id, "storage-002")

    def test_load_missing_raises_key_error(self):
        with self.assertRaises(KeyError):
            self._store.load("does-not-exist-xyz")

    def test_list_all_returns_saved_packs(self):
        for i in range(3):
            self._store.save(self._make_pack(f"list-test-{i:03d}"))
        packs = self._store.list_all()
        ids = {p.finding_id for p in packs}
        for i in range(3):
            self.assertIn(f"list-test-{i:03d}", ids)

    def test_delete_existing(self):
        pack = self._make_pack("del-001")
        self._store.save(pack)
        result = self._store.delete("del-001")
        self.assertTrue(result)
        with self.assertRaises(KeyError):
            self._store.load("del-001")

    def test_delete_nonexistent_returns_false(self):
        result = self._store.delete("never-existed-xyz")
        self.assertFalse(result)

    def test_list_all_sorted_by_captured_at(self):
        """list_all() must return packs in captured_at ascending order."""
        import time

        ids_in_order = []
        for i in range(3):
            pack = self._make_pack(f"order-{i:03d}")
            self._store.save(pack)
            ids_in_order.append(pack.finding_id)
            time.sleep(0.01)  # ensure distinct captured_at values

        packs = self._store.list_all()
        returned_ids = [p.finding_id for p in packs if p.finding_id.startswith("order-")]
        # Check ordering is non-decreasing by captured_at
        dates = [p.captured_at for p in packs if p.finding_id.startswith("order-")]
        self.assertEqual(dates, sorted(dates))


# ===========================================================================
# VerificationProfile tests
# ===========================================================================


class TestVerificationProfile(unittest.TestCase):
    """VerificationProfile maps correctly to OperationMode."""

    def test_detect_only_maps_to_detect(self):
        profile = VerificationProfile.DETECT_ONLY
        self.assertEqual(profile.to_operation_mode(), OperationMode.DETECT)

    def test_verify_safe_maps_to_verify(self):
        profile = VerificationProfile.VERIFY_SAFE
        self.assertEqual(profile.to_operation_mode(), OperationMode.VERIFY)

    def test_from_string_detect_only(self):
        self.assertEqual(
            VerificationProfile.from_string("detect_only"),
            VerificationProfile.DETECT_ONLY,
        )

    def test_from_string_verify_safe(self):
        self.assertEqual(
            VerificationProfile.from_string("VERIFY_SAFE"),
            VerificationProfile.VERIFY_SAFE,
        )

    def test_from_string_invalid_raises(self):
        with self.assertRaises(ValueError):
            VerificationProfile.from_string("exploit_all")

    def test_detect_only_mode_blocks_verify(self):
        from sql_attacker.engine.modes import ModePolicy
        mode = VerificationProfile.DETECT_ONLY.to_operation_mode()
        policy = ModePolicy(mode)
        with self.assertRaises(ModeViolationError):
            policy.assert_may_verify()

    def test_verify_safe_mode_allows_verify(self):
        from sql_attacker.engine.modes import ModePolicy
        mode = VerificationProfile.VERIFY_SAFE.to_operation_mode()
        policy = ModePolicy(mode)
        # Should not raise
        policy.assert_may_verify()


# ===========================================================================
# ScanConfig safety field tests
# ===========================================================================


class TestScanConfigSafetyFields(unittest.TestCase):
    """New ScanConfig safety fields must validate correctly."""

    def test_defaults_are_safe(self):
        cfg = ScanConfig()
        cfg.validate()  # must not raise
        self.assertIsNone(cfg.global_request_cap)
        self.assertGreater(cfg.error_spike_abort_threshold, 0)
        self.assertFalse(cfg.inject_path_segments)
        self.assertFalse(cfg.inject_graphql_vars)

    def test_global_request_cap_valid(self):
        cfg = ScanConfig(global_request_cap=500)
        cfg.validate()  # must not raise
        self.assertEqual(cfg.global_request_cap, 500)

    def test_global_request_cap_zero_invalid(self):
        cfg = ScanConfig(global_request_cap=0)
        with self.assertRaises(ValueError):
            cfg.validate()

    def test_global_request_cap_negative_invalid(self):
        cfg = ScanConfig(global_request_cap=-1)
        with self.assertRaises(ValueError):
            cfg.validate()

    def test_error_spike_threshold_zero_disables_killswitch(self):
        """threshold=0 should be valid (disables the kill-switch)."""
        cfg = ScanConfig(error_spike_abort_threshold=0)
        cfg.validate()  # must not raise

    def test_error_spike_threshold_negative_invalid(self):
        cfg = ScanConfig(error_spike_abort_threshold=-1)
        with self.assertRaises(ValueError):
            cfg.validate()

    def test_inject_path_segments_opt_in(self):
        cfg = ScanConfig(inject_path_segments=True)
        cfg.validate()
        self.assertTrue(cfg.inject_path_segments)

    def test_inject_graphql_vars_opt_in(self):
        cfg = ScanConfig(inject_graphql_vars=True)
        cfg.validate()
        self.assertTrue(cfg.inject_graphql_vars)


# ===========================================================================
# _redact helper tests
# ===========================================================================


class TestRedactHelpers(unittest.TestCase):
    """Internal redaction helpers must strip known secret patterns."""

    def test_bearer_token_redacted(self):
        text = "Authorization: Bearer abcdef1234567890abcdef"
        result = _redact(text)
        self.assertNotIn("abcdef1234567890abcdef", result)
        self.assertIn("<REDACTED>", result)

    def test_api_key_redacted(self):
        text = "api_key=supersecretapikey123"
        result = _redact(text)
        self.assertNotIn("supersecretapikey123", result)

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = _redact(jwt)
        self.assertIn("<JWT_REDACTED>", result)

    def test_non_sensitive_text_unchanged(self):
        text = "Content-Type: application/json"
        self.assertEqual(_redact(text), text)

    def test_redact_dict_sensitive_keys(self):
        d = {
            "Authorization": "Bearer token123",
            "Content-Type": "application/json",
            "x-api-key": "mysecretkey",
        }
        result = _redact_dict(d)
        self.assertEqual(result["Authorization"], "<REDACTED>")
        self.assertEqual(result["x-api-key"], "<REDACTED>")
        self.assertEqual(result["Content-Type"], "application/json")


if __name__ == "__main__":
    unittest.main()
