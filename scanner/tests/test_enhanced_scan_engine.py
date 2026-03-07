"""
Tests for the enhanced ScanEngine features:
- scan_with_profile()
- _deduplicate_findings()
- _pre_scan_recon()
- stealth delay integration
- scan_concurrent()
- retry logic
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import threading

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scan_engine import ScanEngine
from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(vuln_type='xss', url='https://example.com', param='q',
                  confidence=0.8, evidence='test evidence'):
    return VulnerabilityFinding(
        vulnerability_type=vuln_type,
        severity='high',
        url=url,
        description='Test finding',
        evidence=evidence,
        remediation='Fix it',
        parameter=param,
        confidence=confidence,
    )


def _make_engine(**kwargs):
    """Create a ScanEngine with a mocked registry and post-scan infrastructure."""
    engine = ScanEngine.__new__(ScanEngine)
    engine.registry = MagicMock()
    engine.registry.get_all_plugins.return_value = []
    engine.registry.get_plugin_count.return_value = 0
    engine.registry.list_plugins.return_value = []
    engine.finding_tracker = MagicMock()
    engine.impact_analyzer = MagicMock()
    engine._tracker_client = None
    engine.enable_stealth = kwargs.get('enable_stealth', False)
    engine.stealth_timing = kwargs.get('stealth_timing', 'normal')
    engine._stealth_engine = None
    return engine


# ---------------------------------------------------------------------------
# _deduplicate_findings
# ---------------------------------------------------------------------------

class TestDeduplicateFindings:
    def test_no_duplicates_unchanged(self):
        engine = _make_engine()
        f1 = _make_finding('xss', param='a')
        f2 = _make_finding('sqli', param='b')
        result = engine._deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_exact_duplicate_removed(self):
        engine = _make_engine()
        f1 = _make_finding(confidence=0.7, evidence='ev1')
        f2 = _make_finding(confidence=0.5, evidence='ev2')  # same key as f1
        result = engine._deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_evidence_merged_on_duplicate(self):
        engine = _make_engine()
        f1 = _make_finding(confidence=0.7, evidence='evidence A')
        f2 = _make_finding(confidence=0.5, evidence='evidence B')
        result = engine._deduplicate_findings([f1, f2])
        assert 'evidence A' in result[0].evidence
        assert 'evidence B' in result[0].evidence

    def test_highest_confidence_wins(self):
        engine = _make_engine()
        f_low = _make_finding(confidence=0.3, evidence='low conf')
        f_high = _make_finding(confidence=0.95, evidence='high conf')
        result = engine._deduplicate_findings([f_low, f_high])
        assert len(result) == 1
        assert result[0].confidence == 0.95

    def test_different_url_not_deduplicated(self):
        engine = _make_engine()
        f1 = _make_finding(url='https://a.com')
        f2 = _make_finding(url='https://b.com')
        result = engine._deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_parameter_not_deduplicated(self):
        engine = _make_engine()
        f1 = _make_finding(param='name')
        f2 = _make_finding(param='email')
        result = engine._deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        engine = _make_engine()
        assert engine._deduplicate_findings([]) == []

    def test_three_duplicates_collapse_to_one(self):
        engine = _make_engine()
        findings = [_make_finding(confidence=0.5 + i * 0.1) for i in range(3)]
        result = engine._deduplicate_findings(findings)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _pre_scan_recon
# ---------------------------------------------------------------------------

class TestPreScanRecon:
    def test_recon_populates_config_key(self):
        engine = _make_engine()
        config = {}
        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {
                'Server': 'nginx/1.18',
                'X-Powered-By': 'PHP/8.1',
            }
            mock_resp.status_code = 200
            mock_get.return_value = mock_resp
            updated = engine._pre_scan_recon('https://example.com', config)
        assert 'recon' in updated

    def test_recon_detects_technologies(self):
        engine = _make_engine()
        config = {}
        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {
                'Server': 'Apache/2.4',
                'X-Powered-By': 'PHP/8.0',
            }
            mock_resp.status_code = 200
            mock_get.return_value = mock_resp
            updated = engine._pre_scan_recon('https://example.com', config)
        techs = updated['recon']['technologies']
        assert 'apache' in techs
        assert 'php' in techs

    def test_recon_on_network_failure_still_returns_config(self):
        engine = _make_engine()
        config = {'timeout': 5}
        with patch('requests.get', side_effect=Exception('network error')):
            updated = engine._pre_scan_recon('https://example.com', config)
        assert 'recon' in updated
        assert updated['recon']['waf_detected'] is False


# ---------------------------------------------------------------------------
# scan_with_profile
# ---------------------------------------------------------------------------

class TestScanWithProfile:
    def _engine_with_no_plugins(self):
        engine = _make_engine()
        engine.registry.get_all_plugins.return_value = []
        return engine

    def test_known_profile_runs_without_error(self):
        engine = self._engine_with_no_plugins()
        with patch.object(engine, '_pre_scan_recon', return_value={}), \
             patch.object(engine, 'scan', return_value=[]) as mock_scan, \
             patch.object(engine, 'scan_concurrent', return_value=[]) as mock_concurrent:
            engine.scan_with_profile('https://example.com', 'balanced')
            # balanced profile uses max_workers=3 so calls scan_concurrent
            assert mock_scan.called or mock_concurrent.called

    def test_unknown_profile_raises_value_error(self):
        engine = self._engine_with_no_plugins()
        import pytest
        with pytest.raises(ValueError, match="Unknown scan profile"):
            engine.scan_with_profile('https://example.com', 'nonexistent')

    def test_all_builtin_profiles_accepted(self):
        engine = self._engine_with_no_plugins()
        for profile_name in ScanEngine.SCAN_PROFILES:
            engine2 = self._engine_with_no_plugins()
            with patch.object(engine2, '_pre_scan_recon', return_value={}), \
                 patch.object(engine2, 'scan', return_value=[]), \
                 patch.object(engine2, 'scan_concurrent', return_value=[]):
                # Should not raise
                engine2.scan_with_profile('https://example.com', profile_name)

    def test_stealth_profile_enables_stealth(self):
        engine = self._engine_with_no_plugins()
        with patch.object(engine, '_pre_scan_recon', return_value={}), \
             patch.object(engine, 'scan', return_value=[]):
            engine.scan_with_profile('https://example.com', 'stealth')
        # After profile application, stealth timing should be paranoid
        assert engine.stealth_timing == 'paranoid'


# ---------------------------------------------------------------------------
# Stealth delay between plugins
# ---------------------------------------------------------------------------

class TestStealthDelay:
    def test_no_delay_when_stealth_disabled(self):
        engine = _make_engine(enable_stealth=False)
        import time
        t_start = time.time()
        engine._apply_stealth_delay()
        elapsed = time.time() - t_start
        assert elapsed < 0.1

    def test_no_delay_for_normal_timing(self):
        engine = _make_engine(enable_stealth=True, stealth_timing='normal')
        import time
        t_start = time.time()
        engine._apply_stealth_delay()
        elapsed = time.time() - t_start
        assert elapsed < 0.1


# ---------------------------------------------------------------------------
# scan() — retry logic
# ---------------------------------------------------------------------------

class TestRetryLogic:
    def test_failing_plugin_is_skipped_after_retries(self):
        engine = _make_engine()
        bad_plugin = MagicMock()
        bad_plugin.name = 'BadPlugin'
        bad_plugin.scan.side_effect = RuntimeError('broken')
        result = engine._run_plugin_with_retry(bad_plugin, 'https://example.com', {}, max_retries=2)
        assert result == []
        assert bad_plugin.scan.call_count == 3  # initial + 2 retries

    def test_plugin_succeeds_on_second_attempt(self):
        engine = _make_engine()
        finding = _make_finding()
        plugin = MagicMock()
        plugin.name = 'FlakyPlugin'
        plugin.scan.side_effect = [RuntimeError('first failure'), [finding]]
        result = engine._run_plugin_with_retry(plugin, 'https://example.com', {}, max_retries=2)
        assert len(result) == 1
        assert result[0] is finding

    def test_successful_plugin_not_retried(self):
        engine = _make_engine()
        finding = _make_finding()
        plugin = MagicMock()
        plugin.name = 'GoodPlugin'
        plugin.scan.return_value = [finding]
        result = engine._run_plugin_with_retry(plugin, 'https://example.com', {}, max_retries=3)
        assert len(result) == 1
        assert plugin.scan.call_count == 1


# ---------------------------------------------------------------------------
# scan_concurrent()
# ---------------------------------------------------------------------------

class TestScanConcurrent:
    def test_concurrent_aggregates_findings_from_all_plugins(self):
        engine = _make_engine()
        findings_p1 = [_make_finding('xss', param='a')]
        findings_p2 = [_make_finding('sqli', param='b')]

        plugin1 = MagicMock()
        plugin1.name = 'P1'
        plugin1.scan.return_value = findings_p1

        plugin2 = MagicMock()
        plugin2.name = 'P2'
        plugin2.scan.return_value = findings_p2

        engine.registry.get_all_plugins.return_value = [plugin1, plugin2]

        with patch.object(engine, '_post_scan_process'):
            results = engine.scan_concurrent('https://example.com', max_workers=2)

        assert len(results) == 2

    def test_concurrent_handles_plugin_error(self):
        engine = _make_engine()
        bad_plugin = MagicMock()
        bad_plugin.name = 'Bad'
        bad_plugin.scan.side_effect = RuntimeError('crash')

        good_finding = _make_finding('xss')
        good_plugin = MagicMock()
        good_plugin.name = 'Good'
        good_plugin.scan.return_value = [good_finding]

        engine.registry.get_all_plugins.return_value = [bad_plugin, good_plugin]

        with patch.object(engine, '_post_scan_process'):
            results = engine.scan_concurrent('https://example.com', max_workers=2)

        # Good plugin findings should still be present
        assert any(f.vulnerability_type == 'xss' for f in results)
