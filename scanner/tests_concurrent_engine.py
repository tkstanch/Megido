"""
Tests for ConcurrentScanEngine

Covers:
- Concurrent execution of multiple plugins
- Plugin timeout handling
- Error isolation (one failing plugin does not stop others)
- Scan metrics reporting
- Deduplication integration
- scan_with_plugins() filtering
"""

import time
from unittest.mock import MagicMock, patch, PropertyMock
from django.test import SimpleTestCase as TestCase

from scanner.concurrent_scan_engine import ConcurrentScanEngine, ScanMetrics, PluginMetric
from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
from scanner.scan_plugins.scan_plugin_registry import reset_scan_registry


def _make_finding(vuln_type: str = 'xss', severity: str = 'high', url: str = 'https://example.com') -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_type=vuln_type,
        severity=severity,
        url=url,
        description='Test finding',
        evidence='Test evidence',
        remediation='Test remediation',
        confidence=0.8,
    )


def _mock_plugin(plugin_id: str, name: str, findings=None, delay: float = 0.0, raise_exc=None):
    """Create a mock BaseScanPlugin."""
    plugin = MagicMock()
    type(plugin).plugin_id = PropertyMock(return_value=plugin_id)
    type(plugin).name = PropertyMock(return_value=name)

    def _scan(url, config=None):
        if delay > 0:
            time.sleep(delay)
        if raise_exc:
            raise raise_exc
        return findings or []

    plugin.scan.side_effect = _scan
    return plugin


class TestConcurrentScanEngineInit(TestCase):
    """Test ConcurrentScanEngine initialisation."""

    def test_default_parameters(self):
        engine = ConcurrentScanEngine()
        self.assertEqual(engine.max_workers, 10)
        self.assertEqual(engine.plugin_timeout, 120)

    def test_custom_parameters(self):
        engine = ConcurrentScanEngine(max_workers=5, plugin_timeout=30)
        self.assertEqual(engine.max_workers, 5)
        self.assertEqual(engine.plugin_timeout, 30)

    def test_no_metrics_before_scan(self):
        engine = ConcurrentScanEngine()
        self.assertIsNone(engine.get_scan_metrics())


class TestConcurrentScanEngineExecution(TestCase):
    """Test concurrent plugin execution."""

    def setUp(self):
        reset_scan_registry()
        self.engine = ConcurrentScanEngine(max_workers=4, plugin_timeout=10)

    def _patch_registry(self, plugins):
        """Helper to patch the engine's registry with mock plugins."""
        self.engine.registry = MagicMock()
        self.engine.registry.get_all_plugins.return_value = plugins
        self.engine.registry.get_plugin.side_effect = lambda pid: next(
            (p for p in plugins if p.plugin_id == pid), None
        )

    def test_scan_aggregates_findings_from_all_plugins(self):
        finding_a = _make_finding('xss', 'high')
        finding_b = _make_finding('sqli', 'critical')
        plugins = [
            _mock_plugin('plugin_a', 'Plugin A', [finding_a]),
            _mock_plugin('plugin_b', 'Plugin B', [finding_b]),
        ]
        self._patch_registry(plugins)

        results = self.engine.scan('https://example.com')
        vuln_types = {f.vulnerability_type for f in results}
        self.assertIn('xss', vuln_types)
        self.assertIn('sqli', vuln_types)

    def test_scan_with_plugins_filters_correctly(self):
        finding_a = _make_finding('xss', 'high')
        finding_b = _make_finding('sqli', 'critical')
        plugins = [
            _mock_plugin('plugin_a', 'Plugin A', [finding_a]),
            _mock_plugin('plugin_b', 'Plugin B', [finding_b]),
        ]
        self._patch_registry(plugins)

        results = self.engine.scan_with_plugins(
            'https://example.com', ['plugin_a']
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].vulnerability_type, 'xss')

    def test_failing_plugin_does_not_stop_others(self):
        """Error in one plugin must not prevent other plugins from running."""
        finding_b = _make_finding('sqli', 'high')
        plugins = [
            _mock_plugin('plugin_a', 'Failing Plugin', raise_exc=RuntimeError('boom')),
            _mock_plugin('plugin_b', 'Good Plugin', [finding_b]),
        ]
        self._patch_registry(plugins)

        results = self.engine.scan('https://example.com')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].vulnerability_type, 'sqli')

    def test_scan_deduplicates_findings(self):
        """Identical findings from two plugins should be deduplicated."""
        finding_same_1 = _make_finding('xss', 'high', 'https://example.com/page')
        finding_same_2 = _make_finding('xss', 'high', 'https://example.com/page')
        plugins = [
            _mock_plugin('plugin_a', 'Plugin A', [finding_same_1]),
            _mock_plugin('plugin_b', 'Plugin B', [finding_same_2]),
        ]
        self._patch_registry(plugins)

        results = self.engine.scan('https://example.com')
        xss_findings = [f for f in results if f.vulnerability_type == 'xss']
        self.assertEqual(len(xss_findings), 1)

    def test_metrics_populated_after_scan(self):
        plugins = [_mock_plugin('plugin_a', 'Plugin A', [])]
        self._patch_registry(plugins)

        self.engine.scan('https://example.com')

        metrics = self.engine.get_scan_metrics()
        self.assertIsNotNone(metrics)
        self.assertIsInstance(metrics, ScanMetrics)
        self.assertEqual(metrics.plugin_count, 1)
        self.assertGreaterEqual(metrics.total_duration_seconds, 0)

    def test_metrics_contain_plugin_details(self):
        finding = _make_finding('xss', 'high')
        plugins = [_mock_plugin('plugin_a', 'Plugin A', [finding])]
        self._patch_registry(plugins)

        self.engine.scan('https://example.com')

        metrics = self.engine.get_scan_metrics()
        self.assertEqual(len(metrics.plugins), 1)
        pm: PluginMetric = metrics.plugins[0]
        self.assertEqual(pm.plugin_id, 'plugin_a')
        self.assertEqual(pm.plugin_name, 'Plugin A')
        self.assertEqual(pm.finding_count, 1)
        self.assertIsNone(pm.error)

    def test_metrics_capture_plugin_errors(self):
        plugins = [
            _mock_plugin('bad_plugin', 'Bad Plugin', raise_exc=ValueError('test error')),
        ]
        self._patch_registry(plugins)

        self.engine.scan('https://example.com')
        metrics = self.engine.get_scan_metrics()
        self.assertEqual(len(metrics.failed_plugins), 1)
        self.assertIn('test error', metrics.failed_plugins[0].error)

    def test_scan_with_missing_plugin_id(self):
        """Requesting a non-existent plugin ID should not crash."""
        self._patch_registry([])

        results = self.engine.scan_with_plugins('https://example.com', ['nonexistent'])
        self.assertEqual(results, [])

    def test_empty_plugin_list_returns_empty(self):
        self._patch_registry([])
        results = self.engine.scan('https://example.com')
        self.assertEqual(results, [])

    def test_metrics_dedup_reduction(self):
        finding_same = _make_finding('xss', 'high', 'https://example.com')
        plugins = [
            _mock_plugin('plugin_a', 'Plugin A', [finding_same]),
            _mock_plugin('plugin_b', 'Plugin B', [_make_finding('xss', 'high', 'https://example.com')]),
        ]
        self._patch_registry(plugins)

        self.engine.scan('https://example.com')
        metrics = self.engine.get_scan_metrics()
        self.assertGreaterEqual(metrics.total_findings_before_dedup, metrics.total_findings_after_dedup)
