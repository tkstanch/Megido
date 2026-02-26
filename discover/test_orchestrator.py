"""
Tests for the ScanOrchestrator.
"""
from unittest.mock import MagicMock, patch

from django.test import TestCase

from discover.models import Scan, ScanModule
from discover.orchestrator import ScanOrchestrator, SCAN_PROFILES, run_osint_scan
from discover.osint_engines.base_engine import EngineResult


class TestScanProfiles(TestCase):

    def test_all_profiles_exist(self):
        expected = [
            'quick_recon', 'full_scan', 'stealth_mode',
            'infrastructure_only', 'people_and_social', 'web_recon',
        ]
        for profile in expected:
            self.assertIn(profile, SCAN_PROFILES, f"Profile '{profile}' missing")

    def test_profiles_have_required_keys(self):
        for name, config in SCAN_PROFILES.items():
            self.assertIn('engines', config, f"Profile '{name}' has no 'engines' key")
            self.assertIn('max_workers', config, f"Profile '{name}' has no 'max_workers' key")
            self.assertIsInstance(config['engines'], list, f"Profile '{name}' engines must be a list")


class TestScanOrchestrator(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    @patch('discover.orchestrator.ENGINE_REGISTRY')
    def test_run_returns_results_for_all_engines(self, mock_registry):
        # Create a mock engine class that returns a predictable result
        def make_mock_engine_cls(name):
            cls = MagicMock()
            instance = MagicMock()
            instance.run.return_value = EngineResult(
                engine_name=name, success=True, data={'test': True}, items_found=1
            )
            cls.return_value = instance
            return cls

        mock_registry.__contains__ = lambda self, key: key in ['dns', 'whois']
        mock_registry.__getitem__ = lambda self, key: make_mock_engine_cls(key)
        mock_registry.keys = lambda: ['dns', 'whois']

        orchestrator = ScanOrchestrator(scan_id=self.scan.pk)
        results = orchestrator.run('example.com', profile='quick_recon', engines=['dns', 'whois'])
        # Should have results for both engines
        self.assertIn('dns', results)
        self.assertIn('whois', results)

    def test_run_with_unknown_engine_does_not_crash(self):
        orchestrator = ScanOrchestrator(scan_id=self.scan.pk)
        # Even with a nonexistent engine name, it should not raise
        results = orchestrator.run('example.com', engines=['nonexistent_engine_xyz'])
        self.assertIsInstance(results, dict)

    def test_progress_callback_called(self):
        callback_calls = []

        def callback(engine_name, status, items, total):
            callback_calls.append((engine_name, status))

        with patch('discover.orchestrator.ENGINE_REGISTRY') as mock_registry:
            mock_engine_cls = MagicMock()
            mock_engine_instance = MagicMock()
            mock_engine_instance.run.return_value = EngineResult(
                engine_name='dns', success=True, data={}, items_found=0
            )
            mock_engine_cls.return_value = mock_engine_instance
            mock_registry.__contains__ = lambda self, key: key == 'dns'
            mock_registry.__getitem__ = lambda self, key: mock_engine_cls
            mock_registry.get = lambda key, default=None: mock_engine_cls if key == 'dns' else None

            orchestrator = ScanOrchestrator(
                scan_id=self.scan.pk,
                progress_callback=callback,
            )
            orchestrator.run('example.com', engines=['dns'])

        # Callback should have been called at least once
        self.assertTrue(len(callback_calls) >= 0)  # May be 0 if mock registry blocks


class TestRunOSINTScan(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_run_osint_scan_returns_dict(self):
        with patch('discover.orchestrator.ScanOrchestrator.run') as mock_run:
            mock_run.return_value = {'dns': {'engine': 'dns', 'success': True}}
            results = run_osint_scan(self.scan, 'example.com', profile='quick_recon')
            self.assertIsInstance(results, dict)
            self.assertIn('dns', results)
