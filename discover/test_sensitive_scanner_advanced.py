"""
Tests for the Advanced Vulnerability Scanner Module
"""
import unittest
import tempfile
import os
import json
from datetime import datetime
from unittest.mock import Mock, patch
from discover.sensitive_scanner_advanced import (
    RiskLevel,
    RiskScore,
    RiskScoringEngine,
    IncrementalScanner,
    FalsePositiveManager,
    FindingClassification,
    ComplianceMapper,
    ComplianceFramework,
    RemediationEngine,
    PerformanceProfiler,
    PluginInterface,
    PluginManager,
    AdvancedVulnerabilityScanner,
    GitSecretsScannerPlugin
)


class TestRiskScoringSystem(unittest.TestCase):
    """Tests for risk scoring functionality."""
    
    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        score = RiskScore(
            base_severity='critical',
            context_factor=2.0,
            exposure_factor=1.5,
            age_factor=1.0,
            entropy_factor=0.8
        )
        
        self.assertGreater(score.composite_score, 0)
        self.assertLessEqual(score.composite_score, 100)
        self.assertEqual(score.risk_level, 'critical')
    
    def test_risk_levels(self):
        """Test different risk levels."""
        critical = RiskScore('critical', 2.0, 2.0, 1.0, 1.0)
        self.assertEqual(critical.risk_level, 'critical')
        
        low = RiskScore('low', 0.0, 0.0, 1.0, 0.0)
        # Low severity with minimal factors results in 'info' level
        self.assertIn(low.risk_level, ['low', 'info'])
    
    def test_risk_scoring_engine(self):
        """Test risk scoring engine."""
        engine = RiskScoringEngine(exposure_level='high')
        
        finding = {
            'type': 'AWS Access Key',
            'severity': 'critical',
            'source_type': 'file',
            'file_context': {'is_config_file': True}
        }
        
        risk_score = engine.calculate_risk_score(finding)
        self.assertIsInstance(risk_score, RiskScore)
        self.assertGreater(risk_score.composite_score, 50)
    
    def test_finding_prioritization(self):
        """Test finding prioritization by risk score."""
        engine = RiskScoringEngine()
        
        findings = [
            {'type': 'Email', 'severity': 'low'},
            {'type': 'AWS Key', 'severity': 'critical'},
            {'type': 'API Key', 'severity': 'high'}
        ]
        
        prioritized = engine.prioritize_findings(findings)
        
        # Should be sorted by risk score
        self.assertEqual(len(prioritized), 3)
        self.assertIn('risk_score', prioritized[0])
        
        # Critical should be first
        self.assertGreater(
            prioritized[0]['risk_score']['composite_score'],
            prioritized[2]['risk_score']['composite_score']
        )


class TestIncrementalScanning(unittest.TestCase):
    """Tests for incremental scanning."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_state = tempfile.NamedTemporaryFile(delete=False, suffix='.pkl')
        self.temp_state.close()
        self.scanner = IncrementalScanner(self.temp_state.name)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_state.name):
            os.unlink(self.temp_state.name)
    
    def test_checksum_calculation(self):
        """Test file checksum calculation."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_file = f.name
        
        try:
            checksum1 = self.scanner._calculate_checksum(temp_file)
            checksum2 = self.scanner._calculate_checksum(temp_file)
            
            self.assertEqual(checksum1, checksum2)
            self.assertNotEqual(checksum1, "")
        finally:
            os.unlink(temp_file)
    
    def test_file_change_detection(self):
        """Test detection of file changes."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("original content")
            temp_file = f.name
        
        try:
            # First scan - should be new
            self.assertTrue(self.scanner.has_file_changed(temp_file))
            
            # Update state
            self.scanner.update_file_state(temp_file, 0)
            
            # Second scan - should be unchanged
            self.assertFalse(self.scanner.has_file_changed(temp_file))
            
            # Modify file
            with open(temp_file, 'w') as f:
                f.write("modified content")
            
            # Should detect change
            self.assertTrue(self.scanner.has_file_changed(temp_file))
        finally:
            os.unlink(temp_file)
    
    def test_get_changed_files(self):
        """Test filtering of changed files."""
        files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(f"content {i}")
                files.append(f.name)
        
        try:
            # Initially all files are new
            changed = self.scanner.get_changed_files(files)
            self.assertEqual(len(changed), 3)
            
            # Update states
            for f in files:
                self.scanner.update_file_state(f, 0)
            
            # No files changed
            changed = self.scanner.get_changed_files(files)
            self.assertEqual(len(changed), 0)
            
            # Modify one file
            with open(files[1], 'w') as f:
                f.write("new content")
            
            # Only one file changed
            changed = self.scanner.get_changed_files(files)
            self.assertEqual(len(changed), 1)
            self.assertEqual(changed[0], files[1])
        finally:
            for f in files:
                if os.path.exists(f):
                    os.unlink(f)
    
    def test_state_persistence(self):
        """Test state persistence to disk."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            temp_file = f.name
        
        try:
            # Update state and save
            self.scanner.update_file_state(temp_file, 1)
            self.scanner.save()
            
            # Create new scanner instance
            scanner2 = IncrementalScanner(self.temp_state.name)
            
            # Should load previous state
            self.assertIn(temp_file, scanner2.file_states)
            self.assertEqual(scanner2.file_states[temp_file].findings_count, 1)
        finally:
            os.unlink(temp_file)


class TestFalsePositiveManagement(unittest.TestCase):
    """Tests for false positive management."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_allowlist = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_allowlist.close()
        self.manager = FalsePositiveManager(self.temp_allowlist.name)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_allowlist.name):
            os.unlink(self.temp_allowlist.name)
    
    def test_finding_hash_generation(self):
        """Test finding hash generation."""
        finding = {
            'type': 'AWS Key',
            'value': 'AKIAIOSFODNN7EXAMPLE',
            'source': 'test.py'
        }
        
        hash1 = self.manager._finding_hash(finding)
        hash2 = self.manager._finding_hash(finding)
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 16)
    
    def test_classify_finding(self):
        """Test finding classification."""
        finding = {
            'type': 'AWS Key',
            'value': 'test_key',
            'source': 'test.py'
        }
        
        self.manager.classify_finding(
            finding,
            'false_positive',
            'This is a test key',
            'test_user'
        )
        
        self.assertTrue(self.manager.is_false_positive(finding))
    
    def test_filter_findings(self):
        """Test filtering false positives."""
        findings = [
            {'type': 'AWS Key', 'value': 'key1', 'source': 'a.py'},
            {'type': 'API Key', 'value': 'key2', 'source': 'b.py'},
            {'type': 'Secret', 'value': 'key3', 'source': 'c.py'}
        ]
        
        # Classify one as false positive
        self.manager.classify_finding(findings[1], 'false_positive', 'test', 'user')
        
        # Filter findings
        filtered = self.manager.filter_findings(findings)
        
        self.assertEqual(len(filtered), 2)
        self.assertNotIn(findings[1], filtered)
    
    def test_allowlist_persistence(self):
        """Test allowlist persistence."""
        finding = {'type': 'Test', 'value': 'test', 'source': 'test.py'}
        
        self.manager.classify_finding(finding, 'false_positive', 'test', 'user')
        
        # Create new manager instance
        manager2 = FalsePositiveManager(self.temp_allowlist.name)
        
        # Should load previous classifications
        self.assertTrue(manager2.is_false_positive(finding))


class TestComplianceMapping(unittest.TestCase):
    """Tests for compliance framework mapping."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mapper = ComplianceMapper()
    
    def test_compliance_mappings_initialization(self):
        """Test compliance mappings are initialized."""
        self.assertTrue(len(self.mapper.mappings) > 0)
    
    def test_get_compliance_mappings(self):
        """Test getting compliance mappings for finding."""
        finding = {
            'type': 'AWS Access Key',
            'value': 'AKIAIOSFODNN7EXAMPLE'
        }
        
        mappings = self.mapper.get_compliance_mappings(finding)
        
        self.assertTrue(len(mappings) > 0)
        self.assertTrue(any(m.framework == ComplianceFramework.GDPR for m in mappings))
    
    def test_compliance_report_generation(self):
        """Test compliance report generation."""
        findings = [
            {'type': 'AWS Access Key', 'value': 'test'},
            {'type': 'Credit Card Number', 'value': '1234'},
            {'type': 'Password Field', 'value': 'pass'}
        ]
        
        report = self.mapper.generate_compliance_report(findings)
        
        self.assertIn('frameworks', report)
        self.assertIn('requirement_counts', report)
        self.assertGreater(report['total_violations'], 0)


class TestRemediationEngine(unittest.TestCase):
    """Tests for remediation engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = RemediationEngine()
    
    def test_remediation_suggestions_initialization(self):
        """Test remediation suggestions are initialized."""
        self.assertTrue(len(self.engine.suggestions) > 0)
    
    def test_get_remediation(self):
        """Test getting remediation for finding."""
        finding = {
            'type': 'AWS Access Key',
            'value': 'AKIAIOSFODNN7EXAMPLE'
        }
        
        remediation = self.engine.get_remediation(finding)
        
        self.assertIsNotNone(remediation)
        self.assertIsNotNone(remediation.action)
        self.assertIsNotNone(remediation.description)
        self.assertIn(remediation.effort_estimate, ['low', 'medium', 'high'])
    
    def test_remediation_report_generation(self):
        """Test remediation report generation."""
        findings = [
            {'type': 'AWS Access Key', 'severity': 'critical'},
            {'type': 'Password Field', 'severity': 'high'},
            {'type': 'Email Address', 'severity': 'low'}
        ]
        
        report = self.engine.generate_remediation_report(findings)
        
        self.assertIn('remediations', report)
        self.assertIn('effort_distribution', report)
        self.assertIn('estimated_total_effort', report)
        self.assertEqual(len(report['remediations']), 3)


class TestPerformanceProfiler(unittest.TestCase):
    """Tests for performance profiler."""
    
    def test_profiler_basic_flow(self):
        """Test basic profiling flow."""
        profiler = PerformanceProfiler()
        
        profiler.start_scan('test_scan')
        
        # Simulate some work
        import time
        time.sleep(0.01)
        
        metrics = profiler.end_scan(
            files_scanned=10,
            urls_scanned=5,
            patterns_matched=20,
            findings_count=3
        )
        
        self.assertIsNotNone(metrics)
        self.assertEqual(metrics.files_scanned, 10)
        self.assertEqual(metrics.urls_scanned, 5)
        self.assertGreater(metrics.duration_seconds, 0)
    
    def test_profiler_statistics(self):
        """Test profiler statistics calculation."""
        profiler = PerformanceProfiler()
        
        # Run multiple scans
        for i in range(3):
            profiler.start_scan(f'scan_{i}')
            metrics = profiler.end_scan(
                files_scanned=i+1,
                urls_scanned=0,
                patterns_matched=10,
                findings_count=i
            )
        
        stats = profiler.get_statistics()
        
        self.assertEqual(stats['total_scans'], 3)
        self.assertGreater(stats['total_files_scanned'], 0)


class TestPluginSystem(unittest.TestCase):
    """Tests for plugin system."""
    
    def test_plugin_registration(self):
        """Test plugin registration."""
        manager = PluginManager()
        plugin = GitSecretsScannerPlugin()
        
        manager.register_plugin(plugin)
        
        self.assertEqual(len(manager.plugins), 1)
        self.assertIn(plugin.get_name(), manager.plugin_registry)
    
    def test_plugin_pre_scan_hook(self):
        """Test pre-scan hook execution."""
        manager = PluginManager()
        plugin = GitSecretsScannerPlugin()
        manager.register_plugin(plugin)
        
        targets = ['file1.py', 'file2.py', '.gitignore']
        filtered = manager.execute_pre_scan(targets)
        
        # Plugin should filter out .gitignore
        self.assertEqual(len(filtered), 2)
        self.assertNotIn('.gitignore', filtered)
    
    def test_plugin_analyze_finding(self):
        """Test analyze_finding hook."""
        manager = PluginManager()
        plugin = GitSecretsScannerPlugin()
        manager.register_plugin(plugin)
        
        finding = {
            'type': 'AWS Key',
            'source_type': 'file'
        }
        
        analyzed = manager.execute_analyze_finding(finding)
        
        # Plugin should add git metadata
        self.assertIn('git_metadata', analyzed)


class TestAdvancedScanner(unittest.TestCase):
    """Tests for advanced scanner integration."""
    
    def test_scanner_initialization(self):
        """Test advanced scanner initialization."""
        scanner = AdvancedVulnerabilityScanner(
            enable_risk_scoring=True,
            enable_incremental_scan=False,
            enable_false_positive_mgmt=True,
            enable_compliance_mapping=True,
            enable_remediation=True,
            enable_profiling=True,
            enable_plugins=False
        )
        
        self.assertIsNotNone(scanner.risk_scorer)
        self.assertIsNone(scanner.incremental_scanner)
        self.assertIsNotNone(scanner.fp_manager)
        self.assertIsNotNone(scanner.compliance_mapper)
        self.assertIsNotNone(scanner.remediation_engine)
        self.assertIsNotNone(scanner.profiler)
    
    def test_scan_with_advanced_features_files(self):
        """Test scanning files with advanced features."""
        # Create temporary test files
        files = []
        for i in range(2):
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
                f.write(f"aws_key = 'AKIAIOSFODNN7EXAMPL{i}'")
                files.append(f.name)
        
        try:
            scanner = AdvancedVulnerabilityScanner(
                enable_heuristics=False,
                enable_risk_scoring=True,
                enable_incremental_scan=False,
                enable_false_positive_mgmt=False,
                enable_compliance_mapping=True,
                enable_remediation=True,
                enable_profiling=True
            )
            
            result = scanner.scan_with_advanced_features(
                files,
                target_type='file',
                incremental=False
            )
            
            self.assertTrue(result['success'])
            self.assertEqual(result['scan_type'], 'file')
            self.assertEqual(result['targets_scanned'], 2)
            self.assertIn('findings', result)
            self.assertIn('compliance_report', result)
            self.assertIn('remediation_report', result)
            self.assertIn('performance_metrics', result)
            
            # Check risk scores were added
            if result['findings']:
                self.assertIn('risk_score', result['findings'][0])
        finally:
            for f in files:
                if os.path.exists(f):
                    os.unlink(f)
    
    @patch('discover.sensitive_scanner_enhanced.requests.get')
    def test_scan_with_advanced_features_urls(self, mock_get):
        """Test scanning URLs with advanced features."""
        mock_response = Mock()
        mock_response.text = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        scanner = AdvancedVulnerabilityScanner(
            enable_heuristics=False,
            enable_risk_scoring=True,
            enable_compliance_mapping=True
        )
        
        result = scanner.scan_with_advanced_features(
            ['http://example.com'],
            target_type='url',
            incremental=False
        )
        
        self.assertTrue(result['success'])
        self.assertEqual(result['scan_type'], 'url')


if __name__ == '__main__':
    unittest.main()
