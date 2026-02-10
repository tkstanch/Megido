"""
Comprehensive tests for Enterprise Vulnerability Scanner
"""
import unittest
import tempfile
import os
import json
from unittest.mock import Mock, patch, MagicMock
from discover.sensitive_scanner_enterprise import (
    CVEFeedManager,
    TransformerVulnerabilityDetector,
    RemediationCodeGenerator,
    ContainerScanner,
    DistributedScanCoordinator,
    EnterpriseVulnerabilityScanner,
    quick_enterprise_scan,
    HAS_REQUESTS,
    HAS_NUMPY
)


class TestCVEFeedManager(unittest.TestCase):
    """Tests for CVE feed integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cve_manager = CVEFeedManager()
    
    def test_initialization(self):
        """Test CVE manager initializes correctly."""
        self.assertIsNotNone(self.cve_manager)
        self.assertIsInstance(self.cve_manager.cache, dict)
        self.assertIsInstance(self.cve_manager.cache_timestamps, dict)
    
    def test_fetch_recent_cves_mock(self):
        """Test fetching CVEs returns mock data when API unavailable."""
        cves = self.cve_manager.fetch_recent_cves(days=7)
        
        self.assertIsInstance(cves, list)
        self.assertGreater(len(cves), 0)
        
        # Check CVE structure
        for cve in cves:
            self.assertIn('id', cve)
            self.assertIn('description', cve)
            self.assertIn('severity', cve)
            self.assertIn('score', cve)
    
    def test_enrich_finding_with_cve(self):
        """Test finding enrichment with CVE data."""
        finding = {
            'type': 'AWS Access Key',
            'value': 'AKIATEST123',
            'context': 'aws_key = "AKIATEST123"',
            'risk_score': {'composite_score': 75, 'risk_level': 'high'}
        }
        
        enriched = self.cve_manager.enrich_finding_with_cve(finding)
        
        self.assertIn('threat_intelligence', enriched)
        self.assertIn('related_cves', enriched['threat_intelligence'])
        self.assertIn('cve_count', enriched['threat_intelligence'])
    
    def test_cve_cache(self):
        """Test CVE caching mechanism."""
        # First fetch
        cves1 = self.cve_manager.fetch_recent_cves(days=7)
        
        # Second fetch should use cache
        cves2 = self.cve_manager.fetch_recent_cves(days=7)
        
        self.assertEqual(len(cves1), len(cves2))


class TestTransformerVulnerabilityDetector(unittest.TestCase):
    """Tests for advanced ML/AI detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = TransformerVulnerabilityDetector()
    
    def test_initialization(self):
        """Test detector initializes correctly."""
        self.assertIsNotNone(self.detector)
        self.assertTrue(self.detector.is_trained)
        self.assertIsNotNone(self.detector.feature_weights)
    
    def test_extract_advanced_features(self):
        """Test feature extraction."""
        text = "sk_live_abc123xyz"
        context = 'api_key = "sk_live_abc123xyz"'
        
        features = self.detector.extract_advanced_features(text, context)
        
        self.assertIsInstance(features, dict)
        self.assertIn('contains_key_pattern', features)
        self.assertIn('high_entropy', features)
        self.assertIn('assignment_context', features)
        
        # Check feature values are in range
        for feature_value in features.values():
            self.assertGreaterEqual(feature_value, 0.0)
            self.assertLessEqual(feature_value, 1.0)
    
    def test_predict_vulnerability(self):
        """Test vulnerability prediction."""
        text = "AKIAIOSFODNN7EXAMPLE"
        context = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        finding_type = "AWS Access Key"
        
        risk_score, explanation, features = self.detector.predict_vulnerability(
            text, context, finding_type
        )
        
        self.assertIsInstance(risk_score, float)
        self.assertGreaterEqual(risk_score, 0.0)
        self.assertLessEqual(risk_score, 1.0)
        self.assertIsInstance(explanation, str)
        self.assertIsInstance(features, dict)
    
    def test_entropy_calculation(self):
        """Test Shannon entropy calculation."""
        # High entropy string
        high_entropy = "aB3$xY9#kL2@"
        entropy_high = self.detector._calculate_entropy(high_entropy)
        
        # Low entropy string
        low_entropy = "aaaaaaa"
        entropy_low = self.detector._calculate_entropy(low_entropy)
        
        # High entropy should be greater
        self.assertGreater(entropy_high, entropy_low)
    
    def test_feature_weights(self):
        """Test feature weights are properly configured."""
        weights = self.detector.feature_weights
        
        self.assertGreater(len(weights), 0)
        
        # Check important features have high weights
        self.assertGreater(weights['contains_secret_pattern'], 2.0)
        self.assertGreater(weights['contains_key_pattern'], 2.0)


class TestRemediationCodeGenerator(unittest.TestCase):
    """Tests for automated remediation generation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.generator = RemediationCodeGenerator()
    
    def test_initialization(self):
        """Test generator initializes correctly."""
        self.assertIsNotNone(self.generator)
        self.assertIsInstance(self.generator.remediation_templates, dict)
        self.assertGreater(len(self.generator.remediation_templates), 0)
    
    def test_generate_remediation_aws_key(self):
        """Test remediation for AWS key."""
        finding = {
            'type': 'AWS Access Key',
            'value': 'AKIATEST123',
            'context': 'aws_key = "AKIATEST123"',
            'risk_score': {'risk_level': 'critical'}
        }
        
        remediation = self.generator.generate_remediation(finding)
        
        self.assertIn('action', remediation)
        self.assertIn('code_patch', remediation)
        self.assertIn('before', remediation['code_patch'])
        self.assertIn('after', remediation['code_patch'])
        self.assertIn('steps', remediation)
        self.assertIn('priority', remediation)
    
    def test_generate_remediation_password(self):
        """Test remediation for password."""
        finding = {
            'type': 'Password Field',
            'value': 'mypassword123',
            'risk_score': {'risk_level': 'high'}
        }
        
        remediation = self.generator.generate_remediation(finding)
        
        self.assertEqual(remediation['finding_type'], 'Password Field')
        self.assertGreater(len(remediation['steps']), 0)
    
    def test_priority_calculation(self):
        """Test priority calculation."""
        critical_finding = {'risk_score': {'risk_level': 'critical'}}
        low_finding = {'risk_score': {'risk_level': 'low'}}
        
        critical_priority = self.generator._calculate_priority(critical_finding)
        low_priority = self.generator._calculate_priority(low_finding)
        
        self.assertGreater(critical_priority, low_priority)
        self.assertEqual(critical_priority, 5)
        self.assertEqual(low_priority, 2)
    
    def test_effort_estimation(self):
        """Test effort estimation."""
        finding = {'type': 'API Key'}
        
        effort = self.generator._estimate_effort(finding)
        
        self.assertIn(effort, ['low', 'medium', 'high'])
    
    def test_pr_description_generation(self):
        """Test PR description generation."""
        findings = [
            {
                'type': 'AWS Key',
                'risk_score': {'risk_level': 'critical'}
            },
            {
                'type': 'Password',
                'risk_score': {'risk_level': 'high'}
            }
        ]
        
        remediations = [
            {'action': 'Move to env vars'},
            {'action': 'Use secure storage'}
        ]
        
        pr_desc = self.generator.generate_pr_description(findings, remediations)
        
        self.assertIsInstance(pr_desc, str)
        self.assertIn('Security', pr_desc)
        self.assertIn('CRITICAL', pr_desc)
        self.assertIn('HIGH', pr_desc)
    
    def test_generic_remediation(self):
        """Test generic remediation for unknown types."""
        finding = {
            'type': 'Unknown Type',
            'risk_score': {'risk_level': 'medium'}
        }
        
        remediation = self.generator.generate_remediation(finding)
        
        self.assertIn('action', remediation)
        self.assertIn('steps', remediation)


class TestContainerScanner(unittest.TestCase):
    """Tests for container scanning."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = ContainerScanner()
    
    def test_initialization(self):
        """Test scanner initializes correctly."""
        self.assertIsNotNone(self.scanner)
    
    @patch('subprocess.run')
    def test_scan_docker_container_not_available(self, mock_run):
        """Test container scan when Docker not available."""
        mock_run.return_value = Mock(returncode=1)
        
        result = self.scanner.scan_docker_container('test-container')
        
        self.assertEqual(result['status'], 'error')
        self.assertIn('Docker not available', result['message'])
    
    @patch('subprocess.run')
    def test_scan_docker_container_success(self, mock_run):
        """Test successful container scan."""
        # Mock docker version check
        version_result = Mock(returncode=0)
        
        # Mock docker inspect with sensitive env var
        inspect_result = Mock(
            returncode=0,
            stdout=json.dumps([{
                'Config': {
                    'Env': ['API_KEY=test123', 'PASSWORD=secret'],
                    'User': 'root'
                }
            }])
        )
        
        mock_run.side_effect = [version_result, inspect_result]
        
        result = self.scanner.scan_docker_container('test-container')
        
        self.assertEqual(result['status'], 'completed')
        self.assertGreater(len(result['findings']), 0)
    
    @patch('subprocess.run')
    def test_scan_running_processes(self, mock_run):
        """Test process scanning."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="USER PID COMMAND\nroot 123 python --password=secret"
        )
        
        findings = self.scanner.scan_running_processes()
        
        self.assertIsInstance(findings, list)


class TestDistributedScanCoordinator(unittest.TestCase):
    """Tests for distributed scanning."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.coordinator = DistributedScanCoordinator()
    
    def test_initialization(self):
        """Test coordinator initializes correctly."""
        self.assertIsNotNone(self.coordinator)
        self.assertIsInstance(self.coordinator.scan_queue, list)
    
    def test_distribute_scan(self):
        """Test scan distribution."""
        # Create test files
        with tempfile.TemporaryDirectory() as temp_dir:
            test_files = []
            for i in range(10):
                file_path = os.path.join(temp_dir, f'test{i}.py')
                with open(file_path, 'w') as f:
                    f.write(f'# Test file {i}\n')
                test_files.append(file_path)
            
            # Distribute scan
            results = self.coordinator.distribute_scan(test_files, num_workers=3)
            
            self.assertTrue(results['distributed'])
            self.assertEqual(results['num_workers'], 3)
            self.assertGreater(results['chunks_processed'], 0)


class TestEnterpriseVulnerabilityScanner(unittest.TestCase):
    """Tests for enterprise scanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = EnterpriseVulnerabilityScanner(
            enable_cve_integration=True,
            enable_advanced_ml=True,
            enable_auto_remediation=True,
            enable_container_scanning=False,
            enable_distributed_scanning=False
        )
    
    def test_initialization(self):
        """Test scanner initializes correctly."""
        self.assertIsNotNone(self.scanner)
        self.assertIsNotNone(self.scanner.cve_manager)
        self.assertIsNotNone(self.scanner.ml_detector)
        self.assertIsNotNone(self.scanner.remediation_generator)
    
    def test_enterprise_components(self):
        """Test enterprise components are properly initialized."""
        # Test CVE manager
        self.assertIsInstance(self.scanner.cve_manager, CVEFeedManager)
        
        # Test ML detector
        self.assertIsInstance(self.scanner.ml_detector, TransformerVulnerabilityDetector)
        
        # Test remediation generator
        self.assertIsInstance(self.scanner.remediation_generator, RemediationCodeGenerator)
    
    def test_scan_with_enterprise_features(self):
        """Test enterprise scan."""
        # Create test file
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write('api_key = "sk_live_test123"\n')
                f.write('password = "secret123"\n')
            
            output_dir = os.path.join(temp_dir, 'results')
            
            # Run scan
            results = self.scanner.scan_with_enterprise_features(
                [test_file],
                target_type='file',
                output_dir=output_dir
            )
            
            self.assertIn('findings', results)
            self.assertIn('enterprise_features', results)
            self.assertEqual(results['scanner_version'], '5.0-enterprise')
    
    def test_cve_enrichment(self):
        """Test CVE enrichment of findings."""
        findings = [
            {
                'type': 'AWS Access Key',
                'value': 'AKIATEST',
                'context': 'test',
                'risk_score': {'composite_score': 80}
            }
        ]
        
        self.scanner._enrich_with_cve_intelligence(findings)
        
        # Check if enrichment was applied
        if findings[0].get('threat_intelligence'):
            self.assertIn('related_cves', findings[0]['threat_intelligence'])
    
    def test_advanced_ml_application(self):
        """Test advanced ML analysis."""
        findings = [
            {
                'type': 'API Key',
                'value': 'sk_live_abc123',
                'context': 'api_key = "sk_live_abc123"',
                'risk_score': {'composite_score': 70}
            }
        ]
        
        self.scanner._apply_advanced_ml(findings)
        
        # Check if ML analysis was applied
        if findings[0].get('ml_advanced'):
            self.assertIn('risk_score', findings[0]['ml_advanced'])
            self.assertIn('explanation', findings[0]['ml_advanced'])
    
    def test_remediation_generation(self):
        """Test remediation generation."""
        findings = [
            {
                'type': 'AWS Access Key',
                'value': 'AKIATEST',
                'context': 'test',
                'source': 'test.py',
                'risk_score': {'risk_level': 'critical'}
            }
        ]
        
        remediations = self.scanner._generate_remediations(findings)
        
        self.assertIsInstance(remediations, list)
        if remediations:
            self.assertIn('action', remediations[0])
            self.assertIn('code_patch', remediations[0])


class TestQuickEnterpriseScan(unittest.TestCase):
    """Tests for convenience functions."""
    
    def test_quick_enterprise_scan(self):
        """Test quick scan function."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = os.path.join(temp_dir, 'test.py')
            with open(test_file, 'w') as f:
                f.write('# Test file\n')
            
            output_dir = os.path.join(temp_dir, 'results')
            
            # Run quick scan
            results = quick_enterprise_scan([test_file], output_dir)
            
            self.assertIsInstance(results, dict)
            self.assertIn('findings', results)
            self.assertIn('enterprise_features', results)


class TestIntegration(unittest.TestCase):
    """Integration tests for enterprise scanner."""
    
    def test_full_enterprise_pipeline(self):
        """Test complete enterprise scanning pipeline."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file with various vulnerabilities
            test_file = os.path.join(temp_dir, 'vulnerable.py')
            with open(test_file, 'w') as f:
                f.write('#!/usr/bin/env python3\n')
                f.write('# Vulnerable code sample\n')
                f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
                f.write('password = "supersecret123"\n')
                f.write('api_token = "sk_live_abc123xyz"\n')
            
            output_dir = os.path.join(temp_dir, 'results')
            
            # Create scanner with all features
            scanner = EnterpriseVulnerabilityScanner(
                enable_cve_integration=True,
                enable_advanced_ml=True,
                enable_auto_remediation=True,
                enable_risk_scoring=True
            )
            
            # Run full scan
            results = scanner.scan_with_enterprise_features(
                [test_file],
                target_type='file',
                output_dir=output_dir
            )
            
            # Verify results structure
            self.assertIn('findings', results)
            self.assertIn('enterprise_features', results)
            self.assertIn('scanner_version', results)
            
            # Verify enterprise features
            features = results['enterprise_features']
            self.assertIn('cve_enrichment', features)
            self.assertIn('advanced_ml', features)
            self.assertIn('auto_remediation', features)
            
            # Verify output files
            self.assertTrue(os.path.exists(output_dir))


if __name__ == '__main__':
    unittest.main()
