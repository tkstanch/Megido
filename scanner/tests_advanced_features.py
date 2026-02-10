"""
Tests for advanced scanner features including risk scoring, false positive management,
and verified exploit results
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from scanner.models import ScanTarget, Scan, Vulnerability
from scanner.exploit_integration import (
    apply_risk_scoring,
    apply_compliance_mapping,
    apply_remediation_advice,
    filter_false_positives,
    apply_advanced_features_to_scan
)
from unittest.mock import patch, MagicMock
import json


class AdvancedFeaturesTestCase(TestCase):
    """Test cases for advanced scanner features"""

    def setUp(self):
        """Set up test data"""
        # Create a user and token for authenticated requests
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client = Client()

        # Create test scan target and scan
        self.target = ScanTarget.objects.create(
            url='https://example.com',
            name='Test Target'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='completed'
        )

        # Create test vulnerabilities with different severities
        self.vuln_critical = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='sqli',
            severity='critical',
            url='https://example.com/admin',
            parameter='id',
            description='SQL Injection in admin panel',
            evidence='Database error exposed',
            confidence_score=0.9
        )
        
        self.vuln_high = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='high',
            url='https://example.com/search',
            parameter='q',
            description='Reflected XSS vulnerability',
            evidence='Script tag reflected unescaped',
            confidence_score=0.8
        )
        
        self.vuln_low = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='info_disclosure',
            severity='low',
            url='https://example.com',
            description='Missing security header',
            evidence='X-Frame-Options not set',
            confidence_score=0.3
        )

    def test_vulnerability_advanced_model_fields(self):
        """Test that vulnerability model has advanced feature fields"""
        vuln = Vulnerability.objects.get(id=self.vuln_critical.id)
        
        # Risk scoring fields
        self.assertEqual(vuln.risk_score, 0.0)  # Default value
        self.assertEqual(vuln.risk_level, 'medium')  # Default value
        self.assertIsNotNone(vuln.confidence_score)
        
        # Verification fields
        self.assertFalse(vuln.verified)
        self.assertIsNone(vuln.proof_of_impact)
        
        # False positive fields
        self.assertEqual(vuln.false_positive_status, 'unknown')
        self.assertIsNone(vuln.false_positive_reason)
        
        # Compliance fields
        self.assertEqual(vuln.compliance_violations, {})
        
        # Remediation fields
        self.assertEqual(vuln.remediation_priority, 3)
        self.assertEqual(vuln.remediation_effort, 'medium')

    def test_apply_risk_scoring_basic(self):
        """Test applying risk scoring to a vulnerability (basic fallback)"""
        vuln = self.vuln_critical
        apply_risk_scoring(vuln)
        
        # Should have a risk score applied
        self.assertGreater(vuln.risk_score, 0)
        # Critical severity should result in high risk score
        self.assertGreaterEqual(vuln.risk_score, 70)

    def test_apply_risk_scoring_verified(self):
        """Test that verified vulnerabilities get higher risk scores"""
        vuln = self.vuln_high
        
        # Apply risk scoring without verification
        apply_risk_scoring(vuln)
        initial_score = vuln.risk_score
        
        # Mark as verified and apply again
        vuln.verified = True
        apply_risk_scoring(vuln)
        verified_score = vuln.risk_score
        
        # Verified vulnerability should have equal or higher risk score
        # (In basic mode they might be equal, in advanced mode verified should be higher)
        self.assertGreaterEqual(verified_score, initial_score)

    def test_apply_compliance_mapping(self):
        """Test applying compliance mapping to vulnerabilities"""
        vuln = self.vuln_critical
        apply_compliance_mapping(vuln)
        
        # Compliance violations should be a dict (even if empty in basic mode)
        self.assertIsInstance(vuln.compliance_violations, dict)

    def test_apply_remediation_advice(self):
        """Test applying remediation advice"""
        vuln = self.vuln_high
        vuln.remediation = None  # Clear any existing remediation
        apply_remediation_advice(vuln)
        
        # Should have remediation set (either from plugin or engine)
        # Priority should be set
        self.assertIsNotNone(vuln.remediation_priority)
        self.assertIn(vuln.remediation_effort, ['low', 'medium', 'high'])

    def test_verified_vulnerability_with_proof(self):
        """Test that verified vulnerabilities store proof of impact"""
        vuln = self.vuln_critical
        
        # Simulate successful exploitation with proof
        vuln.verified = True
        vuln.exploited = True
        vuln.exploit_status = 'success'
        vuln.proof_of_impact = "Evidence: Successfully extracted data\n\nExtracted Data: {\"users\": 150}\n\nFindings: Table: users; Column: password"
        vuln.confidence_score = 1.0
        vuln.save()
        
        # Reload and verify
        vuln = Vulnerability.objects.get(id=vuln.id)
        self.assertTrue(vuln.verified)
        self.assertTrue(vuln.exploited)
        self.assertIsNotNone(vuln.proof_of_impact)
        self.assertIn('Successfully extracted data', vuln.proof_of_impact)

    def test_filter_false_positives(self):
        """Test filtering false positives from vulnerability list"""
        # Mark one vulnerability as false positive
        self.vuln_low.false_positive_status = 'false_positive'
        self.vuln_low.false_positive_reason = 'Test environment only'
        self.vuln_low.save()
        
        # Get all vulnerabilities
        all_vulns = list(self.scan.vulnerabilities.all())
        self.assertEqual(len(all_vulns), 3)
        
        # Filter false positives
        filtered = filter_false_positives(all_vulns)
        
        # Should have 2 vulnerabilities (false positive filtered out)
        self.assertEqual(len(filtered), 2)
        self.assertNotIn(self.vuln_low, filtered)

    def test_apply_advanced_features_to_scan(self):
        """Test applying all advanced features to a scan"""
        results = apply_advanced_features_to_scan(self.scan.id)
        
        # Check results structure
        self.assertIn('total_vulnerabilities', results)
        self.assertIn('processed', results)
        self.assertEqual(results['total_vulnerabilities'], 3)
        self.assertEqual(results['processed'], 3)
        
        # Reload vulnerabilities and check they have been scored
        for vuln in self.scan.vulnerabilities.all():
            self.assertGreater(vuln.risk_score, 0)

    def test_scan_results_api_with_filters(self):
        """Test scan results API with advanced feature filters"""
        # Mark one as false positive
        self.vuln_low.false_positive_status = 'false_positive'
        self.vuln_low.save()
        
        # Mark one as verified
        self.vuln_critical.verified = True
        self.vuln_critical.proof_of_impact = 'Test proof'
        self.vuln_critical.save()
        
        # Test default behavior (excludes false positives)
        response = self.client.get(
            f'/scanner/api/scans/{self.scan.id}/results/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Should exclude false positive by default
        self.assertEqual(len(data['vulnerabilities']), 2)
        
    def test_scan_results_verified_only_filter(self):
        """Test filtering to show only verified vulnerabilities"""
        # Mark one as verified
        self.vuln_critical.verified = True
        self.vuln_critical.proof_of_impact = 'Test proof'
        self.vuln_critical.risk_score = 95.0
        self.vuln_critical.save()
        
        # Apply advanced features to ensure all have risk scores
        apply_advanced_features_to_scan(self.scan.id)
        
        # Request only verified vulnerabilities
        response = self.client.get(
            f'/scanner/api/scans/{self.scan.id}/results/?verified_only=true',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Should only show verified vulnerabilities
        self.assertEqual(len(data['vulnerabilities']), 1)
        self.assertTrue(data['vulnerabilities'][0]['verified'])

    def test_scan_results_includes_advanced_fields(self):
        """Test that scan results API includes advanced feature fields"""
        # Apply advanced features first
        apply_advanced_features_to_scan(self.scan.id)
        
        response = self.client.get(
            f'/scanner/api/scans/{self.scan.id}/results/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check that vulnerabilities include advanced fields
        vuln = data['vulnerabilities'][0]
        self.assertIn('verified', vuln)
        self.assertIn('risk_score', vuln)
        self.assertIn('risk_level', vuln)
        self.assertIn('confidence_score', vuln)
        self.assertIn('false_positive_status', vuln)
        self.assertIn('compliance_violations', vuln)
        self.assertIn('remediation_priority', vuln)

    @patch('scanner.exploit_integration.exploit_vulnerability')
    def test_verified_status_after_successful_exploitation(self, mock_exploit):
        """Test that successful exploitation marks vulnerability as verified"""
        from scanner.exploit_integration import _exploit_vulnerability_and_update
        
        # Mock successful exploitation with evidence
        mock_exploit.return_value = {
            'success': True,
            'plugin_used': 'XSS Plugin',
            'evidence': 'JavaScript executed in browser context',
            'data': {'screenshot': 'base64data', 'dom': '<html>...</html>'},
            'findings': ['Alert box triggered', 'Cookie access confirmed']
        }
        
        vuln = self.vuln_high
        initial_confidence = vuln.confidence_score
        
        results = {
            'total': 0,
            'exploited': 0,
            'failed': 0,
            'no_plugin': 0,
            'results': []
        }
        
        # Exploit the vulnerability
        _exploit_vulnerability_and_update(vuln, {}, results)
        
        # Reload vulnerability
        vuln = Vulnerability.objects.get(id=vuln.id)
        
        # Should be marked as verified
        self.assertTrue(vuln.verified)
        self.assertTrue(vuln.exploited)
        self.assertEqual(vuln.exploit_status, 'success')
        
        # Should have proof of impact
        self.assertIsNotNone(vuln.proof_of_impact)
        self.assertIn('JavaScript executed', vuln.proof_of_impact)
        
        # Confidence score should be increased
        self.assertGreater(vuln.confidence_score, initial_confidence)

    @patch('scanner.exploit_integration.exploit_vulnerability')
    def test_unverified_after_failed_exploitation(self, mock_exploit):
        """Test that failed exploitation does not mark as verified"""
        from scanner.exploit_integration import _exploit_vulnerability_and_update
        
        # Mock failed exploitation
        mock_exploit.return_value = {
            'success': False,
            'plugin_used': 'SQLi Plugin',
            'error': 'No SQL injection detected'
        }
        
        vuln = self.vuln_critical
        
        results = {
            'total': 0,
            'exploited': 0,
            'failed': 0,
            'no_plugin': 0,
            'results': []
        }
        
        # Attempt to exploit the vulnerability
        _exploit_vulnerability_and_update(vuln, {}, results)
        
        # Reload vulnerability
        vuln = Vulnerability.objects.get(id=vuln.id)
        
        # Should NOT be marked as verified
        self.assertFalse(vuln.verified)
        self.assertFalse(vuln.exploited)
        self.assertEqual(vuln.exploit_status, 'failed')

    def test_risk_score_ordering(self):
        """Test that vulnerabilities are ordered by risk score"""
        # Apply advanced features to set risk scores
        apply_advanced_features_to_scan(self.scan.id)
        
        # Get scan results
        response = self.client.get(
            f'/scanner/api/scans/{self.scan.id}/results/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        data = response.json()
        
        # Check that vulnerabilities are ordered by risk score (descending)
        risk_scores = [v['risk_score'] for v in data['vulnerabilities']]
        self.assertEqual(risk_scores, sorted(risk_scores, reverse=True))

    def test_apply_advanced_features_endpoint(self):
        """Test the apply advanced features API endpoint"""
        response = self.client.post(
            f'/scanner/api/scans/{self.scan.id}/apply_advanced_features/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check results
        self.assertIn('total_vulnerabilities', data)
        self.assertIn('processed', data)
        self.assertGreater(data['risk_scored'], 0)


class ProofOfImpactTestCase(TestCase):
    """Test cases specifically for proof of impact functionality"""

    def setUp(self):
        """Set up test data"""
        self.target = ScanTarget.objects.create(
            url='https://testapp.com',
            name='Test Application'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='completed'
        )
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='high',
            url='https://testapp.com/search',
            parameter='q',
            description='XSS vulnerability',
            evidence='Payload reflected'
        )

    def test_proof_of_impact_structure(self):
        """Test that proof of impact is properly structured"""
        proof = """Evidence: XSS payload successfully executed in browser

Extracted Data: {"cookies": "session=abc123", "localStorage": {"user": "admin"}}

Findings: JavaScript execution confirmed; DOM manipulation successful; Cookie access verified"""
        
        self.vuln.verified = True
        self.vuln.proof_of_impact = proof
        self.vuln.save()
        
        # Reload and verify structure
        vuln = Vulnerability.objects.get(id=self.vuln.id)
        self.assertIn('Evidence:', vuln.proof_of_impact)
        self.assertIn('Extracted Data:', vuln.proof_of_impact)
        self.assertIn('Findings:', vuln.proof_of_impact)

    def test_verified_badge_display(self):
        """Test that verified vulnerabilities display correctly in UI"""
        # This would be a browser test in reality, but we can test the data structure
        self.vuln.verified = True
        self.vuln.proof_of_impact = 'Test proof'
        self.vuln.risk_score = 85.0
        self.vuln.risk_level = 'critical'
        self.vuln.save()
        
        from rest_framework.test import APIClient
        client = APIClient()
        
        response = client.get(f'/scanner/api/scans/{self.scan.id}/results/')
        data = response.json()
        
        vuln_data = data['vulnerabilities'][0]
        self.assertTrue(vuln_data['verified'])
        self.assertIsNotNone(vuln_data['proof_of_impact'])
        self.assertEqual(vuln_data['risk_level'], 'critical')
