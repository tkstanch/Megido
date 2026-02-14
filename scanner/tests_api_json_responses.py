"""
Tests to verify that scanner API endpoints always return valid JSON responses
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from scanner.models import ScanTarget, Scan, Vulnerability
from unittest.mock import patch, MagicMock
import json


class ScannerAPIJSONResponseTestCase(TestCase):
    """Test cases to verify all scanner API endpoints return valid JSON"""

    def setUp(self):
        """Set up test data"""
        # Create a user and token for authenticated requests
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client = Client()

        # Create test scan target
        self.target = ScanTarget.objects.create(
            url='https://example.com',
            name='Test Target'
        )

    def test_targets_get_returns_json_200(self):
        """Test GET /scanner/api/targets/ returns valid JSON with 200 status"""
        response = self.client.get(
            '/scanner/api/targets/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, list)

    def test_targets_post_returns_json_201(self):
        """Test POST /scanner/api/targets/ returns valid JSON with 201 status"""
        response = self.client.post(
            '/scanner/api/targets/',
            data=json.dumps({'url': 'https://test.com', 'name': 'Test'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)
        self.assertIn('message', data)

    @patch('scanner.views.perform_basic_scan')
    def test_start_scan_success_returns_json_201(self, mock_scan):
        """Test POST /scanner/api/targets/<id>/scan/ returns valid JSON with 201 on success"""
        # Mock the scan function to succeed
        mock_scan.return_value = None
        
        response = self.client.post(
            f'/scanner/api/targets/{self.target.id}/scan/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)
        self.assertIn('message', data)
        self.assertIn('status', data)

    @patch('scanner.views.perform_basic_scan')
    def test_start_scan_failure_returns_json_500(self, mock_scan):
        """Test POST /scanner/api/targets/<id>/scan/ returns valid JSON with 500 on failure"""
        # Mock the scan function to fail
        mock_scan.side_effect = Exception('Scan failed')
        
        response = self.client.post(
            f'/scanner/api/targets/{self.target.id}/scan/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('error', data)

    def test_start_scan_target_not_found_returns_json_404(self):
        """Test POST /scanner/api/targets/<invalid_id>/scan/ returns valid JSON with 404"""
        response = self.client.post(
            '/scanner/api/targets/99999/scan/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('error', data)

    def test_scan_results_returns_json_200(self):
        """Test GET /scanner/api/scans/<id>/results/ returns valid JSON with 200"""
        # Create a completed scan
        scan = Scan.objects.create(
            target=self.target,
            status='completed'
        )
        
        response = self.client.get(
            f'/scanner/api/scans/{scan.id}/results/'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('scan_id', data)
        self.assertIn('status', data)
        self.assertIn('vulnerabilities', data)

    def test_scan_results_not_found_returns_json_404(self):
        """Test GET /scanner/api/scans/<invalid_id>/results/ returns valid JSON with 404"""
        response = self.client.get(
            '/scanner/api/scans/99999/results/'
        )
        
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('error', data)

    def test_vulnerability_detail_returns_json_200(self):
        """Test GET /scanner/api/vulnerabilities/<id>/ returns valid JSON with 200"""
        # Create a scan and vulnerability
        scan = Scan.objects.create(target=self.target, status='completed')
        vuln = Vulnerability.objects.create(
            scan=scan,
            vulnerability_type='xss',
            severity='high',
            url='https://example.com/page',
            description='XSS vulnerability'
        )
        
        response = self.client.get(
            f'/scanner/api/vulnerabilities/{vuln.id}/'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('id', data)
        self.assertIn('type', data)
        self.assertIn('severity', data)

    def test_vulnerability_not_found_returns_json_404(self):
        """Test GET /scanner/api/vulnerabilities/<invalid_id>/ returns valid JSON with 404"""
        response = self.client.get(
            '/scanner/api/vulnerabilities/99999/'
        )
        
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('error', data)

    def test_exploit_status_returns_json_200(self):
        """Test GET /scanner/api/exploit_status/<task_id>/ returns valid JSON with 200"""
        # Use a dummy task ID
        response = self.client.get(
            '/scanner/api/exploit_status/dummy-task-id/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('state', data)
        self.assertIn('task_id', data)

    def test_exploit_vulnerabilities_scan_not_found_returns_json_404(self):
        """Test POST /scanner/api/scans/<invalid_id>/exploit/ returns valid JSON with 404"""
        response = self.client.post(
            '/scanner/api/scans/99999/exploit/',
            data=json.dumps({'action': 'all'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('error', data)

    def test_exploit_vulnerabilities_invalid_action_returns_json_400(self):
        """Test POST /scanner/api/scans/<id>/exploit/ with invalid action returns JSON 400"""
        scan = Scan.objects.create(target=self.target, status='completed')
        
        response = self.client.post(
            f'/scanner/api/scans/{scan.id}/exploit/',
            data=json.dumps({'action': 'invalid'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('error', data)

    def test_exploit_vulnerabilities_no_ids_returns_json_400(self):
        """Test POST /scanner/api/scans/<id>/exploit/ with selected but no IDs returns JSON 400"""
        scan = Scan.objects.create(target=self.target, status='completed')
        
        response = self.client.post(
            f'/scanner/api/scans/{scan.id}/exploit/',
            data=json.dumps({'action': 'selected', 'vulnerability_ids': []}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response can be parsed as JSON
        data = response.json()
        self.assertIsInstance(data, dict)
        self.assertIn('error', data)
