"""
Tests for Celery-based async exploit functionality
"""

from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from scanner.models import ScanTarget, Scan, Vulnerability
from scanner.tasks import async_exploit_all_vulnerabilities, async_exploit_selected_vulnerabilities
from unittest.mock import patch, MagicMock, Mock
from celery import states


# Use eager mode for testing - tasks execute synchronously
@override_settings(CELERY_TASK_ALWAYS_EAGER=True, CELERY_TASK_EAGER_PROPAGATES=True)
class CeleryExploitTasksTestCase(TestCase):
    """Test cases for Celery exploit tasks"""

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

        # Create test vulnerabilities
        self.vuln1 = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='sqli',
            severity='high',
            url='https://example.com/page1',
            parameter='id',
            description='SQL Injection vulnerability',
            evidence='Error message in response'
        )
        self.vuln2 = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='xss',
            severity='medium',
            url='https://example.com/page2',
            parameter='search',
            description='XSS vulnerability',
            evidence='Script tag reflected'
        )

    @patch('scanner.tasks.exploit_vulnerability')
    def test_async_exploit_all_vulnerabilities_success(self, mock_exploit):
        """Test async exploit all vulnerabilities task"""
        # Mock successful exploitation
        mock_exploit.return_value = {
            'success': True,
            'plugin_used': 'Test Plugin',
            'evidence': 'Test evidence',
            'findings': ['Finding 1'],
            'data': {}
        }

        # Execute the task directly (in eager mode it runs synchronously)
        results = async_exploit_all_vulnerabilities(self.scan.id)

        # Check results summary
        self.assertEqual(results['total'], 2)
        self.assertEqual(results['exploited'], 2)
        self.assertEqual(results['failed'], 0)
        self.assertEqual(results['no_plugin'], 0)
        self.assertEqual(len(results['results']), 2)
        self.assertIn('task_id', results)

        # Verify vulnerabilities were updated
        vuln1 = Vulnerability.objects.get(id=self.vuln1.id)
        self.assertTrue(vuln1.exploited)
        self.assertEqual(vuln1.exploit_status, 'success')
        self.assertIsNotNone(vuln1.exploit_result)
        self.assertIsNotNone(vuln1.exploit_attempted_at)

    @patch('scanner.tasks.exploit_vulnerability')
    def test_async_exploit_selected_vulnerabilities_success(self, mock_exploit):
        """Test async exploit selected vulnerabilities task"""
        # Mock successful exploitation
        mock_exploit.return_value = {
            'success': True,
            'plugin_used': 'Test Plugin',
            'evidence': 'Test evidence',
            'findings': [],
            'data': {}
        }

        # Execute the task directly
        results = async_exploit_selected_vulnerabilities([self.vuln1.id])

        # Check results
        self.assertEqual(results['total'], 1)
        self.assertEqual(results['exploited'], 1)
        self.assertIn('task_id', results)

        # Verify only selected vulnerability was updated
        vuln1 = Vulnerability.objects.get(id=self.vuln1.id)
        vuln2 = Vulnerability.objects.get(id=self.vuln2.id)
        self.assertTrue(vuln1.exploited)
        self.assertFalse(vuln2.exploited)

    @patch('scanner.tasks.exploit_vulnerability')
    def test_async_exploit_with_no_plugin(self, mock_exploit):
        """Test async exploitation when no plugin is available"""
        # Mock no plugin available
        mock_exploit.return_value = {
            'success': False,
            'plugin_used': None,
            'error': 'No exploit plugin available',
            'findings': [],
            'data': {}
        }

        results = async_exploit_all_vulnerabilities(self.scan.id)

        # Check that vulnerabilities are marked as no_plugin
        self.assertEqual(results['no_plugin'], 2)
        
        vuln1 = Vulnerability.objects.get(id=self.vuln1.id)
        self.assertEqual(vuln1.exploit_status, 'no_plugin')

    @patch('scanner.tasks.exploit_vulnerability')
    def test_async_exploit_with_failure(self, mock_exploit):
        """Test async exploitation when plugin exists but fails"""
        # Mock exploitation failure
        mock_exploit.return_value = {
            'success': False,
            'plugin_used': 'Test Plugin',
            'error': 'Connection refused',
            'findings': [],
            'data': {}
        }

        results = async_exploit_all_vulnerabilities(self.scan.id)

        # Check that vulnerabilities are marked as failed
        self.assertEqual(results['failed'], 2)
        
        vuln1 = Vulnerability.objects.get(id=self.vuln1.id)
        self.assertEqual(vuln1.exploit_status, 'failed')

    def test_async_exploit_task_with_invalid_scan(self):
        """Test async exploit task with non-existent scan"""
        results = async_exploit_all_vulnerabilities(99999)

        self.assertIn('error', results)
        self.assertEqual(results['total'], 0)


class CeleryExploitAPITestCase(TestCase):
    """Test cases for Celery-based exploit API endpoints"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)
        self.client = Client()

        self.target = ScanTarget.objects.create(
            url='https://example.com',
            name='Test Target'
        )
        self.scan = Scan.objects.create(
            target=self.target,
            status='completed'
        )

        self.vuln1 = Vulnerability.objects.create(
            scan=self.scan,
            vulnerability_type='sqli',
            severity='high',
            url='https://example.com/page1',
            parameter='id',
            description='SQL Injection vulnerability'
        )

    @patch('scanner.tasks.async_exploit_all_vulnerabilities.delay')
    def test_exploit_api_returns_task_id(self, mock_task_delay):
        """Test that exploit API endpoint returns a task ID"""
        mock_result = MagicMock()
        mock_result.id = 'test-task-id-xyz'
        mock_task_delay.return_value = mock_result

        response = self.client.post(
            f'/scanner/api/scans/{self.scan.id}/exploit/',
            data={'action': 'all'},
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )

        self.assertEqual(response.status_code, 202)
        data = response.json()
        self.assertIn('task_id', data)
        self.assertEqual(data['task_id'], 'test-task-id-xyz')
        self.assertIn('status_url', data)

    @patch('scanner.tasks.async_exploit_selected_vulnerabilities.delay')
    def test_exploit_api_selected_returns_task_id(self, mock_task_delay):
        """Test that exploit API with selected IDs returns a task ID"""
        mock_result = MagicMock()
        mock_result.id = 'test-task-id-def'
        mock_task_delay.return_value = mock_result

        response = self.client.post(
            f'/scanner/api/scans/{self.scan.id}/exploit/',
            data={
                'action': 'selected',
                'vulnerability_ids': [self.vuln1.id]
            },
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )

        self.assertEqual(response.status_code, 202)
        data = response.json()
        self.assertIn('task_id', data)

    @patch('scanner.views.AsyncResult')
    def test_exploit_status_pending(self, mock_async_result):
        """Test exploit status endpoint for pending task"""
        mock_result = MagicMock()
        mock_result.state = states.PENDING
        mock_async_result.return_value = mock_result

        response = self.client.get(
            '/scanner/api/exploit_status/test-task-id/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['state'], states.PENDING)
        self.assertIn('status', data)

    @patch('scanner.views.AsyncResult')
    def test_exploit_status_progress(self, mock_async_result):
        """Test exploit status endpoint for task in progress"""
        mock_result = MagicMock()
        mock_result.state = 'PROGRESS'  # Task state used in our implementation
        mock_result.info = {
            'current': 2,
            'total': 5,
            'status': 'Processing vulnerability 2/5'
        }
        mock_async_result.return_value = mock_result

        response = self.client.get(
            '/scanner/api/exploit_status/test-task-id/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['state'], 'PROGRESS')
        self.assertEqual(data['current'], 2)
        self.assertEqual(data['total'], 5)
        self.assertIn('status', data)

    @patch('scanner.views.AsyncResult')
    def test_exploit_status_success(self, mock_async_result):
        """Test exploit status endpoint for successful task"""
        mock_result = MagicMock()
        mock_result.state = states.SUCCESS
        mock_result.result = {
            'total': 3,
            'exploited': 2,
            'failed': 1,
            'no_plugin': 0,
            'results': []
        }
        mock_async_result.return_value = mock_result

        response = self.client.get(
            '/scanner/api/exploit_status/test-task-id/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['state'], states.SUCCESS)
        self.assertIn('result', data)
        self.assertEqual(data['result']['total'], 3)
        self.assertEqual(data['result']['exploited'], 2)

    @patch('scanner.views.AsyncResult')
    def test_exploit_status_failure(self, mock_async_result):
        """Test exploit status endpoint for failed task"""
        mock_result = MagicMock()
        mock_result.state = states.FAILURE
        mock_result.info = Exception('Task failed with error')
        mock_async_result.return_value = mock_result

        response = self.client.get(
            '/scanner/api/exploit_status/test-task-id/',
            HTTP_AUTHORIZATION=f'Token {self.token.key}'
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['state'], states.FAILURE)
        self.assertIn('error', data)

    def test_exploit_status_requires_auth(self):
        """Test that exploit status endpoint requires authentication"""
        response = self.client.get('/scanner/api/exploit_status/test-task-id/')
        self.assertEqual(response.status_code, 401)

