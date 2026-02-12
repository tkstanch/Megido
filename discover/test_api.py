"""
Tests for the Discover app REST API.
"""
from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
import json

from discover.models import Scan, SensitiveFinding, UserActivity, ScanRecommendation


class APITestCase(TestCase):
    """Base test case for API tests"""
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.admin_user = User.objects.create_superuser(
            username='admin',
            password='admin123'
        )
        
        # Create test scan
        self.scan = Scan.objects.create(
            target='example.com',
            user=self.user,
            wayback_urls='[]',
            shodan_data='{}',
            hunter_data='[]',
            dork_queries='{}',
            dork_results='{}',
            total_urls=10,
            total_emails=5,
            sensitive_scan_completed=True,
            total_findings=3,
            high_risk_findings=1,
        )
        
        # Create test findings
        self.finding_critical = SensitiveFinding.objects.create(
            scan=self.scan,
            url='https://example.com/api',
            finding_type='AWS Access Key',
            value='AKIAIOSFODNN7EXAMPLE',
            context='AWS key found in config',
            severity='critical',
        )
        
        self.finding_high = SensitiveFinding.objects.create(
            scan=self.scan,
            url='https://example.com/config',
            finding_type='API Key',
            value='api_key_12345',
            context='API key in source',
            severity='high',
        )
        
        self.finding_low = SensitiveFinding.objects.create(
            scan=self.scan,
            url='https://example.com/contact',
            finding_type='Email Address',
            value='test@example.com',
            context='Contact email',
            severity='low',
        )


class ScanAPITestCase(APITestCase):
    """Tests for Scan API endpoints"""
    
    def test_list_scans(self):
        """Test listing scans"""
        response = self.client.get('/discover/api/v1/scans/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
    
    def test_retrieve_scan(self):
        """Test retrieving a single scan"""
        response = self.client.get(f'/discover/api/v1/scans/{self.scan.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['target'], 'example.com')
        self.assertEqual(response.data['total_findings'], 3)
    
    def test_scan_statistics(self):
        """Test scan statistics endpoint"""
        response = self.client.get('/discover/api/v1/scans/statistics/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_scans', response.data)
        self.assertIn('total_findings', response.data)
        self.assertIn('findings_by_severity', response.data)
    
    def test_scan_status(self):
        """Test scan status endpoint"""
        response = self.client.get(f'/discover/api/v1/scans/{self.scan.id}/status/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['target'], 'example.com')
        self.assertTrue(response.data['sensitive_scan_completed'])
    
    def test_scan_findings(self):
        """Test scan findings endpoint"""
        response = self.client.get(f'/discover/api/v1/scans/{self.scan.id}/findings/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        # Should have 3 findings
        self.assertEqual(len(response.data['results']), 3)
    
    def test_scan_findings_filter_by_severity(self):
        """Test filtering findings by severity"""
        response = self.client.get(
            f'/discover/api/v1/scans/{self.scan.id}/findings/',
            {'severity': 'critical'}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['severity'], 'critical')
    
    def test_export_scan(self):
        """Test exporting a scan"""
        response = self.client.get(f'/discover/api/v1/scans/{self.scan.id}/export_single/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'application/json')


class FindingAPITestCase(APITestCase):
    """Tests for Finding API endpoints"""
    
    def test_list_findings(self):
        """Test listing findings"""
        response = self.client.get('/discover/api/v1/findings/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 3)
    
    def test_retrieve_finding(self):
        """Test retrieving a single finding"""
        response = self.client.get(f'/discover/api/v1/findings/{self.finding_critical.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['finding_type'], 'AWS Access Key')
        self.assertEqual(response.data['severity'], 'critical')
    
    def test_filter_findings_by_severity(self):
        """Test filtering findings by severity"""
        response = self.client.get('/discover/api/v1/findings/', {'severity': 'critical'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['severity'], 'critical')
    
    def test_filter_findings_by_scan(self):
        """Test filtering findings by scan"""
        response = self.client.get('/discover/api/v1/findings/', {'scan_id': self.scan.id})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 3)
    
    def test_verify_finding(self):
        """Test verifying a finding"""
        response = self.client.post(f'/discover/api/v1/findings/{self.finding_critical.id}/verify/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['verified'])
        
        # Refresh from DB
        self.finding_critical.refresh_from_db()
        self.assertTrue(self.finding_critical.verified)
    
    def test_mark_false_positive(self):
        """Test marking a finding as false positive"""
        response = self.client.post(
            f'/discover/api/v1/findings/{self.finding_critical.id}/mark_false_positive/'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['false_positive'])
        
        # Refresh from DB
        self.finding_critical.refresh_from_db()
        self.assertTrue(self.finding_critical.false_positive)
    
    def test_export_findings_json(self):
        """Test exporting findings as JSON"""
        response = self.client.get('/discover/api/v1/findings/export/', {'format': 'json'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_export_findings_csv(self):
        """Test exporting findings as CSV"""
        response = self.client.get('/discover/api/v1/findings/export/', {'format': 'csv'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'text/csv')
    
    def test_export_findings_sarif(self):
        """Test exporting findings as SARIF"""
        response = self.client.get('/discover/api/v1/findings/export/', {'format': 'sarif'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'application/json')


class HealthCheckTestCase(APITestCase):
    """Tests for health check endpoint"""
    
    def test_health_check(self):
        """Test API health check"""
        response = self.client.get('/discover/api/v1/health/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'healthy')
        self.assertEqual(response.data['service'], 'Megido Discover API')
