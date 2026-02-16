from django.test import TestCase, Client
from django.utils import timezone
from django.urls import reverse
from .models import Vulnerability
from .analyse import (
    analyze_xss_response,
    analyze_sqli_response,
    analyze_command_injection_response,
    extract_endpoint
)


class MockResponse:
    """Mock HTTP response object for testing"""
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}


class VulnerabilityModelTests(TestCase):
    """Tests for the Vulnerability model"""
    
    def test_create_vulnerability(self):
        """Test creating a vulnerability record"""
        vuln = Vulnerability.objects.create(
            attack_type='xss',
            severity='high',
            target_url='https://example.com/search?q=test',
            payload='<script>alert("XSS")</script>',
            request_method='GET',
            response_status_code=200,
            endpoint='/search'
        )
        
        self.assertEqual(vuln.attack_type, 'xss')
        self.assertEqual(vuln.severity, 'high')
        self.assertIsNotNone(vuln.detected_at)
        
    def test_vulnerability_str(self):
        """Test string representation of vulnerability"""
        vuln = Vulnerability.objects.create(
            attack_type='sqli',
            target_url='https://example.com/api/users',
            payload="' OR '1'='1",
        )
        
        str_repr = str(vuln)
        self.assertIn('SQL Injection', str_repr)
        
    def test_get_short_payload(self):
        """Test payload truncation"""
        long_payload = 'A' * 200
        vuln = Vulnerability.objects.create(
            attack_type='xss',
            target_url='https://example.com',
            payload=long_payload,
        )
        
        short = vuln.get_short_payload()
        self.assertTrue(len(short) <= 100)
        self.assertTrue(short.endswith('...'))


class AnalyseFunctionsTests(TestCase):
    """Tests for analysis functions in analyse.py"""
    
    def test_analyze_xss_response_detected(self):
        """Test XSS detection when payload is reflected"""
        payload = '<script>alert(1)</script>'
        response = MockResponse(f'<html>Search: {payload}</html>')
        
        vuln = analyze_xss_response(
            target_url='https://test.com/search',
            payload=payload,
            response=response
        )
        
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.attack_type, 'xss')
        self.assertEqual(vuln.severity, 'high')
        
    def test_analyze_xss_response_not_detected(self):
        """Test XSS not detected when payload is not reflected"""
        payload = '<script>alert(1)</script>'
        response = MockResponse('<html>No reflection</html>')
        
        vuln = analyze_xss_response(
            target_url='https://test.com/search',
            payload=payload,
            response=response
        )
        
        self.assertIsNone(vuln)
        
    def test_analyze_sqli_response_with_error(self):
        """Test SQL injection detection with error message"""
        payload = "' OR '1'='1"
        response = MockResponse('SQL syntax error near OR')
        
        vuln = analyze_sqli_response(
            target_url='https://test.com/api',
            payload=payload,
            response=response
        )
        
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.attack_type, 'sqli')
        self.assertEqual(vuln.severity, 'critical')
        
    def test_analyze_command_injection(self):
        """Test command injection detection"""
        payload = '; cat /etc/passwd'
        response = MockResponse('root:x:0:0:root:/root:/bin/bash')
        
        vuln = analyze_command_injection_response(
            target_url='https://test.com/ping',
            payload=payload,
            response=response
        )
        
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.attack_type, 'command_injection')
        
    def test_extract_endpoint(self):
        """Test endpoint extraction and normalization"""
        test_cases = [
            ('https://example.com/api/users/123', '/api/users/{id}'),
            ('https://example.com/products/456/reviews/789', '/products/{id}/reviews/{id}'),
            ('https://example.com/search', '/search'),
        ]
        
        for url, expected_endpoint in test_cases:
            endpoint = extract_endpoint(url)
            self.assertEqual(endpoint, expected_endpoint)


class VulnerabilityViewTests(TestCase):
    """Tests for vulnerability views"""
    
    def setUp(self):
        """Create test data"""
        self.client = Client()
        self.vuln1 = Vulnerability.objects.create(
            attack_type='xss',
            severity='high',
            target_url='https://example.com/search',
            payload='<script>alert(1)</script>',
            evidence_html='<html><body>Test</body></html>'
        )
        self.vuln2 = Vulnerability.objects.create(
            attack_type='sqli',
            severity='critical',
            target_url='https://example.com/api',
            payload="' OR '1'='1"
        )
        
    def test_dashboard_view(self):
        """Test dashboard view loads correctly"""
        response = self.client.get(reverse('response_analyser:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Response Analyser Dashboard')
        
    def test_vulnerability_list_view(self):
        """Test vulnerability list view"""
        response = self.client.get(reverse('response_analyser:vulnerability_list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Vulnerability List')
        
    def test_vulnerability_detail_view(self):
        """Test vulnerability detail view"""
        response = self.client.get(
            reverse('response_analyser:vulnerability_detail', args=[self.vuln1.pk])
        )
        self.assertEqual(response.status_code, 200)
        # Payload is HTML-escaped in the template
        self.assertContains(response, '&lt;script&gt;alert(1)&lt;/script&gt;')
        
    def test_render_evidence_html(self):
        """Test HTML evidence rendering"""
        response = self.client.get(
            reverse('response_analyser:render_evidence_html', args=[self.vuln1.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/html')
        self.assertEqual(response['X-Frame-Options'], 'SAMEORIGIN')
        
    def test_vulnerability_list_filtering(self):
        """Test vulnerability list filtering"""
        response = self.client.get(
            reverse('response_analyser:vulnerability_list') + '?attack_type=xss'
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.vuln1.target_url)
        
    def test_vulnerability_list_search(self):
        """Test vulnerability list search"""
        response = self.client.get(
            reverse('response_analyser:vulnerability_list') + '?search=alert'
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'alert')


class PoCFunctionalityTests(TestCase):
    """Tests for Proof of Concept functionality"""
    
    def setUp(self):
        """Create test data with proof_of_impact"""
        self.client = Client()
        self.vuln_with_poc = Vulnerability.objects.create(
            attack_type='xss',
            severity='high',
            target_url='https://example.com/search',
            payload='<script>alert(1)</script>',
            proof_of_impact='✓ VERIFIED - XSS vulnerability confirmed\n\nPayload was reflected in response\nUser input is not sanitized'
        )
        self.vuln_without_poc = Vulnerability.objects.create(
            attack_type='sqli',
            severity='medium',
            target_url='https://example.com/api',
            payload="' OR '1'='1",
            proof_of_impact=None
        )
    
    def test_poc_visible_in_detail_view(self):
        """Test that PoC section is visible when proof_of_impact exists"""
        response = self.client.get(
            reverse('response_analyser:vulnerability_detail', args=[self.vuln_with_poc.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Proof of Concept')
        self.assertContains(response, 'View PoC')
        self.assertContains(response, self.vuln_with_poc.proof_of_impact[:50])
    
    def test_poc_not_visible_when_missing(self):
        """Test that PoC section is not visible when proof_of_impact is null"""
        response = self.client.get(
            reverse('response_analyser:vulnerability_detail', args=[self.vuln_without_poc.pk])
        )
        self.assertEqual(response.status_code, 200)
        # PoC section should not be present
        self.assertNotContains(response, 'Proof of Concept (PoC)')
    
    def test_download_poc_text(self):
        """Test downloading PoC as text file"""
        response = self.client.get(
            reverse('response_analyser:download_poc', args=[self.vuln_with_poc.pk]) + '?format=text'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('poc_vuln_', response['Content-Disposition'])
        self.assertIn('.txt', response['Content-Disposition'])
        # Check content
        content = response.content.decode('utf-8')
        self.assertIn('Proof of Concept', content)
        self.assertIn('XSS', content)
        self.assertIn(self.vuln_with_poc.proof_of_impact, content)
    
    def test_download_poc_json(self):
        """Test downloading PoC as JSON file"""
        response = self.client.get(
            reverse('response_analyser:download_poc', args=[self.vuln_with_poc.pk]) + '?format=json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('poc_vuln_', response['Content-Disposition'])
        self.assertIn('.json', response['Content-Disposition'])
        # Check JSON content
        import json
        content = json.loads(response.content.decode('utf-8'))
        self.assertEqual(content['vulnerability_id'], self.vuln_with_poc.pk)
        self.assertIn('XSS', content['attack_type'])
        self.assertEqual(content['proof_of_impact'], self.vuln_with_poc.proof_of_impact)
    
    def test_download_poc_not_found(self):
        """Test downloading PoC when it doesn't exist"""
        response = self.client.get(
            reverse('response_analyser:download_poc', args=[self.vuln_without_poc.pk])
        )
        self.assertEqual(response.status_code, 404)
        self.assertIn('No Proof of Concept available', response.content.decode('utf-8'))
    
    def test_dashboard_shows_poc_button(self):
        """Test that dashboard shows View PoC button for vulnerabilities with PoC"""
        response = self.client.get(reverse('response_analyser:dashboard'))
        self.assertEqual(response.status_code, 200)
        # Should show View PoC button for vuln with PoC
        self.assertContains(response, 'View PoC')
        # Should show N/A for vuln without PoC
        self.assertContains(response, 'N/A')
    
    def test_modal_javascript_functions(self):
        """Test that modal JavaScript functions are present in templates"""
        response = self.client.get(
            reverse('response_analyser:vulnerability_detail', args=[self.vuln_with_poc.pk])
        )
        self.assertContains(response, 'openPoCModal')
        self.assertContains(response, 'closePoCModal')
        self.assertContains(response, 'pocModal')
        
        response = self.client.get(reverse('response_analyser:dashboard'))
        self.assertContains(response, 'openPoCModalDashboard')
        self.assertContains(response, 'closePoCModalDashboard')
        self.assertContains(response, 'pocModalDashboard')
