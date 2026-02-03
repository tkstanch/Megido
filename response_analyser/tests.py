from django.test import TestCase
from django.utils import timezone
from .models import Vulnerability


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
