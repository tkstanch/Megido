from django.test import TestCase, Client
from django.urls import reverse
from django.conf import settings
from django.apps import apps
from .models import (
    BypasserTarget, BypasserSession, CharacterProbe,
    EncodingAttempt, BypassResult
)
from .encoding import EncodingTechniques, SpecialCharacters, detect_blocking
from .views import validate_target_url
import json


class BypasserAppConfigTest(TestCase):
    """Test that the bypasser app is properly configured"""
    
    def test_app_exists(self):
        """Verify that bypasser app exists"""
        app_config = apps.get_app_config('bypasser')
        self.assertEqual(app_config.name, 'bypasser')
    
    def test_app_in_installed_apps(self):
        """Verify that bypasser app is in INSTALLED_APPS"""
        self.assertIn('bypasser', settings.INSTALLED_APPS)


class BypasserModelsTest(TestCase):
    """Test bypasser models"""
    
    def setUp(self):
        """Set up test data"""
        self.target = BypasserTarget.objects.create(
            url='https://example.com/search',
            name='Test Target',
            http_method='GET',
            test_parameter='q'
        )
        self.session = BypasserSession.objects.create(
            target=self.target,
            status='pending'
        )
    
    def test_bypasser_target_creation(self):
        """Test creating a bypasser target"""
        self.assertEqual(self.target.url, 'https://example.com/search')
        self.assertEqual(self.target.name, 'Test Target')
        self.assertEqual(self.target.http_method, 'GET')
        self.assertEqual(self.target.test_parameter, 'q')
    
    def test_bypasser_session_creation(self):
        """Test creating a bypasser session"""
        self.assertEqual(self.session.target, self.target)
        self.assertEqual(self.session.status, 'pending')
        self.assertEqual(self.session.characters_tested, 0)
        self.assertEqual(self.session.characters_blocked, 0)
        self.assertIsNotNone(self.session.started_at)
    
    def test_character_probe_creation(self):
        """Test creating a character probe"""
        probe = CharacterProbe.objects.create(
            session=self.session,
            character='<',
            character_code='U+003C',
            character_name='Less Than',
            status='blocked',
            http_status_code=403,
            blocked_by_waf=True
        )
        self.assertEqual(probe.character, '<')
        self.assertEqual(probe.status, 'blocked')
        self.assertTrue(probe.blocked_by_waf)
    
    def test_encoding_attempt_creation(self):
        """Test creating an encoding attempt"""
        probe = CharacterProbe.objects.create(
            session=self.session,
            character='<',
            character_code='U+003C',
            character_name='Less Than',
            status='blocked'
        )
        
        attempt = EncodingAttempt.objects.create(
            session=self.session,
            character_probe=probe,
            encoding_type='url_single',
            original_payload='<',
            encoded_payload='%3C',
            success=True,
            bypass_confirmed=True
        )
        
        self.assertEqual(attempt.encoding_type, 'url_single')
        self.assertEqual(attempt.encoded_payload, '%3C')
        self.assertTrue(attempt.success)
    
    def test_bypass_result_creation(self):
        """Test creating a bypass result"""
        probe = CharacterProbe.objects.create(
            session=self.session,
            character='<',
            character_code='U+003C',
            character_name='Less Than',
            status='blocked'
        )
        
        attempt = EncodingAttempt.objects.create(
            session=self.session,
            character_probe=probe,
            encoding_type='url_single',
            original_payload='<',
            encoded_payload='%3C',
            success=True
        )
        
        result = BypassResult.objects.create(
            session=self.session,
            character_probe=probe,
            encoding_attempt=attempt,
            technique_description='URL encoding bypass',
            payload_example='test%3Cvalue',
            risk_level='high',
            impact_description='Filter can be bypassed',
            evidence='Character reflected in response',
            recommendation='Implement proper input validation'
        )
        
        self.assertEqual(result.risk_level, 'high')
        self.assertEqual(result.encoding_attempt, attempt)


class EncodingTechniquesTest(TestCase):
    """Test encoding techniques"""
    
    def test_url_encode_single(self):
        """Test single URL encoding"""
        encoded = EncodingTechniques.url_encode_single('<')
        self.assertEqual(encoded, '%3C')
    
    def test_url_encode_double(self):
        """Test double URL encoding"""
        encoded = EncodingTechniques.url_encode_double('<')
        self.assertEqual(encoded, '%253C')
    
    def test_html_entity_decimal(self):
        """Test HTML entity decimal encoding"""
        encoded = EncodingTechniques.html_entity_decimal('<')
        self.assertEqual(encoded, '&#60;')
    
    def test_html_entity_hex(self):
        """Test HTML entity hex encoding"""
        encoded = EncodingTechniques.html_entity_hex('<')
        self.assertEqual(encoded, '&#x3c;')
    
    def test_unicode_escape(self):
        """Test Unicode escape encoding"""
        encoded = EncodingTechniques.unicode_escape('<')
        self.assertEqual(encoded, '\\u003c')
    
    def test_base64_encode(self):
        """Test Base64 encoding"""
        encoded = EncodingTechniques.base64_encode('<')
        self.assertIn(encoded, ['PA==', 'PQ=='])  # Different implementations
    
    def test_hex_encode(self):
        """Test hexadecimal encoding"""
        encoded = EncodingTechniques.hex_encode('<')
        self.assertEqual(encoded, '\\x3c')
    
    def test_mixed_case(self):
        """Test mixed case variations"""
        variations = EncodingTechniques.mixed_case('test')
        self.assertIn('test', variations)
        self.assertIn('TEST', variations)
        self.assertTrue(len(variations) > 0)
    
    def test_null_byte_injection(self):
        """Test null byte injection"""
        encoded = EncodingTechniques.null_byte_injection('test')
        self.assertEqual(encoded, 'test%00')
    
    def test_comment_insertion_html(self):
        """Test HTML comment insertion"""
        encoded = EncodingTechniques.comment_insertion_html('ab')
        self.assertEqual(encoded, 'a<!---->b')
    
    def test_html5_named_entities(self):
        """Test HTML5 named entities"""
        encoded = EncodingTechniques.html5_named_entities('<')
        self.assertEqual(encoded, '&lt;')
        
        encoded = EncodingTechniques.html5_named_entities('>')
        self.assertEqual(encoded, '&gt;')
    
    def test_get_all_encodings(self):
        """Test getting all encodings for a character"""
        encodings = EncodingTechniques.get_all_encodings('<')
        
        self.assertIn('url_single', encodings)
        self.assertIn('url_double', encodings)
        self.assertIn('html_decimal', encodings)
        self.assertIn('html_hex', encodings)
        self.assertIn('unicode', encodings)
        self.assertIn('base64', encodings)
        
        # Verify at least one encoding is different from original
        self.assertNotEqual(encodings['url_single'], '<')


class SpecialCharactersTest(TestCase):
    """Test special character collections"""
    
    def test_get_common_special_chars(self):
        """Test getting common special characters"""
        chars = SpecialCharacters.get_common_special_chars()
        
        self.assertTrue(len(chars) > 0)
        self.assertTrue(any(c[0] == '<' for c in chars))
        self.assertTrue(any(c[0] == '>' for c in chars))
        self.assertTrue(any(c[0] == "'" for c in chars))
        
        # Verify structure of returned data
        char, code, name = chars[0]
        self.assertTrue(isinstance(char, str))
        self.assertTrue(code.startswith('U+'))
        self.assertTrue(isinstance(name, str))
    
    def test_get_xss_chars(self):
        """Test getting XSS-related characters"""
        chars = SpecialCharacters.get_xss_chars()
        
        self.assertTrue(len(chars) > 0)
        self.assertTrue(any(c[0] == '<' for c in chars))
        self.assertTrue(any(c[0] == '>' for c in chars))
    
    def test_get_sqli_chars(self):
        """Test getting SQL injection characters"""
        chars = SpecialCharacters.get_sqli_chars()
        
        self.assertTrue(len(chars) > 0)
        self.assertTrue(any(c[0] == "'" for c in chars))
    
    def test_get_command_injection_chars(self):
        """Test getting command injection characters"""
        chars = SpecialCharacters.get_command_injection_chars()
        
        self.assertTrue(len(chars) > 0)
        self.assertTrue(any(c[0] == ';' for c in chars))
        self.assertTrue(any(c[0] == '|' for c in chars))


class DetectBlockingTest(TestCase):
    """Test blocking detection logic"""
    
    def test_detect_blocking_by_status_code(self):
        """Test detection by status code"""
        is_blocked, reason = detect_blocking(
            baseline_response="OK",
            test_response="Forbidden",
            baseline_status=200,
            test_status=403
        )
        
        self.assertTrue(is_blocked)
        self.assertIn('403', reason)
    
    def test_detect_blocking_by_waf_indicator(self):
        """Test detection by WAF indicator"""
        is_blocked, reason = detect_blocking(
            baseline_response="Welcome",
            test_response="Request blocked by security firewall",
            baseline_status=200,
            test_status=200
        )
        
        self.assertTrue(is_blocked)
        self.assertTrue('firewall' in reason.lower() or 'blocked' in reason.lower())
    
    def test_no_blocking_detected(self):
        """Test when no blocking is detected"""
        is_blocked, reason = detect_blocking(
            baseline_response="Hello World",
            test_response="Hello World Test",
            baseline_status=200,
            test_status=200
        )
        
        self.assertFalse(is_blocked)


class BypasserAPITest(TestCase):
    """Test bypasser API endpoints"""
    
    def setUp(self):
        """Set up test client"""
        self.client = Client()
    
    def test_bypasser_targets_get(self):
        """Test getting list of bypasser targets"""
        # Create test targets
        BypasserTarget.objects.create(
            url='https://example1.com',
            name='Target 1'
        )
        BypasserTarget.objects.create(
            url='https://example2.com',
            name='Target 2'
        )
        
        response = self.client.get('/bypasser/api/targets/')
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(len(data), 2)
        # Check that both targets are present
        names = [target['name'] for target in data]
        self.assertIn('Target 1', names)
        self.assertIn('Target 2', names)
    
    def test_bypasser_targets_post(self):
        """Test creating a bypasser target"""
        response = self.client.post(
            '/bypasser/api/targets/',
            data=json.dumps({
                'url': 'https://example.com/test',
                'name': 'Test Target',
                'http_method': 'POST',
                'test_parameter': 'search'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn('id', data)
        
        # Verify target was created
        target = BypasserTarget.objects.get(id=data['id'])
        self.assertEqual(target.url, 'https://example.com/test')
        self.assertEqual(target.name, 'Test Target')
    
    def test_bypasser_targets_post_invalid_internal_url(self):
        """Test creating a bypasser target with internal URL is blocked"""
        response = self.client.post(
            '/bypasser/api/targets/',
            data=json.dumps({
                'url': 'http://127.0.0.1/test',
                'name': 'Internal Target',
            }),
            content_type='application/json'
        )
        
        # Should be rejected
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn('error', data)
        self.assertIn('internal', data['error'].lower())
    
    def test_bypasser_targets_post_invalid_scheme(self):
        """Test creating a bypasser target with invalid scheme"""
        response = self.client.post(
            '/bypasser/api/targets/',
            data=json.dumps({
                'url': 'file:///etc/passwd',
                'name': 'File Target',
            }),
            content_type='application/json'
        )
        
        # Should be rejected
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn('error', data)
    
    def test_session_results_not_found(self):
        """Test getting results for non-existent session"""
        response = self.client.get('/bypasser/api/sessions/9999/results/')
        self.assertEqual(response.status_code, 404)
    
    def test_bypass_results_not_found(self):
        """Test getting bypass results for non-existent session"""
        response = self.client.get('/bypasser/api/sessions/9999/bypasses/')
        self.assertEqual(response.status_code, 404)


class BypasserViewTest(TestCase):
    """Test bypasser views"""
    
    def test_dashboard_view(self):
        """Test bypasser dashboard view"""
        response = self.client.get('/bypasser/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Bypasser')


class BypasserURLsTest(TestCase):
    """Test that all required URL patterns are defined"""
    
    def test_url_patterns(self):
        """Test that all required URL patterns exist"""
        # Dashboard
        url = reverse('bypasser:dashboard')
        self.assertEqual(url, '/bypasser/')
        
        # API targets
        url = reverse('bypasser:bypasser_targets')
        self.assertEqual(url, '/bypasser/api/targets/')
        
        # Start probe
        url = reverse('bypasser:start_character_probe', kwargs={'target_id': 1})
        self.assertEqual(url, '/bypasser/api/targets/1/probe/')
        
        # Session results
        url = reverse('bypasser:session_results', kwargs={'session_id': 1})
        self.assertEqual(url, '/bypasser/api/sessions/1/results/')
        
        # Test bypass
        url = reverse('bypasser:test_encoding_bypass', kwargs={'session_id': 1})
        self.assertEqual(url, '/bypasser/api/sessions/1/test-bypass/')
        
        # Bypass results
        url = reverse('bypasser:bypass_results', kwargs={'session_id': 1})
        self.assertEqual(url, '/bypasser/api/sessions/1/bypasses/')


class BypasserAdminTest(TestCase):
    """Test that models are registered in admin"""
    
    def test_models_registered_in_admin(self):
        """Test that all models are registered in admin"""
        from django.contrib import admin
        from .models import (
            BypasserTarget, BypasserSession, CharacterProbe,
            EncodingAttempt, BypassResult
        )
        
        self.assertTrue(admin.site.is_registered(BypasserTarget))
        self.assertTrue(admin.site.is_registered(BypasserSession))
        self.assertTrue(admin.site.is_registered(CharacterProbe))
        self.assertTrue(admin.site.is_registered(EncodingAttempt))
        self.assertTrue(admin.site.is_registered(BypassResult))


class URLValidationTest(TestCase):
    """Test URL validation for SSRF prevention"""
    
    def test_valid_https_url(self):
        """Test that valid HTTPS URLs are accepted"""
        is_valid, message = validate_target_url('https://example.com')
        self.assertTrue(is_valid)
    
    def test_valid_http_url(self):
        """Test that valid HTTP URLs are accepted"""
        is_valid, message = validate_target_url('http://example.com')
        self.assertTrue(is_valid)
    
    def test_invalid_scheme_file(self):
        """Test that file:// scheme is rejected"""
        is_valid, message = validate_target_url('file:///etc/passwd')
        self.assertFalse(is_valid)
        self.assertIn('HTTP', message)
    
    def test_invalid_scheme_ftp(self):
        """Test that ftp:// scheme is rejected"""
        is_valid, message = validate_target_url('ftp://example.com')
        self.assertFalse(is_valid)
    
    def test_localhost_blocked(self):
        """Test that localhost is blocked"""
        is_valid, message = validate_target_url('http://localhost/test')
        self.assertFalse(is_valid)
        self.assertIn('internal', message.lower())
    
    def test_127001_blocked(self):
        """Test that 127.0.0.1 is blocked"""
        is_valid, message = validate_target_url('http://127.0.0.1/test')
        self.assertFalse(is_valid)
        self.assertIn('internal', message.lower())
    
    def test_private_network_10_blocked(self):
        """Test that 10.x.x.x network is blocked"""
        is_valid, message = validate_target_url('http://10.0.0.1/test')
        self.assertFalse(is_valid)
        self.assertIn('internal', message.lower())
    
    def test_private_network_192168_blocked(self):
        """Test that 192.168.x.x network is blocked"""
        is_valid, message = validate_target_url('http://192.168.1.1/test')
        self.assertFalse(is_valid)
        self.assertIn('internal', message.lower())
    
    def test_private_network_172_blocked(self):
        """Test that 172.16-31.x.x network is blocked"""
        is_valid, message = validate_target_url('http://172.16.0.1/test')
        self.assertFalse(is_valid)
        self.assertIn('internal', message.lower())
    
    def test_link_local_blocked(self):
        """Test that 169.254.x.x (link-local) is blocked"""
        is_valid, message = validate_target_url('http://169.254.169.254/metadata')
        self.assertFalse(is_valid)
        self.assertIn('internal', message.lower())
    
    def test_metadata_endpoint_blocked(self):
        """Test that cloud metadata endpoints are blocked"""
        is_valid, message = validate_target_url('http://metadata.google.internal/computeMetadata/')
        self.assertFalse(is_valid)
        self.assertIn('internal', message.lower())
