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


class CustomBypassTechniqueTest(TestCase):
    """Test custom bypass technique models"""
    
    def test_custom_technique_creation(self):
        """Test creating a custom bypass technique"""
        from .models import CustomBypassTechnique
        
        technique = CustomBypassTechnique.objects.create(
            name='Double URL Encoding',
            description='Applies URL encoding twice',
            category='waf',
            technique_template='{{payload|url_encode_double}}',
            example_input='<script>',
            example_output='%253Cscript%253E',
            tags='url,encoding,waf',
            author='TestUser'
        )
        
        self.assertEqual(technique.name, 'Double URL Encoding')
        self.assertEqual(technique.category, 'waf')
        self.assertEqual(technique.times_used, 0)
        self.assertEqual(technique.times_successful, 0)
        self.assertEqual(technique.success_rate, 0.0)
        self.assertTrue(technique.is_active)
    
    def test_custom_technique_update_success_rate(self):
        """Test updating success rate of a technique"""
        from .models import CustomBypassTechnique
        
        technique = CustomBypassTechnique.objects.create(
            name='Test Technique',
            category='waf',
            technique_template='{{payload|url_encode}}',
            times_used=10,
            times_successful=7
        )
        
        technique.update_success_rate()
        self.assertEqual(technique.success_rate, 70.0)
    
    def test_custom_technique_execution_creation(self):
        """Test creating a custom technique execution record"""
        from .models import CustomBypassTechnique, CustomTechniqueExecution
        
        target = BypasserTarget.objects.create(
            url='https://example.com',
            name='Test Target'
        )
        session = BypasserSession.objects.create(
            target=target,
            status='running'
        )
        technique = CustomBypassTechnique.objects.create(
            name='Test Technique',
            category='waf',
            technique_template='{{payload|url_encode}}'
        )
        
        execution = CustomTechniqueExecution.objects.create(
            session=session,
            technique=technique,
            input_payload='<script>',
            output_payload='%3Cscript%3E',
            success=True,
            bypass_confirmed=True,
            reflection_found=True
        )
        
        self.assertEqual(execution.input_payload, '<script>')
        self.assertEqual(execution.output_payload, '%3Cscript%3E')
        self.assertTrue(execution.success)
        self.assertTrue(execution.bypass_confirmed)


class TechniqueParserTest(TestCase):
    """Test technique parser functionality"""
    
    def test_template_validation_valid(self):
        """Test validation of valid templates"""
        from .technique_parser import TechniqueParser
        
        is_valid, msg = TechniqueParser.validate_template('{{payload|url_encode}}')
        self.assertTrue(is_valid)
        
        is_valid, msg = TechniqueParser.validate_template('{{char|html_hex|base64}}')
        self.assertTrue(is_valid)
        
        is_valid, msg = TechniqueParser.validate_template('test{{payload|url_encode}}test')
        self.assertTrue(is_valid)
    
    def test_template_validation_invalid(self):
        """Test validation of invalid templates"""
        from .technique_parser import TechniqueParser
        
        # Empty template
        is_valid, msg = TechniqueParser.validate_template('')
        self.assertFalse(is_valid)
        
        # No placeholders
        is_valid, msg = TechniqueParser.validate_template('just text')
        self.assertFalse(is_valid)
        
        # Dangerous pattern
        is_valid, msg = TechniqueParser.validate_template('{{payload}}__import__("os")')
        self.assertFalse(is_valid)
        
        # Invalid variable name
        is_valid, msg = TechniqueParser.validate_template('{{invalid_var|url_encode}}')
        self.assertFalse(is_valid)
        
        # Invalid transformation
        is_valid, msg = TechniqueParser.validate_template('{{payload|nonexistent_transform}}')
        self.assertFalse(is_valid)
    
    def test_parse_and_execute_simple(self):
        """Test parsing and executing simple templates"""
        from .technique_parser import TechniqueParser
        
        success, result, error = TechniqueParser.parse_and_execute(
            '{{payload}}',
            {'payload': 'test'}
        )
        
        self.assertTrue(success)
        self.assertEqual(result, 'test')
        self.assertEqual(error, '')
    
    def test_parse_and_execute_with_transformation(self):
        """Test parsing and executing templates with transformations"""
        from .technique_parser import TechniqueParser
        
        success, result, error = TechniqueParser.parse_and_execute(
            '{{payload|url_encode}}',
            {'payload': '<script>'}
        )
        
        self.assertTrue(success)
        self.assertEqual(result, '%3Cscript%3E')
    
    def test_parse_and_execute_chained_transformations(self):
        """Test parsing and executing templates with chained transformations"""
        from .technique_parser import TechniqueParser
        
        success, result, error = TechniqueParser.parse_and_execute(
            '{{payload|upper}}',
            {'payload': 'script'}
        )
        
        self.assertTrue(success)
        self.assertEqual(result, 'SCRIPT')
    
    def test_parse_and_execute_multiple_placeholders(self):
        """Test parsing templates with multiple placeholders"""
        from .technique_parser import TechniqueParser
        
        success, result, error = TechniqueParser.parse_and_execute(
            '{{payload|url_encode}}{{char|html_hex}}',
            {'payload': '<', 'char': '>'}
        )
        
        self.assertTrue(success)
        self.assertIn('%3C', result)
        self.assertIn('&#x3e;', result)
    
    def test_get_available_transformations(self):
        """Test getting available transformations"""
        from .technique_parser import TechniqueParser
        
        transformations = TechniqueParser.get_available_transformations()
        
        self.assertIn('url_encode', transformations)
        self.assertIn('html_hex', transformations)
        self.assertIn('base64', transformations)
        self.assertIsInstance(transformations['url_encode'], str)
    
    def test_get_available_variables(self):
        """Test getting available variables"""
        from .technique_parser import TechniqueParser
        
        variables = TechniqueParser.get_available_variables()
        
        self.assertIn('payload', variables)
        self.assertIn('char', variables)
        self.assertIn('target', variables)
        self.assertIn('param', variables)


class CustomTechniqueAPITest(TestCase):
    """Test custom technique API endpoints"""
    
    def setUp(self):
        """Set up test client"""
        self.client = Client()
    
    def test_create_custom_technique(self):
        """Test creating a custom technique via API"""
        response = self.client.post(
            '/bypasser/api/custom-techniques/',
            data=json.dumps({
                'name': 'Test Technique',
                'description': 'A test bypass technique',
                'category': 'waf',
                'technique_template': '{{payload|url_encode_double}}',
                'tags': 'test,url,encoding'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn('id', data)
        self.assertEqual(data['name'], 'Test Technique')
    
    def test_create_custom_technique_invalid_template(self):
        """Test creating technique with invalid template"""
        response = self.client.post(
            '/bypasser/api/custom-techniques/',
            data=json.dumps({
                'name': 'Invalid Technique',
                'technique_template': '{{payload|nonexistent}}',
                'category': 'waf'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn('error', data)
    
    def test_list_custom_techniques(self):
        """Test listing custom techniques"""
        from .models import CustomBypassTechnique
        
        # Create test techniques
        CustomBypassTechnique.objects.create(
            name='Technique 1',
            category='waf',
            technique_template='{{payload|url_encode}}'
        )
        CustomBypassTechnique.objects.create(
            name='Technique 2',
            category='firewall',
            technique_template='{{payload|html_hex}}'
        )
        
        response = self.client.get('/bypasser/api/custom-techniques/')
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(len(data), 2)
        # Check that both techniques are present
        names = [tech['name'] for tech in data]
        self.assertIn('Technique 1', names)
        self.assertIn('Technique 2', names)
    
    def test_get_custom_technique_detail(self):
        """Test getting technique details"""
        from .models import CustomBypassTechnique
        
        technique = CustomBypassTechnique.objects.create(
            name='Test Technique',
            category='waf',
            technique_template='{{payload|url_encode}}'
        )
        
        response = self.client.get(f'/bypasser/api/custom-techniques/{technique.id}/')
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(data['name'], 'Test Technique')
        self.assertEqual(data['category'], 'waf')
    
    def test_update_custom_technique(self):
        """Test updating a custom technique"""
        from .models import CustomBypassTechnique
        
        technique = CustomBypassTechnique.objects.create(
            name='Original Name',
            category='waf',
            technique_template='{{payload|url_encode}}'
        )
        
        response = self.client.put(
            f'/bypasser/api/custom-techniques/{technique.id}/',
            data=json.dumps({
                'name': 'Updated Name',
                'description': 'Updated description'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Verify update
        technique.refresh_from_db()
        self.assertEqual(technique.name, 'Updated Name')
        self.assertEqual(technique.description, 'Updated description')
    
    def test_delete_custom_technique(self):
        """Test deleting a custom technique"""
        from .models import CustomBypassTechnique
        
        technique = CustomBypassTechnique.objects.create(
            name='To Delete',
            category='waf',
            technique_template='{{payload|url_encode}}'
        )
        
        response = self.client.delete(f'/bypasser/api/custom-techniques/{technique.id}/')
        self.assertEqual(response.status_code, 204)
        
        # Verify deletion
        self.assertFalse(CustomBypassTechnique.objects.filter(id=technique.id).exists())
    
    def test_test_custom_technique(self):
        """Test testing a custom technique"""
        from .models import CustomBypassTechnique
        
        technique = CustomBypassTechnique.objects.create(
            name='Test Technique',
            category='waf',
            technique_template='{{payload|url_encode}}'
        )
        
        response = self.client.post(
            f'/bypasser/api/custom-techniques/{technique.id}/test/',
            data=json.dumps({
                'payload': '<script>alert(1)</script>'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('%3C', data['result'])
    
    def test_get_available_transformations(self):
        """Test getting available transformations"""
        response = self.client.get('/bypasser/api/transformations/')
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertIn('transformations', data)
        self.assertIn('variables', data)
        self.assertIn('template_syntax', data)
        self.assertIn('examples', data)
