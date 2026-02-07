from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import InterceptorSettings, InterceptedRequest, InterceptedResponse, PayloadRule
import json


class InterceptorSettingsTest(TestCase):
    def test_settings_singleton(self):
        """Test that InterceptorSettings works as a singleton"""
        settings1 = InterceptorSettings.get_settings()
        settings2 = InterceptorSettings.get_settings()
        self.assertEqual(settings1.id, settings2.id)
        self.assertEqual(settings1, settings2)
    
    def test_default_disabled(self):
        """Test that interceptor is disabled by default"""
        settings = InterceptorSettings.get_settings()
        self.assertFalse(settings.is_enabled)
    
    def test_enable_interceptor(self):
        """Test enabling the interceptor"""
        settings = InterceptorSettings.get_settings()
        settings.is_enabled = True
        settings.save()
        
        # Fetch again to verify
        settings = InterceptorSettings.get_settings()
        self.assertTrue(settings.is_enabled)


class InterceptedRequestTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
    
    def test_create_request(self):
        """Test creating an intercepted request"""
        request = InterceptedRequest.objects.create(
            url='http://example.com/test',
            method='GET',
            headers={'Content-Type': 'text/html'},
            body='',
            source_app='browser',
            user=self.user
        )
        self.assertEqual(request.url, 'http://example.com/test')
        self.assertEqual(request.method, 'GET')
        self.assertEqual(request.source_app, 'browser')
    
    def test_request_ordering(self):
        """Test that requests are ordered by timestamp descending"""
        req1 = InterceptedRequest.objects.create(
            url='http://example.com/1',
            method='GET',
            headers={},
            source_app='scanner'
        )
        req2 = InterceptedRequest.objects.create(
            url='http://example.com/2',
            method='POST',
            headers={},
            source_app='spider'
        )
        
        requests = list(InterceptedRequest.objects.all())
        self.assertEqual(requests[0].id, req2.id)  # Most recent first


class InterceptedResponseTest(TestCase):
    def test_create_response(self):
        """Test creating an intercepted response"""
        request = InterceptedRequest.objects.create(
            url='http://example.com/test',
            method='GET',
            headers={},
            source_app='browser'
        )
        
        response = InterceptedResponse.objects.create(
            request=request,
            status_code=200,
            headers={'Content-Type': 'text/html'},
            body='<html></html>',
            response_time=123.45
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request, request)
        self.assertEqual(response.response_time, 123.45)


class PayloadRuleTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
    
    def test_create_rule(self):
        """Test creating a payload rule"""
        rule = PayloadRule.objects.create(
            name='Test Rule',
            target_url_pattern='.*test.*',
            injection_type='header',
            injection_point='X-Test',
            payload_content='test-value',
            active=True,
            created_by=self.user,
            target_apps=['scanner']
        )
        
        self.assertEqual(rule.name, 'Test Rule')
        self.assertTrue(rule.active)
        self.assertEqual(rule.injection_type, 'header')
    
    def test_rule_ordering(self):
        """Test that rules are ordered by creation date descending"""
        rule1 = PayloadRule.objects.create(
            name='Rule 1',
            target_url_pattern='.*',
            injection_type='header',
            injection_point='X-1',
            payload_content='value1',
            created_by=self.user
        )
        rule2 = PayloadRule.objects.create(
            name='Rule 2',
            target_url_pattern='.*',
            injection_type='header',
            injection_point='X-2',
            payload_content='value2',
            created_by=self.user
        )
        
        rules = list(PayloadRule.objects.all())
        self.assertEqual(rules[0].id, rule2.id)  # Most recent first


class InterceptorAPITest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass')
    
    def test_receive_request(self):
        """Test receiving a request from mitmproxy"""
        data = {
            'url': 'http://example.com/api',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"test": "data"}',
            'source_app': 'scanner'
        }
        
        response = self.client.post(
            '/interceptor/api/request/',
            json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        result = response.json()
        self.assertTrue(result['success'])
        self.assertIn('request_id', result)
        
        # Verify request was created
        request_id = result['request_id']
        request = InterceptedRequest.objects.get(id=request_id)
        self.assertEqual(request.url, 'http://example.com/api')
        self.assertEqual(request.method, 'POST')
        self.assertEqual(request.source_app, 'scanner')
    
    def test_receive_response(self):
        """Test receiving a response from mitmproxy"""
        # Create a request first
        request = InterceptedRequest.objects.create(
            url='http://example.com/api',
            method='GET',
            headers={},
            source_app='browser'
        )
        
        data = {
            'request_id': request.id,
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'body': '<html></html>',
            'response_time': 150.0
        }
        
        response = self.client.post(
            '/interceptor/api/response/',
            json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        result = response.json()
        self.assertTrue(result['success'])
        
        # Verify response was created
        response_obj = InterceptedResponse.objects.get(request=request)
        self.assertEqual(response_obj.status_code, 200)
        self.assertEqual(response_obj.response_time, 150.0)
    
    def test_get_active_payload_rules(self):
        """Test getting active payload rules"""
        # Create some rules
        PayloadRule.objects.create(
            name='Active Rule',
            target_url_pattern='.*',
            injection_type='header',
            injection_point='X-Test',
            payload_content='value',
            active=True,
            created_by=self.user
        )
        
        PayloadRule.objects.create(
            name='Inactive Rule',
            target_url_pattern='.*',
            injection_type='header',
            injection_point='X-Test2',
            payload_content='value2',
            active=False,
            created_by=self.user
        )
        
        response = self.client.get('/interceptor/api/payload-rules/active/')
        self.assertEqual(response.status_code, 200)
        
        result = response.json()
        self.assertTrue(result['success'])
        self.assertEqual(result['count'], 1)  # Only active rule
        self.assertEqual(result['rules'][0]['name'], 'Active Rule')
    
    def test_intercept_history(self):
        """Test getting intercept history"""
        self.client.login(username='testuser', password='testpass')
        
        # Create some requests
        InterceptedRequest.objects.create(
            url='http://example.com/1',
            method='GET',
            headers={},
            source_app='scanner'
        )
        InterceptedRequest.objects.create(
            url='http://example.com/2',
            method='POST',
            headers={},
            source_app='spider'
        )
        
        # Get all history
        response = self.client.get('/interceptor/api/history/')
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertEqual(len(data), 2)
        
        # Filter by source_app
        response = self.client.get('/interceptor/api/history/?source_app=scanner')
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['source_app'], 'scanner')


class InterceptorViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
    
    def test_interceptor_dashboard(self):
        """Test that interceptor dashboard loads correctly"""
        response = self.client.get('/interceptor/')
        self.assertEqual(response.status_code, 200)
    
    def test_status_api_get(self):
        """Test getting interceptor status"""
        response = self.client.get('/interceptor/api/status/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('is_enabled', data)
        self.assertFalse(data['is_enabled'])  # Should be disabled by default
    
    def test_status_api_toggle(self):
        """Test toggling interceptor status"""
        # Enable interceptor
        response = self.client.post(
            '/interceptor/api/status/',
            json.dumps({'is_enabled': True}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertTrue(data['is_enabled'])
        
        # Verify it's enabled
        response = self.client.get('/interceptor/api/status/')
        data = response.json()
        self.assertTrue(data['is_enabled'])
        
        # Disable it
        response = self.client.post(
            '/interceptor/api/status/',
            json.dumps({'is_enabled': False}),
            content_type='application/json'
        )
        data = response.json()
        self.assertFalse(data['is_enabled'])
