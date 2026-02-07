from django.test import TestCase, Client
from .models import InterceptorSettings, InterceptedRequest
from proxy.models import ProxyRequest


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


class InterceptorViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
    
    def test_interceptor_dashboard(self):
        """Test that interceptor dashboard loads correctly"""
        response = self.client.get('/interceptor/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Request Interceptor')
        self.assertContains(response, 'Interceptor Control')
    
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
            {'is_enabled': True},
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
            {'is_enabled': False},
            content_type='application/json'
        )
        data = response.json()
        self.assertFalse(data['is_enabled'])
