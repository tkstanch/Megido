from django.test import TestCase
from django.conf import settings
from django.urls import reverse, resolve
from django.apps import apps
from . import views


class SpiderAppConfigTest(TestCase):
    """Test that the spider app is properly configured"""
    
    def test_app_exists(self):
        """Verify that spider app exists"""
        app_config = apps.get_app_config('spider')
        self.assertEqual(app_config.name, 'spider')
    
    def test_app_in_installed_apps(self):
        """Verify that spider app is in INSTALLED_APPS"""
        self.assertIn('spider', settings.INSTALLED_APPS)


class SpiderViewTest(TestCase):
    """Test the spider app views"""
    
    def test_index_view_exists(self):
        """Verify that index view exists"""
        self.assertTrue(hasattr(views, 'index'))
    
    def test_index_view_response(self):
        """Verify that index view returns correct response"""
        response = self.client.get('/spider/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Spider app is working!', response.content)


class SpiderUrlsTest(TestCase):
    """Test the spider app URL configuration"""
    
    def test_urls_file_exists(self):
        """Verify that urls.py exists in spider app"""
        from spider import urls
        self.assertTrue(hasattr(urls, 'urlpatterns'))
        self.assertTrue(hasattr(urls, 'app_name'))
        self.assertEqual(urls.app_name, 'spider')
    
    def test_index_url_resolves(self):
        """Verify that the index URL resolves correctly"""
        resolver = resolve('/spider/')
        self.assertEqual(resolver.func, views.index)
