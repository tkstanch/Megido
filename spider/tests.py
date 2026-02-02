from django.test import TestCase, Client
from django.urls import reverse
from django.conf import settings
from django.apps import apps
from .models import (
    SpiderTarget, SpiderSession, DiscoveredURL,
    HiddenContent, BruteForceAttempt, InferredContent,
    ToolScanResult
)
from . import views
import json


class SpiderAppConfigTest(TestCase):
    """Test that the spider app is properly configured"""
    
    def test_app_exists(self):
        """Verify that spider app exists"""
        app_config = apps.get_app_config('spider')
        self.assertEqual(app_config.name, 'spider')
    
    def test_app_in_installed_apps(self):
        """Verify that spider app is in INSTALLED_APPS"""
        self.assertIn('spider', settings.INSTALLED_APPS)


class SpiderModelsTest(TestCase):
    """Test spider models"""
    
    def setUp(self):
        """Set up test data"""
        self.target = SpiderTarget.objects.create(
            url='https://example.com',
            name='Test Target',
            max_depth=3
        )
        self.session = SpiderSession.objects.create(
            target=self.target,
            status='pending'
        )
    
    def test_spider_target_creation(self):
        """Test creating a spider target"""
        self.assertEqual(self.target.url, 'https://example.com')
        self.assertEqual(self.target.name, 'Test Target')
        self.assertEqual(self.target.max_depth, 3)
        self.assertTrue(self.target.use_dirbuster)
        self.assertTrue(self.target.use_nikto)
    
    def test_spider_session_creation(self):
        """Test creating a spider session"""
        self.assertEqual(self.session.target, self.target)
        self.assertEqual(self.session.status, 'pending')
        self.assertEqual(self.session.urls_discovered, 0)
        self.assertIsNotNone(self.session.started_at)
    
    def test_discovered_url_creation(self):
        """Test creating a discovered URL"""
        url = DiscoveredURL.objects.create(
            session=self.session,
            url='https://example.com/test',
            discovery_method='crawl',
            status_code=200
        )
        self.assertEqual(url.session, self.session)
        self.assertEqual(url.discovery_method, 'crawl')
        self.assertEqual(url.status_code, 200)
    
    def test_hidden_content_creation(self):
        """Test creating hidden content"""
        content = HiddenContent.objects.create(
            session=self.session,
            url='https://example.com/admin',
            content_type='admin_panel',
            discovery_method='dirbuster',
            status_code=200,
            risk_level='high'
        )
        self.assertEqual(content.content_type, 'admin_panel')
        self.assertEqual(content.risk_level, 'high')
    
    def test_brute_force_attempt_creation(self):
        """Test creating brute force attempt"""
        attempt = BruteForceAttempt.objects.create(
            session=self.session,
            base_url='https://example.com',
            path_tested='/admin',
            full_url='https://example.com/admin',
            status_code=200,
            success=True
        )
        self.assertTrue(attempt.success)
        self.assertEqual(attempt.status_code, 200)
    
    def test_inferred_content_creation(self):
        """Test creating inferred content"""
        inferred = InferredContent.objects.create(
            session=self.session,
            source_url='https://example.com/v1',
            inferred_url='https://example.com/v2',
            inference_type='version',
            confidence=0.8,
            reasoning='Version pattern detected'
        )
        self.assertEqual(inferred.inference_type, 'version')
        self.assertEqual(inferred.confidence, 0.8)
        self.assertFalse(inferred.verified)
    
    def test_tool_scan_result_creation(self):
        """Test creating tool scan result"""
        result = ToolScanResult.objects.create(
            session=self.session,
            tool_name='dirbuster',
            status='running'
        )
        self.assertEqual(result.tool_name, 'dirbuster')
        self.assertEqual(result.findings_count, 0)
    
    def test_spider_session_statistics(self):
        """Test session statistics update"""
        # Create some discovered URLs
        for i in range(5):
            DiscoveredURL.objects.create(
                session=self.session,
                url=f'https://example.com/page{i}',
                discovery_method='crawl'
            )
        
        # Update statistics
        self.session.urls_discovered = self.session.discovered_urls.count()
        self.session.save()
        
        self.assertEqual(self.session.urls_discovered, 5)


class SpiderViewTest(TestCase):
    """Test spider views"""
    
    def setUp(self):
        """Set up test client and data"""
        self.client = Client()
        self.target = SpiderTarget.objects.create(
            url='https://example.com',
            name='Test Target'
        )
        self.session = SpiderSession.objects.create(
            target=self.target,
            status='completed'
        )
    
    def test_index_view(self):
        """Test spider index/dashboard view"""
        response = self.client.get(reverse('spider:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'spider/dashboard.html')
    
    def test_spider_targets_list(self):
        """Test listing spider targets via API"""
        response = self.client.get(reverse('spider:spider_targets'))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['url'], 'https://example.com')
    
    def test_spider_targets_create(self):
        """Test creating a spider target via API"""
        response = self.client.post(
            reverse('spider:spider_targets'),
            data=json.dumps({
                'url': 'https://test.com',
                'name': 'New Target',
                'max_depth': 2
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.content)
        self.assertIn('id', data)
        
        # Verify target was created
        target = SpiderTarget.objects.get(id=data['id'])
        self.assertEqual(target.url, 'https://test.com')
        self.assertEqual(target.name, 'New Target')
    
    def test_spider_results(self):
        """Test getting spider session results"""
        # Add some test data
        DiscoveredURL.objects.create(
            session=self.session,
            url='https://example.com/test',
            discovery_method='crawl',
            status_code=200
        )
        
        HiddenContent.objects.create(
            session=self.session,
            url='https://example.com/admin',
            content_type='admin_panel',
            discovery_method='dirbuster',
            status_code=200,
            risk_level='high'
        )
        
        response = self.client.get(
            reverse('spider:spider_results', kwargs={'session_id': self.session.id})
        )
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertEqual(data['session_id'], self.session.id)
        self.assertEqual(data['status'], 'completed')
        self.assertIn('discovered_urls', data)
        self.assertIn('hidden_content', data)
        self.assertGreater(len(data['discovered_urls']), 0)
        self.assertGreater(len(data['hidden_content']), 0)
    
    def test_spider_results_not_found(self):
        """Test getting results for non-existent session"""
        response = self.client.get(
            reverse('spider:spider_results', kwargs={'session_id': 99999})
        )
        self.assertEqual(response.status_code, 404)


class SpiderUrlsTest(TestCase):
    """Test spider URL configuration"""
    
    def test_urls_file_exists(self):
        """Verify that urls.py exists and is configured"""
        from spider import urls
        self.assertTrue(hasattr(urls, 'urlpatterns'))
        self.assertTrue(hasattr(urls, 'app_name'))
        self.assertEqual(urls.app_name, 'spider')
    
    def test_url_patterns(self):
        """Test that all required URL patterns are defined"""
        url_names = ['index', 'spider_targets', 'start_spider', 'spider_results']
        for name in url_names:
            try:
                url = reverse(f'spider:{name}', kwargs={'target_id': 1} if 'target' in name else {'session_id': 1} if 'session' in name else {})
                self.assertIsNotNone(url)
            except Exception as e:
                if 'target_id' not in str(e) and 'session_id' not in str(e):
                    self.fail(f"URL pattern 'spider:{name}' not found")


class SpiderAdminTest(TestCase):
    """Test spider admin interface"""
    
    def test_models_registered_in_admin(self):
        """Test that all models are registered in admin"""
        from django.contrib import admin
        from spider import models
        
        registered_models = [
            models.SpiderTarget,
            models.SpiderSession,
            models.DiscoveredURL,
            models.HiddenContent,
            models.BruteForceAttempt,
            models.InferredContent,
            models.ToolScanResult,
        ]
        
        for model in registered_models:
            self.assertTrue(
                admin.site.is_registered(model),
                f"{model.__name__} is not registered in admin"
            )
