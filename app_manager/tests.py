from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import AppConfiguration, AppStateChange, AppSettings


class AppConfigurationModelTest(TestCase):
    def setUp(self):
        self.app_config = AppConfiguration.objects.create(
            app_name='test_app',
            display_name='Test App',
            description='A test application',
            is_enabled=True,
            icon='🧪',
            category='testing',
            capabilities='test, debug, verify'
        )
    
    def test_app_configuration_creation(self):
        """Test that app configuration is created correctly"""
        self.assertEqual(self.app_config.app_name, 'test_app')
        self.assertEqual(self.app_config.display_name, 'Test App')
        self.assertTrue(self.app_config.is_enabled)
    
    def test_get_capabilities_list(self):
        """Test that capabilities are returned as a list"""
        capabilities = self.app_config.get_capabilities_list()
        self.assertEqual(len(capabilities), 3)
        self.assertIn('test', capabilities)
        self.assertIn('debug', capabilities)
    
    def test_string_representation(self):
        """Test string representation of app config"""
        expected = "Test App (Enabled)"
        self.assertEqual(str(self.app_config), expected)


class AppManagerViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.app_config = AppConfiguration.objects.create(
            app_name='test_app',
            display_name='Test App',
            description='A test application',
            is_enabled=True,
            icon='🧪',
            category='testing',
            capabilities='test, debug'
        )
    
    def test_dashboard_view(self):
        """Test that dashboard view loads correctly"""
        response = self.client.get('/app-manager/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'App Management Dashboard')
        self.assertContains(response, 'Test App')
    
    def test_list_apps_api(self):
        """Test that list apps API returns correct data"""
        response = self.client.get('/app-manager/api/apps/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(isinstance(data, list))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['app_name'], 'test_app')
    
    def test_toggle_app_api(self):
        """Test that toggle app API changes state"""
        self.assertTrue(self.app_config.is_enabled)
        response = self.client.post(f'/app-manager/api/apps/{self.app_config.id}/toggle/')
        self.assertEqual(response.status_code, 200)
        
        # Refresh from database
        self.app_config.refresh_from_db()
        self.assertFalse(self.app_config.is_enabled)
    
    def test_app_detail_api(self):
        """Test that app detail API returns correct data"""
        response = self.client.get(f'/app-manager/api/apps/{self.app_config.id}/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['app_name'], 'test_app')
        self.assertEqual(data['display_name'], 'Test App')


class AppStateChangeTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.app_config = AppConfiguration.objects.create(
            app_name='test_app',
            display_name='Test App',
            description='A test application',
            is_enabled=True
        )
    
    def test_state_change_logging(self):
        """Test that state changes are logged"""
        AppStateChange.objects.create(
            app_config=self.app_config,
            user=self.user,
            previous_state=True,
            new_state=False,
            ip_address='127.0.0.1'
        )
        
        changes = AppStateChange.objects.filter(app_config=self.app_config)
        self.assertEqual(changes.count(), 1)
        change = changes.first()
        self.assertEqual(change.user, self.user)
        self.assertTrue(change.previous_state)
        self.assertFalse(change.new_state)
