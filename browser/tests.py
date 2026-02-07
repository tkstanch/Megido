from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import BrowserSession, BrowserHistory, BrowserAppInteraction, BrowserSettings
from unittest.mock import Mock, patch, MagicMock
import sys


class BrowserSessionModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.session = BrowserSession.objects.create(
            user=self.user,
            session_name='Test Session'
        )
    
    def test_session_creation(self):
        """Test that browser session is created correctly"""
        self.assertEqual(self.session.session_name, 'Test Session')
        self.assertEqual(self.session.user, self.user)
        self.assertTrue(self.session.is_active)
    
    def test_session_string_representation(self):
        """Test string representation of session"""
        self.assertIn('Test Session', str(self.session))


class BrowserHistoryModelTest(TestCase):
    def setUp(self):
        self.session = BrowserSession.objects.create(session_name='Test Session')
        self.history = BrowserHistory.objects.create(
            session=self.session,
            url='https://example.com',
            title='Example Domain'
        )
    
    def test_history_creation(self):
        """Test that browser history is created correctly"""
        self.assertEqual(self.history.url, 'https://example.com')
        self.assertEqual(self.history.title, 'Example Domain')
        self.assertEqual(self.history.session, self.session)


class BrowserViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
    
    def test_browser_view(self):
        """Test that browser view loads correctly"""
        response = self.client.get('/browser/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Integrated Browser')
        self.assertContains(response, 'Available Apps')
        # Check for new interceptor integration
        self.assertContains(response, 'Interceptor')
    
    def test_interceptor_status_get(self):
        """Test getting interceptor status from browser"""
        response = self.client.get('/browser/api/interceptor-status/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('is_enabled', data)
        self.assertIn('updated_at', data)
    
    def test_interceptor_status_toggle(self):
        """Test toggling interceptor status from browser"""
        # First get current status
        response = self.client.get('/browser/api/interceptor-status/')
        current_status = response.json()['is_enabled']
        
        # Toggle it
        response = self.client.post(
            '/browser/api/interceptor-status/',
            {'is_enabled': not current_status},
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['is_enabled'], not current_status)
    
    def test_list_sessions_api(self):
        """Test that list sessions API works"""
        response = self.client.get('/browser/api/sessions/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(isinstance(data, list))
    
    def test_add_history_api(self):
        """Test that add history API works"""
        session = BrowserSession.objects.create(session_name='Test')
        response = self.client.post(
            '/browser/api/history/',
            data={
                'session_id': session.id,
                'url': 'https://example.com',
                'title': 'Example'
            },
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        
        # Verify history was created
        history = BrowserHistory.objects.filter(session=session)
        self.assertEqual(history.count(), 1)
    
    def test_log_app_interaction_api(self):
        """Test that log app interaction API works"""
        session = BrowserSession.objects.create(session_name='Test')
        response = self.client.post(
            '/browser/api/interaction/',
            data={
                'session_id': session.id,
                'app_name': 'scanner',
                'action': 'scan',
                'target_url': 'https://example.com'
            },
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        
        # Verify interaction was logged
        interactions = BrowserAppInteraction.objects.filter(session=session)
        self.assertEqual(interactions.count(), 1)
        interaction = interactions.first()
        self.assertEqual(interaction.app_name, 'scanner')


class CEFIntegrationTests(TestCase):
    """
    Tests for CEF integration modules
    
    Note: These tests mock CEF Python since it may not be installed in test environment
    """
    
    def setUp(self):
        """Set up test fixtures"""
        self.django_url = "http://127.0.0.1:8000"
    
    @patch('browser.cef_integration.django_bridge.requests.Session')
    def test_django_bridge_initialization(self, mock_session):
        """Test DjangoBridge initialization"""
        from browser.cef_integration.django_bridge import DjangoBridge
        
        bridge = DjangoBridge(self.django_url)
        self.assertEqual(bridge.base_url, self.django_url)
        self.assertIsNotNone(bridge.session)
    
    @patch('browser.cef_integration.django_bridge.requests.Session')
    def test_django_bridge_get_enabled_apps(self, mock_session):
        """Test fetching enabled apps through bridge"""
        from browser.cef_integration.django_bridge import DjangoBridge
        
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = [
            {'app_name': 'scanner', 'display_name': 'Scanner'},
            {'app_name': 'proxy', 'display_name': 'Proxy'}
        ]
        mock_response.raise_for_status = Mock()
        mock_session.return_value.get.return_value = mock_response
        
        bridge = DjangoBridge(self.django_url)
        apps = bridge.get_enabled_apps()
        
        self.assertEqual(len(apps), 2)
        self.assertEqual(apps[0]['app_name'], 'scanner')
    
    @patch('browser.cef_integration.django_bridge.requests.Session')
    def test_django_bridge_interceptor_toggle(self, mock_session):
        """Test toggling interceptor through bridge"""
        from browser.cef_integration.django_bridge import DjangoBridge
        
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {'success': True, 'is_enabled': True}
        mock_response.raise_for_status = Mock()
        mock_session.return_value.post.return_value = mock_response
        
        bridge = DjangoBridge(self.django_url)
        result = bridge.toggle_interceptor(True)
        
        self.assertTrue(result['success'])
        self.assertTrue(result['is_enabled'])
    
    @patch('browser.cef_integration.django_bridge.requests.Session')
    def test_django_bridge_add_history(self, mock_session):
        """Test adding history through bridge"""
        from browser.cef_integration.django_bridge import DjangoBridge
        
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {'success': True, 'history_id': 1}
        mock_response.raise_for_status = Mock()
        mock_session.return_value.post.return_value = mock_response
        
        bridge = DjangoBridge(self.django_url)
        result = bridge.add_history(1, "https://example.com", "Example")
        
        self.assertTrue(result['success'])
        self.assertEqual(result['history_id'], 1)
    
    @patch('browser.cef_integration.django_bridge.DjangoBridge')
    def test_session_manager_start_session(self, mock_bridge_class):
        """Test SessionManager session creation"""
        from browser.cef_integration.session_manager import SessionManager
        
        # Mock bridge
        mock_bridge = Mock()
        mock_bridge.create_session.return_value = 1
        
        session_manager = SessionManager(mock_bridge)
        session_id = session_manager.start_session("Test Session")
        
        self.assertEqual(session_id, 1)
        self.assertEqual(session_manager.current_session_id, 1)
        mock_bridge.create_session.assert_called_once_with("Test Session")
    
    @patch('browser.cef_integration.django_bridge.DjangoBridge')
    def test_session_manager_log_navigation(self, mock_bridge_class):
        """Test SessionManager navigation logging"""
        from browser.cef_integration.session_manager import SessionManager
        
        # Mock bridge
        mock_bridge = Mock()
        mock_bridge.create_session.return_value = 1
        mock_bridge.add_history.return_value = {'success': True}
        
        session_manager = SessionManager(mock_bridge)
        session_manager.start_session()
        result = session_manager.log_navigation("https://example.com", "Example")
        
        self.assertTrue(result)
        mock_bridge.add_history.assert_called_once()
    
    @patch('browser.cef_integration.django_bridge.DjangoBridge')
    def test_session_manager_log_app_action(self, mock_bridge_class):
        """Test SessionManager app action logging"""
        from browser.cef_integration.session_manager import SessionManager
        
        # Mock bridge
        mock_bridge = Mock()
        mock_bridge.create_session.return_value = 1
        mock_bridge.log_app_interaction.return_value = {'success': True}
        
        session_manager = SessionManager(mock_bridge)
        session_manager.start_session()
        result = session_manager.log_app_action("scanner", "scan", "https://example.com")
        
        self.assertTrue(result)
        mock_bridge.log_app_interaction.assert_called_once()
    
    @patch('browser.cef_integration.django_bridge.DjangoBridge')
    def test_request_handler_initialization(self, mock_bridge_class):
        """Test RequestHandler initialization"""
        from browser.cef_integration.request_handler import RequestHandler
        
        mock_bridge = Mock()
        mock_bridge.get_interceptor_status.return_value = {'is_enabled': False}
        
        handler = RequestHandler(mock_bridge)
        
        self.assertIsNotNone(handler)
        self.assertFalse(handler.interceptor_enabled)
    
    @patch('browser.cef_integration.django_bridge.DjangoBridge')
    def test_request_handler_update_status(self, mock_bridge_class):
        """Test RequestHandler interceptor status update"""
        from browser.cef_integration.request_handler import RequestHandler
        
        mock_bridge = Mock()
        mock_bridge.get_interceptor_status.return_value = {'is_enabled': True}
        
        handler = RequestHandler(mock_bridge)
        handler.update_interceptor_status()
        
        self.assertTrue(handler.interceptor_enabled)
    
    def test_cef_integration_module_imports(self):
        """Test that CEF integration modules can be imported"""
        try:
            from browser.cef_integration import django_bridge
            from browser.cef_integration import session_manager
            from browser.cef_integration import request_handler
            
            # These should not raise ImportError
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import CEF integration modules: {e}")
    
    def test_cef_integration_graceful_degradation(self):
        """Test that CEF integration handles missing cefpython3 gracefully"""
        # browser_window should handle missing CEF gracefully
        # It should not crash on import, just set cef = None
        try:
            from browser.cef_integration import browser_window
            # Should import without error even if cefpython3 is not installed
            self.assertTrue(True)
        except ImportError:
            self.fail("browser_window.py should not fail to import when cefpython3 is missing")


class DesktopLauncherTests(TestCase):
    """
    Tests for desktop launcher functionality
    """
    
    @patch('browser.desktop_launcher.DJANGO_AVAILABLE', True)
    def test_django_launcher_initialization(self):
        """Test DjangoServerLauncher initialization"""
        from browser.desktop_launcher import DjangoServerLauncher
        
        launcher = DjangoServerLauncher(port=8001, host="127.0.0.1")
        
        self.assertEqual(launcher.port, 8001)
        self.assertEqual(launcher.host, "127.0.0.1")
        self.assertIsNone(launcher.process)
    
    @patch('browser.desktop_launcher.CEF_AVAILABLE', True)
    def test_cef_launcher_initialization(self):
        """Test CEFBrowserLauncher initialization"""
        from browser.desktop_launcher import CEFBrowserLauncher
        
        launcher = CEFBrowserLauncher("http://localhost:8000")
        
        self.assertEqual(launcher.django_url, "http://localhost:8000")
        self.assertIsNone(launcher.browser_window)


class BackwardCompatibilityTests(TestCase):
    """
    Tests to ensure iframe browser still works alongside CEF integration
    """
    
    def test_iframe_browser_view_still_works(self):
        """Test that original iframe browser view still loads"""
        response = self.client.get('/browser/')
        self.assertEqual(response.status_code, 200)
    
    def test_browser_api_endpoints_still_work(self):
        """Test that all original API endpoints still function"""
        # Test sessions endpoint
        response = self.client.get('/browser/api/sessions/')
        self.assertEqual(response.status_code, 200)
        
        # Test enabled apps endpoint
        response = self.client.get('/browser/api/enabled-apps/')
        self.assertEqual(response.status_code, 200)
        
        # Test interceptor status endpoint
        response = self.client.get('/browser/api/interceptor-status/')
        self.assertEqual(response.status_code, 200)
    
    def test_existing_models_unchanged(self):
        """Test that existing browser models still work"""
        session = BrowserSession.objects.create(session_name="Test")
        self.assertIsNotNone(session)
        
        history = BrowserHistory.objects.create(
            session=session,
            url="https://example.com"
        )
        self.assertIsNotNone(history)
        
        interaction = BrowserAppInteraction.objects.create(
            session=session,
            app_name="scanner",
            action="test"
        )
        self.assertIsNotNone(interaction)


class BrowserAppInteractionTest(TestCase):
    def setUp(self):
        self.session = BrowserSession.objects.create(session_name='Test Session')
        self.interaction = BrowserAppInteraction.objects.create(
            session=self.session,
            app_name='scanner',
            action='scan_page',
            target_url='https://example.com',
            result='Scan completed'
        )
    
    def test_interaction_creation(self):
        """Test that interaction is logged correctly"""
        self.assertEqual(self.interaction.app_name, 'scanner')
        self.assertEqual(self.interaction.action, 'scan_page')
        self.assertEqual(self.interaction.target_url, 'https://example.com')
