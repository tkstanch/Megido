from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import BrowserSession, BrowserHistory, BrowserAppInteraction, BrowserSettings


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
