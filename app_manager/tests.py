from io import StringIO
from unittest.mock import patch

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.core.management import call_command
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


class PopulateAppsCommandTest(TestCase):
    def test_populate_apps_creates_forensics_app(self):
        """Test that populate_apps command creates forensics app configuration"""
        # Run the populate_apps command
        call_command('populate_apps')
        
        # Check that forensics app was created
        forensics_app = AppConfiguration.objects.filter(app_name='forensics').first()
        self.assertIsNotNone(forensics_app, "Forensics app should be created by populate_apps command")
        self.assertEqual(forensics_app.display_name, 'Digital Forensics')
        self.assertEqual(forensics_app.category, 'analysis')
        self.assertEqual(forensics_app.icon, '🔬')
        self.assertIn('analyze', forensics_app.capabilities)
    
    def test_populate_apps_creates_all_apps(self):
        """Test that populate_apps command creates all expected apps"""
        call_command('populate_apps')
        
        # Expected apps based on the populate_apps command
        expected_apps = [
            'proxy', 'spider', 'scanner', 'repeater', 'interceptor',
            'mapper', 'bypasser', 'collaborator', 'decompiler',
            'malware_analyser', 'response_analyser', 'sql_attacker',
            'data_tracer', 'discover', 'manipulator', 'forensics'
        ]
        
        for app_name in expected_apps:
            app = AppConfiguration.objects.filter(app_name=app_name).first()
            self.assertIsNotNone(app, f"App '{app_name}' should be created by populate_apps command")
        
        # Verify the total count
        self.assertEqual(AppConfiguration.objects.count(), len(expected_apps))


class PopulateAllCommandTest(TestCase):
    """Test the populate_all management command"""

    def test_command_runs_successfully(self):
        """Test that the command runs without errors"""
        out = StringIO()
        err = StringIO()
        call_command('populate_all', stdout=out, stderr=err)
        output = out.getvalue()

        self.assertIn('Summary:', output)
        self.assertIn('populate_apps', output)
        self.assertIn('populate_manipulator_data', output)
        self.assertIn('populate_malware_data', output)

    def test_all_subcommand_data_is_populated(self):
        """Test that data from all three sub-commands is populated"""
        from manipulator.models import VulnerabilityType, Payload, EncodingTechnique
        from malware_analyser.models import AnalysisGoal, MalwareType

        call_command('populate_all')

        # populate_apps data
        expected_apps = [
            'proxy', 'spider', 'scanner', 'repeater', 'interceptor',
            'mapper', 'bypasser', 'collaborator', 'decompiler',
            'malware_analyser', 'response_analyser', 'sql_attacker',
            'data_tracer', 'discover', 'manipulator', 'forensics'
        ]
        for app_name in expected_apps:
            self.assertTrue(
                AppConfiguration.objects.filter(app_name=app_name).exists(),
                f"App '{app_name}' should exist after populate_all",
            )

        # populate_manipulator_data data
        self.assertTrue(VulnerabilityType.objects.filter(name='XSS').exists())
        self.assertTrue(Payload.objects.count() > 0)
        self.assertTrue(EncodingTechnique.objects.filter(name='URL Encoding').exists())

        # populate_malware_data data
        self.assertTrue(AnalysisGoal.objects.count() > 0)
        self.assertTrue(MalwareType.objects.count() > 0)

    def test_stop_on_error_flag_stops_execution(self):
        """Test that --stop-on-error halts execution after a failing command"""
        out = StringIO()
        err = StringIO()

        def failing_populate_apps(*args, **kwargs):
            raise Exception('Simulated failure')

        with patch('app_manager.management.commands.populate_all.call_command', side_effect=failing_populate_apps):
            call_command('populate_all', stop_on_error=True, stdout=out, stderr=err)

        error_output = err.getvalue()
        output = out.getvalue()
        self.assertIn('populate_apps', error_output + output)
        self.assertIn('Stopped due to --stop-on-error flag.', output)

    def test_continue_on_error_by_default(self):
        """Test that failures are logged but execution continues by default"""
        out = StringIO()
        err = StringIO()

        call_count = []

        original_call_command = __import__('django.core.management', fromlist=['call_command']).call_command

        def patched_call_command(cmd, *args, **kwargs):
            call_count.append(cmd)
            if cmd == 'populate_manipulator_data':
                raise Exception('Simulated failure')
            return original_call_command(cmd, *args, **kwargs)

        with patch('app_manager.management.commands.populate_all.call_command', side_effect=patched_call_command):
            call_command('populate_all', stdout=out, stderr=err)

        # All three commands should have been attempted
        self.assertIn('populate_apps', call_count)
        self.assertIn('populate_manipulator_data', call_count)
        self.assertIn('populate_malware_data', call_count)

        output = out.getvalue()
        self.assertIn('Summary:', output)
