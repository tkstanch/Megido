from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from .models import SQLInjectionTask, SQLInjectionResult
import json


class SQLInjectionTaskModelTest(TestCase):
    """Test SQLInjectionTask model"""
    
    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
            get_params={'id': '1'},
            enable_error_based=True,
            enable_time_based=True,
        )
    
    def test_task_creation(self):
        """Test that task is created properly"""
        self.assertEqual(self.task.target_url, 'https://example.com/test?id=1')
        self.assertEqual(self.task.http_method, 'GET')
        self.assertEqual(self.task.status, 'pending')
        self.assertEqual(self.task.vulnerabilities_found, 0)
    
    def test_task_str(self):
        """Test string representation"""
        self.assertIn('SQLi Task', str(self.task))
        self.assertIn('example.com', str(self.task))
    
    def test_get_params_dict(self):
        """Test parameter dictionary methods"""
        self.assertEqual(self.task.get_params_dict(), {'id': '1'})
        self.assertEqual(self.task.get_post_dict(), {})
        self.assertEqual(self.task.get_cookies_dict(), {})
        self.assertEqual(self.task.get_headers_dict(), {})


class SQLInjectionResultModelTest(TestCase):
    """Test SQLInjectionResult model"""
    
    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
        )
        self.result = SQLInjectionResult.objects.create(
            task=self.task,
            injection_type='error_based',
            vulnerable_parameter='id',
            parameter_type='GET',
            test_payload="1' OR '1'='1",
            detection_evidence='SQL error detected',
            database_type='mysql',
            is_exploitable=True,
            database_version='5.7.0',
        )
    
    def test_result_creation(self):
        """Test that result is created properly"""
        self.assertEqual(self.result.task, self.task)
        self.assertEqual(self.result.injection_type, 'error_based')
        self.assertEqual(self.result.vulnerable_parameter, 'id')
        self.assertEqual(self.result.database_type, 'mysql')
        self.assertTrue(self.result.is_exploitable)
    
    def test_result_str(self):
        """Test string representation"""
        self.assertIn('Error-based', str(self.result))
        self.assertIn('id', str(self.result))


class SQLInjectionViewsTest(TestCase):
    """Test views"""
    
    def setUp(self):
        self.client = Client()
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
        )
    
    def test_dashboard_view(self):
        """Test dashboard view loads"""
        response = self.client.get(reverse('sql_attacker:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'SQL Injection Attacker Dashboard')
    
    def test_dashboard_no_template_syntax_error(self):
        """Test dashboard renders without TemplateSyntaxError from empty url tags"""
        # This test specifically verifies that there are no empty {% url %} tags
        # that would cause: TemplateSyntaxError: 'url' takes at least one argument
        response = self.client.get(reverse('sql_attacker:dashboard'))
        self.assertEqual(response.status_code, 200)
        # If we get here without exception, the template rendered successfully
        self.assertContains(response, 'Dashboard')
    
    def test_task_list_view(self):
        """Test task list view loads"""
        response = self.client.get(reverse('sql_attacker:task_list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'SQL Injection Attack Tasks')
    
    def test_task_create_view_get(self):
        """Test task create view loads"""
        response = self.client.get(reverse('sql_attacker:task_create'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create SQL Injection Attack Task')
    
    def test_task_detail_view(self):
        """Test task detail view loads"""
        response = self.client.get(reverse('sql_attacker:task_detail', args=[self.task.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'SQL Injection Attack Task')
        self.assertContains(response, self.task.target_url)
    
    def test_api_tasks_list(self):
        """Test API tasks list endpoint"""
        response = self.client.get(reverse('sql_attacker:api_tasks'))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIsInstance(data, list)
    
    def test_api_task_detail(self):
        """Test API task detail endpoint"""
        response = self.client.get(reverse('sql_attacker:api_task_detail', args=[self.task.id]))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['id'], self.task.id)
        self.assertEqual(data['target_url'], self.task.target_url)


class SQLInjectionEngineTest(TestCase):
    """Test SQL injection engine components"""
    
    def test_engine_initialization(self):
        """Test engine can be initialized"""
        from .sqli_engine import SQLInjectionEngine
        
        config = {
            'use_random_delays': False,
            'randomize_user_agent': True,
            'use_payload_obfuscation': False,
            'verify_ssl': False,
        }
        
        engine = SQLInjectionEngine(config)
        self.assertIsNotNone(engine)
        self.assertEqual(engine.config['use_random_delays'], False)
    
    def test_engine_has_payloads(self):
        """Test engine has payload definitions"""
        from .sqli_engine import SQLInjectionEngine
        
        self.assertTrue(len(SQLInjectionEngine.ERROR_BASED_PAYLOADS) > 0)
        self.assertTrue(len(SQLInjectionEngine.TIME_BASED_PAYLOADS) > 0)
        self.assertTrue(len(SQLInjectionEngine.SQL_ERROR_PATTERNS) > 0)


class ParameterDiscoveryIntegrationTest(TestCase):
    """Integration tests for parameter discovery with SQL injection"""
    
    def test_task_with_auto_discovery_enabled(self):
        """Test creating task with auto discovery enabled"""
        task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
            auto_discover_params=True,
            enable_error_based=True,
        )
        
        self.assertTrue(task.auto_discover_params)
        self.assertIsNone(task.discovered_params)
    
    def test_result_with_parameter_source(self):
        """Test creating result with parameter source"""
        task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test',
            http_method='POST',
        )
        
        result = SQLInjectionResult.objects.create(
            task=task,
            injection_type='error_based',
            vulnerable_parameter='csrf_token',
            parameter_type='POST',
            parameter_source='hidden',
            test_payload="' OR '1'='1",
            detection_evidence='SQL error detected',
            database_type='mysql',
        )
        
        self.assertEqual(result.parameter_source, 'hidden')
        self.assertEqual(result.vulnerable_parameter, 'csrf_token')
    
    def test_discovered_params_stored_in_task(self):
        """Test that discovered parameters are stored in task"""
        task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test',
            auto_discover_params=True,
        )
        
        # Simulate discovered parameters
        discovered_params = [
            {
                'name': 'user_id',
                'value': '123',
                'source': 'form',
                'method': 'POST',
                'field_type': 'text',
            },
            {
                'name': 'token',
                'value': 'abc',
                'source': 'hidden',
                'method': 'POST',
                'field_type': 'hidden',
            }
        ]
        
        task.discovered_params = discovered_params
        task.save()
        
        # Reload from DB
        task_reloaded = SQLInjectionTask.objects.get(id=task.id)
        self.assertEqual(len(task_reloaded.discovered_params), 2)
        self.assertEqual(task_reloaded.discovered_params[0]['name'], 'user_id')
        self.assertEqual(task_reloaded.discovered_params[1]['source'], 'hidden')
