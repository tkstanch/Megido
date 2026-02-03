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
