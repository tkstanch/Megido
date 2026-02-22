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


class ResponseClassificationTest(TestCase):
    """Tests for http_utils response classification logic."""

    def _mock_response(self, status_code=200, headers=None, body="OK"):
        """Helper to build a minimal mock requests.Response."""
        import requests
        r = requests.models.Response()
        r.status_code = status_code
        r.headers = requests.structures.CaseInsensitiveDict(headers or {})
        r._content = body.encode("utf-8")
        return r

    def test_allowed_200(self):
        from .http_utils import classify_response, ALLOWED
        r = self._mock_response(200)
        cls = classify_response(r)
        self.assertEqual(cls.outcome, ALLOWED)

    def test_rate_limited_429(self):
        from .http_utils import classify_response, RATE_LIMITED
        r = self._mock_response(429, headers={"Retry-After": "10"})
        cls = classify_response(r)
        self.assertEqual(cls.outcome, RATE_LIMITED)
        self.assertEqual(cls.evidence["retry_after"], "10")

    def test_blocked_403(self):
        from .http_utils import classify_response, BLOCKED
        r = self._mock_response(403, body="403 Forbidden - Access Denied")
        cls = classify_response(r)
        self.assertEqual(cls.outcome, BLOCKED)

    def test_auth_required_401(self):
        from .http_utils import classify_response, AUTH_REQUIRED
        r = self._mock_response(401, headers={"WWW-Authenticate": "Basic realm='test'"})
        cls = classify_response(r)
        self.assertEqual(cls.outcome, AUTH_REQUIRED)

    def test_challenge_cloudflare_body(self):
        from .http_utils import classify_response, CHALLENGE
        body = "Checking your browser before accessing... Cloudflare Ray ID: abc123"
        r = self._mock_response(503, body=body)
        cls = classify_response(r)
        self.assertEqual(cls.outcome, CHALLENGE)

    def test_transient_503(self):
        from .http_utils import classify_response, TRANSIENT_ERROR
        r = self._mock_response(503, body="Service Unavailable")
        cls = classify_response(r)
        self.assertEqual(cls.outcome, TRANSIENT_ERROR)

    def test_transient_none_response(self):
        from .http_utils import classify_response, TRANSIENT_ERROR
        cls = classify_response(None)
        self.assertEqual(cls.outcome, TRANSIENT_ERROR)

    def test_vendor_cloudflare_header(self):
        from .http_utils import classify_response
        r = self._mock_response(200, headers={"Server": "cloudflare", "CF-RAY": "abc"})
        cls = classify_response(r)
        self.assertEqual(cls.vendor, "cloudflare")

    def test_vendor_akamai_header(self):
        from .http_utils import classify_response
        r = self._mock_response(200, headers={"Server": "AkamaiGHost"})
        cls = classify_response(r)
        self.assertEqual(cls.vendor, "akamai")

    def test_blocked_akamai_body(self):
        from .http_utils import classify_response, BLOCKED
        body = "Access Denied. Reference #18.abc1234.1234567890.def"
        r = self._mock_response(403, body=body)
        cls = classify_response(r)
        self.assertEqual(cls.outcome, BLOCKED)

    def test_rate_limited_body_200(self):
        """Soft rate-limit page served as 200 should be classified as RATE_LIMITED."""
        from .http_utils import classify_response, RATE_LIMITED
        body = "Too many requests. Please slow down and try again later."
        r = self._mock_response(200, body=body)
        cls = classify_response(r)
        self.assertEqual(cls.outcome, RATE_LIMITED)


class CircuitBreakerTest(TestCase):
    """Tests for the CircuitBreaker class."""

    def test_opens_after_threshold(self):
        from .http_utils import CircuitBreaker, BLOCKED
        cb = CircuitBreaker(threshold=3, reset_after=9999)
        for _ in range(3):
            cb.record("host1", BLOCKED)
        self.assertTrue(cb.is_open("host1"))

    def test_does_not_open_before_threshold(self):
        from .http_utils import CircuitBreaker, BLOCKED
        cb = CircuitBreaker(threshold=3, reset_after=9999)
        cb.record("host1", BLOCKED)
        cb.record("host1", BLOCKED)
        self.assertFalse(cb.is_open("host1"))

    def test_resets_on_allowed(self):
        from .http_utils import CircuitBreaker, BLOCKED, ALLOWED
        cb = CircuitBreaker(threshold=3, reset_after=9999)
        cb.record("host1", BLOCKED)
        cb.record("host1", BLOCKED)
        cb.record("host1", ALLOWED)  # reset
        cb.record("host1", BLOCKED)
        self.assertFalse(cb.is_open("host1"))
        self.assertEqual(cb.consecutive_count("host1"), 1)

    def test_resets_after_timeout(self):
        from .http_utils import CircuitBreaker, BLOCKED
        import time as _time
        cb = CircuitBreaker(threshold=2, reset_after=0.05)
        cb.record("host1", BLOCKED)
        cb.record("host1", BLOCKED)
        self.assertTrue(cb.is_open("host1"))
        _time.sleep(0.1)
        self.assertFalse(cb.is_open("host1"))

    def test_challenge_also_trips_breaker(self):
        from .http_utils import CircuitBreaker, CHALLENGE
        cb = CircuitBreaker(threshold=2, reset_after=9999)
        cb.record("host1", CHALLENGE)
        cb.record("host1", CHALLENGE)
        self.assertTrue(cb.is_open("host1"))


class BackoffTest(TestCase):
    """Tests for compute_backoff and get_retry_after."""

    def test_compute_backoff_grows(self):
        from .http_utils import compute_backoff
        d0 = compute_backoff(0, base=1.0)
        d1 = compute_backoff(1, base=1.0)
        d2 = compute_backoff(2, base=1.0)
        self.assertLess(d0, d1)
        self.assertLess(d1, d2)

    def test_compute_backoff_cap(self):
        from .http_utils import compute_backoff
        d = compute_backoff(100, base=1.0, cap=30.0)
        self.assertEqual(d, 30.0)

    def test_get_retry_after_parses_header(self):
        from .http_utils import get_retry_after
        import requests
        r = requests.models.Response()
        r.status_code = 429
        r.headers = requests.structures.CaseInsensitiveDict({"Retry-After": "42"})
        self.assertEqual(get_retry_after(r, default=5.0), 42.0)

    def test_get_retry_after_default_on_missing(self):
        from .http_utils import get_retry_after
        import requests
        r = requests.models.Response()
        r.status_code = 429
        r.headers = requests.structures.CaseInsensitiveDict()
        self.assertEqual(get_retry_after(r, default=7.0), 7.0)

    def test_get_retry_after_none_response(self):
        from .http_utils import get_retry_after
        self.assertEqual(get_retry_after(None, default=3.0), 3.0)


class EngineCircuitBreakerIntegrationTest(TestCase):
    """Integration tests: engine circuit breaker interacts with _make_request."""

    def _make_engine(self, extra_config=None):
        from .sqli_engine import SQLInjectionEngine
        config = {
            'use_random_delays': False,
            'randomize_user_agent': False,
            'use_payload_obfuscation': False,
            'verify_ssl': False,
            'enable_stealth': False,
            'enable_comprehensive_payloads': False,
            'enable_advanced_payloads': False,
            'enable_false_positive_reduction': False,
            'enable_impact_demonstration': False,
            'enable_adaptive_bypass': False,
            'enable_boolean_blind': False,
            'enable_payload_optimization': False,
            'enable_cognitive_planning': False,
            'enable_context_analysis': False,
            'enable_advanced_learning': False,
            'enable_comprehensive_testing': False,
            'enable_bypass_techniques': False,
            'circuit_breaker_threshold': 2,
            'circuit_breaker_reset_after': 9999,
        }
        if extra_config:
            config.update(extra_config)
        return SQLInjectionEngine(config)

    def test_make_request_returns_none_when_circuit_open(self):
        """When circuit is open, _make_request should return None without sending."""
        from unittest.mock import patch
        engine = self._make_engine()
        from .http_utils import BLOCKED
        engine._circuit_breaker.record("example.com", BLOCKED)
        engine._circuit_breaker.record("example.com", BLOCKED)
        self.assertTrue(engine._circuit_breaker.is_open("example.com"))

        with patch.object(engine.session, 'get') as mock_get:
            result = engine._make_request("http://example.com/test", "GET")
            mock_get.assert_not_called()
        self.assertIsNone(result)

    def test_rate_limited_triggers_backoff(self):
        """Rate-limited response should trigger time.sleep with backoff delay."""
        from unittest.mock import patch, MagicMock
        import requests
        engine = self._make_engine({'max_rate_limit_retries': 1, 'backoff_base': 0.01})

        # Build a 429 response
        blocked_resp = requests.models.Response()
        blocked_resp.status_code = 429
        blocked_resp.headers = requests.structures.CaseInsensitiveDict({"Retry-After": "0"})
        blocked_resp._content = b"Too many requests"

        # On the second call return a 200
        ok_resp = requests.models.Response()
        ok_resp.status_code = 200
        ok_resp.headers = requests.structures.CaseInsensitiveDict()
        ok_resp._content = b"OK"

        with patch.object(engine.session, 'get', side_effect=[blocked_resp, ok_resp]):
            with patch('sql_attacker.sqli_engine.time.sleep') as mock_sleep:
                result = engine._make_request("http://ratelimit.example.com/test", "GET")
                # sleep should have been called for backoff
                self.assertTrue(mock_sleep.called)

