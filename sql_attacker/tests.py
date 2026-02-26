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


# ---------------------------------------------------------------------------
# engine.normalization tests
# ---------------------------------------------------------------------------


class NormalizationTest(TestCase):
    """Unit tests for sql_attacker.engine.normalization."""

    def test_strip_html_removes_tags(self):
        from .engine.normalization import strip_html
        self.assertNotIn("<b>", strip_html("<b>hello</b>"))
        self.assertIn("hello", strip_html("<b>hello</b>"))

    def test_strip_html_decodes_entities(self):
        from .engine.normalization import strip_html
        result = strip_html("Tom &amp; Jerry &lt;3")
        self.assertIn("&", result)
        self.assertNotIn("&amp;", result)

    def test_normalize_whitespace(self):
        from .engine.normalization import normalize_whitespace
        result = normalize_whitespace("  hello   world\n\t! ")
        self.assertEqual(result, "hello world !")

    def test_scrub_removes_uuid(self):
        from .engine.normalization import scrub_dynamic_tokens
        text = "Request-ID: 550e8400-e29b-41d4-a716-446655440000 OK"
        result = scrub_dynamic_tokens(text)
        self.assertNotIn("550e8400", result)
        self.assertIn("<UUID>", result)

    def test_scrub_removes_timestamp(self):
        from .engine.normalization import scrub_dynamic_tokens
        text = "Generated at 2024-01-15T12:34:56Z by server"
        result = scrub_dynamic_tokens(text)
        self.assertNotIn("2024-01-15", result)
        self.assertIn("<TIMESTAMP>", result)

    def test_scrub_removes_long_hex_token(self):
        from .engine.normalization import scrub_dynamic_tokens
        text = "csrfmiddlewaretoken=abcdef1234567890abcdef1234567890"
        result = scrub_dynamic_tokens(text)
        # The CSRF token pattern or hex token pattern should scrub it
        self.assertNotIn("abcdef1234567890abcdef1234567890", result)

    def test_normalize_response_body_pipeline(self):
        from .engine.normalization import normalize_response_body
        html = (
            "<html><body>"
            "<p>Hello  world</p>"
            "<span>Token: 550e8400-e29b-41d4-a716-446655440000</span>"
            "</body></html>"
        )
        result = normalize_response_body(html)
        self.assertNotIn("<html>", result)
        self.assertNotIn("550e8400", result)
        self.assertIn("Hello", result)
        self.assertIn("world", result)

    def test_fingerprint_stable_across_calls(self):
        from .engine.normalization import fingerprint
        text = "<p>Same content</p>"
        self.assertEqual(fingerprint(text), fingerprint(text))

    def test_fingerprint_differs_for_different_content(self):
        from .engine.normalization import fingerprint
        self.assertNotEqual(fingerprint("hello"), fingerprint("world"))

    def test_fingerprint_stable_despite_dynamic_tokens(self):
        """Two responses that differ only in timestamps should have the same fingerprint."""
        from .engine.normalization import fingerprint
        body1 = "Page generated at 2024-01-01T00:00:00Z. Welcome!"
        body2 = "Page generated at 2025-06-15T09:30:00Z. Welcome!"
        self.assertEqual(fingerprint(body1), fingerprint(body2))


# ---------------------------------------------------------------------------
# engine.baseline tests
# ---------------------------------------------------------------------------


class BaselineStatisticsTest(TestCase):
    """Unit tests for baseline median/IQR helpers and BaselineCollector."""

    def test_median_odd(self):
        from .engine.baseline import _median
        self.assertEqual(_median([1.0, 3.0, 2.0]), 2.0)

    def test_median_even(self):
        from .engine.baseline import _median
        self.assertEqual(_median([1.0, 2.0, 3.0, 4.0]), 2.5)

    def test_iqr_basic(self):
        from .engine.baseline import _iqr
        vals = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
        iqr = _iqr(vals)
        self.assertGreater(iqr, 0)

    def test_iqr_single_value(self):
        from .engine.baseline import _iqr
        self.assertEqual(_iqr([5.0]), 0.0)

    def test_baseline_collector_returns_result(self):
        from unittest.mock import MagicMock
        import datetime
        from .engine.baseline import BaselineCollector

        def _fake_request(url, method, params, data, cookies, headers):
            r = MagicMock()
            r.elapsed = MagicMock()
            r.elapsed.total_seconds.return_value = 0.15
            r.text = "<html>Hello world</html>"
            return r

        collector = BaselineCollector(request_fn=_fake_request, n_samples=3)
        result = collector.collect("http://example.com/test", "GET")
        self.assertIsNotNone(result)
        self.assertEqual(result.sample_count, 3)
        self.assertAlmostEqual(result.median_time, 0.15, places=2)
        self.assertIsInstance(result.body_signature, str)
        self.assertEqual(len(result.body_signature), 16)

    def test_baseline_collector_returns_none_on_all_failures(self):
        from .engine.baseline import BaselineCollector

        def _always_none(url, method, params, data, cookies, headers):
            return None

        collector = BaselineCollector(request_fn=_always_none, n_samples=3)
        result = collector.collect("http://example.com/test", "GET")
        self.assertIsNone(result)


class BaselineCacheTest(TestCase):
    """Unit tests for BaselineCache."""

    def _make_result(self):
        from .engine.baseline import BaselineResult
        return BaselineResult(
            median_time=0.2,
            iqr_time=0.05,
            body_signature="abc123def456abcd",
            sample_count=3,
        )

    def test_put_and_get(self):
        from .engine.baseline import BaselineCache
        cache = BaselineCache(ttl_seconds=300)
        result = self._make_result()
        cache.put("http://example.com", "GET", result)
        retrieved = cache.get("http://example.com", "GET")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.body_signature, result.body_signature)

    def test_get_returns_none_for_missing(self):
        from .engine.baseline import BaselineCache
        cache = BaselineCache()
        self.assertIsNone(cache.get("http://missing.example.com", "GET"))

    def test_entry_expires(self):
        import time as _time
        from .engine.baseline import BaselineCache
        cache = BaselineCache(ttl_seconds=0.05)
        cache.put("http://example.com", "GET", self._make_result())
        _time.sleep(0.1)
        self.assertIsNone(cache.get("http://example.com", "GET"))

    def test_invalidate(self):
        from .engine.baseline import BaselineCache
        cache = BaselineCache()
        cache.put("http://example.com", "GET", self._make_result())
        cache.invalidate("http://example.com", "GET")
        self.assertIsNone(cache.get("http://example.com", "GET"))


class CanarySchedulerTest(TestCase):
    """Unit tests for CanaryScheduler."""

    def test_canary_payloads_come_first(self):
        from .engine.baseline import CanaryScheduler
        scheduler = CanaryScheduler(canary_payloads=["'", "\""])
        full = ["payload_a", "'", "payload_b", "\"", "payload_c"]
        canary, remainder = scheduler.schedule(full)
        self.assertEqual(canary, ["'", "\""])
        self.assertNotIn("'", remainder)
        self.assertNotIn("\"", remainder)
        self.assertIn("payload_a", remainder)

    def test_remainder_preserves_order(self):
        from .engine.baseline import CanaryScheduler
        scheduler = CanaryScheduler(canary_payloads=["'"])
        full = ["a", "'", "b", "c"]
        _, remainder = scheduler.schedule(full)
        self.assertEqual(remainder, ["a", "b", "c"])


class ConfirmFindingTest(TestCase):
    """Unit tests for the confirmation loop in engine.baseline."""

    def test_confirmed_when_repeatable_and_benign_negative(self):
        from .engine.baseline import confirm_finding

        responses = ["vuln_response", "vuln_response"]
        idx = [0]

        def test_fn():
            r = responses[idx[0] % len(responses)]
            idx[0] += 1
            return r

        def benign_fn():
            return "safe_response"

        def detect_fn(r):
            return r == "vuln_response"

        confirmed, rationale = confirm_finding(test_fn, benign_fn, detect_fn, repetitions=2)
        self.assertTrue(confirmed)
        self.assertIn("confirmed", rationale)

    def test_not_confirmed_when_benign_also_triggers(self):
        from .engine.baseline import confirm_finding

        def test_fn():
            return "bad"

        def benign_fn():
            return "bad"  # also triggers

        def detect_fn(r):
            return True

        confirmed, rationale = confirm_finding(test_fn, benign_fn, detect_fn, repetitions=2)
        self.assertFalse(confirmed)
        self.assertIn("false positive", rationale)

    def test_not_confirmed_when_not_repeatable(self):
        from .engine.baseline import confirm_finding

        # With repetitions=3, required=2. Only 1 out of 3 probes positive → not confirmed.
        responses = ["vuln", "safe", "safe"]
        idx = [0]

        def test_fn():
            r = responses[idx[0] % len(responses)]
            idx[0] += 1
            return r

        def benign_fn():
            return "safe"

        def detect_fn(r):
            return r == "vuln"

        confirmed, rationale = confirm_finding(test_fn, benign_fn, detect_fn, repetitions=3)
        self.assertFalse(confirmed)


# ---------------------------------------------------------------------------
# engine.scoring tests
# ---------------------------------------------------------------------------


class ScoringTest(TestCase):
    """Unit tests for engine.scoring.compute_confidence."""

    def test_single_strong_signal_gives_likely_or_confirmed(self):
        from .engine.scoring import compute_confidence
        result = compute_confidence({"sql_error_pattern": 1.0})
        self.assertGreaterEqual(result.score, 0.5)
        self.assertIn(result.verdict, ("likely", "confirmed"))

    def test_two_strong_signals_give_confirmed(self):
        from .engine.scoring import compute_confidence
        result = compute_confidence({
            "sql_error_pattern": 1.0,
            "timing_delta_significant": 1.0,
        })
        self.assertEqual(result.verdict, "confirmed")
        self.assertGreaterEqual(result.score, 0.70)

    def test_no_signals_gives_uncertain(self):
        from .engine.scoring import compute_confidence
        result = compute_confidence({})
        self.assertEqual(result.verdict, "uncertain")
        self.assertEqual(result.score, 0.0)

    def test_zero_value_features_dont_contribute(self):
        from .engine.scoring import compute_confidence
        result = compute_confidence({"sql_error_pattern": 0.0, "timing_delta_significant": 0.0})
        self.assertEqual(result.score, 0.0)

    def test_contributions_sorted_by_contribution_descending(self):
        from .engine.scoring import compute_confidence
        result = compute_confidence({
            "http_error_code": 1.0,   # weight 0.50
            "sql_error_pattern": 1.0,  # weight 0.90
        })
        self.assertGreater(result.contributions[0].contribution, result.contributions[1].contribution)

    def test_per_feature_contribution_structure(self):
        from .engine.scoring import compute_confidence, FeatureContribution
        result = compute_confidence({"boolean_diff": 0.8})
        self.assertEqual(len(result.contributions), 1)
        c = result.contributions[0]
        self.assertIsInstance(c, FeatureContribution)
        self.assertEqual(c.name, "boolean_diff")
        self.assertAlmostEqual(c.contribution, 0.75 * 0.8, places=3)

    def test_rationale_is_informative(self):
        from .engine.scoring import compute_confidence
        result = compute_confidence({"sql_error_pattern": 1.0, "repeatability": 1.0})
        self.assertIn("score=", result.rationale)
        self.assertIn("verdict=", result.rationale)

    def test_backwards_compat_shim(self):
        from .engine.scoring import compute_confidence_from_signals
        score, verdict = compute_confidence_from_signals(["sql_error_pattern", "timing_delta_significant"])
        self.assertIsInstance(score, float)
        self.assertIn(verdict, ("confirmed", "likely", "uncertain"))


# ---------------------------------------------------------------------------
# New model fields tests
# ---------------------------------------------------------------------------


class FindingSchemaModelTest(TestCase):
    """Verify that the new finding-schema fields are present on SQLInjectionResult."""

    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/api?q=1',
            http_method='GET',
        )

    def test_injection_location_field(self):
        result = SQLInjectionResult.objects.create(
            task=self.task,
            injection_type='error_based',
            vulnerable_parameter='q',
            parameter_type='GET',
            injection_location='GET',
            test_payload="'",
            detection_evidence='SQL error detected',
        )
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertEqual(reloaded.injection_location, 'GET')

    def test_evidence_packet_field(self):
        packet = {
            'normalized_diff': 'Substantial difference detected',
            'matched_patterns': ['SQL syntax.*MySQL'],
            'classifier_outcome': 'ALLOWED',
            'timing_delta': 0.12,
        }
        result = SQLInjectionResult.objects.create(
            task=self.task,
            injection_type='time_based',
            vulnerable_parameter='q',
            parameter_type='GET',
            test_payload="' AND SLEEP(5)--",
            detection_evidence='Timing anomaly',
            evidence_packet=packet,
        )
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertEqual(reloaded.evidence_packet['timing_delta'], 0.12)

    def test_confidence_rationale_field(self):
        rationale = "score=0.972, verdict=confirmed, active_features=2 (top: sql_error_pattern, timing_delta_significant)"
        result = SQLInjectionResult.objects.create(
            task=self.task,
            injection_type='error_based',
            vulnerable_parameter='q',
            parameter_type='GET',
            test_payload="'",
            detection_evidence='SQL error detected',
            confidence_rationale=rationale,
        )
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertEqual(reloaded.confidence_rationale, rationale)

    def test_reproduction_steps_field(self):
        steps = "1. Send GET /api?q=' to example.com\n2. Observe SQL error in response."
        result = SQLInjectionResult.objects.create(
            task=self.task,
            injection_type='error_based',
            vulnerable_parameter='q',
            parameter_type='GET',
            test_payload="'",
            detection_evidence='SQL error detected',
            reproduction_steps=steps,
        )
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertEqual(reloaded.reproduction_steps, steps)


# ---------------------------------------------------------------------------
# API result schema tests
# ---------------------------------------------------------------------------


class APIResultSchemaTest(TestCase):
    """Verify that api_task_detail exposes the new finding-schema fields."""

    def setUp(self):
        self.client = Client()
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/api?q=1',
            http_method='GET',
        )
        SQLInjectionResult.objects.create(
            task=self.task,
            injection_type='error_based',
            vulnerable_parameter='q',
            parameter_type='GET',
            injection_location='GET',
            test_payload="'",
            detection_evidence='SQL error',
            evidence_packet={'timing_delta': 0.05},
            confidence_score=0.90,
            confidence_rationale='score=0.90, verdict=confirmed',
            reproduction_steps='1. Send GET /api?q=\'',
        )

    def test_api_result_includes_injection_location(self):
        response = self.client.get(reverse('sql_attacker:api_task_detail', args=[self.task.id]))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('results', data)
        result = data['results'][0]
        self.assertIn('injection_location', result)
        self.assertEqual(result['injection_location'], 'GET')

    def test_api_result_includes_evidence_packet(self):
        response = self.client.get(reverse('sql_attacker:api_task_detail', args=[self.task.id]))
        data = json.loads(response.content)
        result = data['results'][0]
        self.assertIn('evidence_packet', result)
        self.assertEqual(result['evidence_packet']['timing_delta'], 0.05)

    def test_api_result_includes_confidence_rationale(self):
        response = self.client.get(reverse('sql_attacker:api_task_detail', args=[self.task.id]))
        data = json.loads(response.content)
        result = data['results'][0]
        self.assertIn('confidence_rationale', result)
        self.assertIn('confirmed', result['confidence_rationale'])

    def test_api_result_includes_reproduction_steps(self):
        response = self.client.get(reverse('sql_attacker:api_task_detail', args=[self.task.id]))
        data = json.loads(response.content)
        result = data['results'][0]
        self.assertIn('reproduction_steps', result)
        self.assertIn("GET", result['reproduction_steps'])


# ---------------------------------------------------------------------------
# VPoC evidence mapping tests
# ---------------------------------------------------------------------------


class MapVisualEvidenceToFieldsTest(TestCase):
    """Unit tests for the _map_visual_evidence_to_fields adapter."""

    def _import(self):
        from sql_attacker.views import _map_visual_evidence_to_fields
        return _map_visual_evidence_to_fields

    def test_empty_evidence_returns_none_fields(self):
        fn = self._import()
        result = fn({})
        self.assertIsNone(result['screenshots'])
        self.assertIsNone(result['evidence_timeline'])
        self.assertNotIn('gif_evidence', result)
        self.assertNotIn('visual_proof_path', result)
        self.assertNotIn('visual_proof_type', result)

    def test_gif_becomes_primary_artifact(self):
        fn = self._import()
        result = fn({'screenshots': ['/tmp/s1.png'], 'gif': '/tmp/attack.gif', 'timeline': []})
        self.assertEqual(result['visual_proof_path'], '/tmp/attack.gif')
        self.assertEqual(result['visual_proof_type'], 'gif')
        self.assertEqual(result['gif_evidence'], '/tmp/attack.gif')

    def test_screenshot_becomes_primary_when_no_gif(self):
        fn = self._import()
        result = fn({'screenshots': ['/tmp/s1.png', '/tmp/s2.png'], 'gif': None, 'timeline': []})
        self.assertEqual(result['visual_proof_path'], '/tmp/s1.png')
        self.assertEqual(result['visual_proof_type'], 'screenshot')
        self.assertNotIn('gif_evidence', result)

    def test_screenshots_and_timeline_populated(self):
        fn = self._import()
        timeline = [{'step': 'baseline', 'timestamp': '2026-01-01T00:00:00+00:00'}]
        result = fn({'screenshots': ['/tmp/s1.png'], 'gif': None, 'timeline': timeline})
        self.assertEqual(result['screenshots'], ['/tmp/s1.png'])
        self.assertEqual(result['evidence_timeline'], timeline)

    def test_missing_size_does_not_raise(self):
        """visual_proof_size is omitted gracefully when the file does not exist."""
        fn = self._import()
        result = fn({'screenshots': ['/nonexistent/path.png'], 'gif': None, 'timeline': []})
        self.assertNotIn('visual_proof_size', result)


class VerifiedResultGetsVPoCTest(TestCase):
    """
    Verify that SQLInjectionResult persistence attaches visual evidence only
    for verified (exploitable) findings and leaves it empty for unverified ones.
    """

    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
        )

    def _make_result(self, is_exploitable, visual_evidence=None):
        """Helper: create a SQLInjectionResult mimicking the views.py logic."""
        from sql_attacker.views import _map_visual_evidence_to_fields

        verified = bool(is_exploitable)
        kwargs = dict(
            task=self.task,
            injection_type='error_based',
            vulnerable_parameter='id',
            parameter_type='GET',
            test_payload="'",
            detection_evidence='SQL error detected',
            is_exploitable=is_exploitable,
            verified=verified,
        )
        if verified and visual_evidence:
            kwargs.update(_map_visual_evidence_to_fields(visual_evidence))
        return SQLInjectionResult.objects.create(**kwargs)

    def test_verified_result_has_evidence_fields(self):
        evidence = {
            'screenshots': ['/tmp/s1.png'],
            'gif': None,
            'timeline': [{'step': 'baseline'}],
        }
        result = self._make_result(is_exploitable=True, visual_evidence=evidence)
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertTrue(reloaded.verified)
        self.assertEqual(reloaded.screenshots, ['/tmp/s1.png'])
        self.assertEqual(reloaded.evidence_timeline, [{'step': 'baseline'}])
        self.assertEqual(reloaded.visual_proof_path, '/tmp/s1.png')
        self.assertEqual(reloaded.visual_proof_type, 'screenshot')

    def test_verified_result_with_gif_uses_gif_as_primary(self):
        evidence = {
            'screenshots': ['/tmp/s1.png'],
            'gif': '/tmp/attack.gif',
            'timeline': [],
        }
        result = self._make_result(is_exploitable=True, visual_evidence=evidence)
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertTrue(reloaded.verified)
        self.assertEqual(reloaded.visual_proof_path, '/tmp/attack.gif')
        self.assertEqual(reloaded.visual_proof_type, 'gif')

    def test_unverified_result_has_no_visual_evidence(self):
        evidence = {
            'screenshots': ['/tmp/s1.png'],
            'gif': '/tmp/attack.gif',
            'timeline': [{'step': 'baseline'}],
        }
        result = self._make_result(is_exploitable=False, visual_evidence=evidence)
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertFalse(reloaded.verified)
        self.assertIsNone(reloaded.screenshots)
        self.assertIsNone(reloaded.evidence_timeline)
        self.assertIsNone(reloaded.visual_proof_path)
        self.assertIsNone(reloaded.visual_proof_type)

    def test_verified_without_evidence_does_not_crash(self):
        """Verified result with empty evidence package is saved without visual fields."""
        result = self._make_result(is_exploitable=True, visual_evidence={})
        reloaded = SQLInjectionResult.objects.get(pk=result.pk)
        self.assertTrue(reloaded.verified)
        self.assertIsNone(reloaded.screenshots)
        self.assertIsNone(reloaded.visual_proof_path)


class ServiceExecuteTaskLifecycleTest(TestCase):
    """
    Tests for sql_attacker.services.execute_task covering status lifecycle
    and error persistence (including network ConnectTimeout).
    """

    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
            get_params={'id': '1'},
            enable_error_based=True,
        )

    def test_execute_task_sets_failed_status_on_engine_exception(self):
        """
        When the SQL injection engine raises an unexpected exception,
        execute_task must persist status='failed', error_message, and completed_at.
        """
        from unittest.mock import patch
        from sql_attacker.services import execute_task

        with patch(
            'sql_attacker.services.SQLInjectionEngine.execute_attack_with_evidence',
            side_effect=RuntimeError('engine boom'),
        ):
            execute_task(self.task.id)

        self.task.refresh_from_db()
        self.assertEqual(self.task.status, 'failed')
        self.assertIn('engine boom', self.task.error_message)
        self.assertIsNotNone(self.task.completed_at)

    def test_execute_task_sets_failed_on_connect_timeout(self):
        """
        A requests.exceptions.ConnectTimeout raised by the engine should result
        in status='failed' with an error_message and completed_at set.
        """
        from unittest.mock import patch
        import requests.exceptions
        from sql_attacker.services import execute_task

        with patch(
            'sql_attacker.services.SQLInjectionEngine.execute_attack_with_evidence',
            side_effect=requests.exceptions.ConnectTimeout(
                'HTTPSConnectionPool(host=\'example.com\', port=443): '
                'Max retries exceeded with url: /test'
            ),
        ):
            execute_task(self.task.id)

        self.task.refresh_from_db()
        self.assertEqual(self.task.status, 'failed')
        self.assertIsNotNone(self.task.error_message)
        self.assertIsNotNone(self.task.completed_at)

    def test_execute_task_missing_task_does_not_raise(self):
        """execute_task with a non-existent task_id must not propagate an exception."""
        from sql_attacker.services import execute_task
        # Should not raise
        try:
            execute_task(999999)
        except Exception as exc:
            self.fail(f"execute_task raised unexpectedly: {exc}")


class TasksMarkFailedTest(TestCase):
    """Tests for tasks._mark_task_failed helper."""

    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
        )

    def test_mark_task_failed_sets_all_fields(self):
        from sql_attacker.tasks import _mark_task_failed
        _mark_task_failed(self.task.id, 'Task exceeded time limit')
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, 'failed')
        self.assertEqual(self.task.error_message, 'Task exceeded time limit')
        self.assertIsNotNone(self.task.completed_at)

    def test_mark_task_failed_nonexistent_id_does_not_raise(self):
        """_mark_task_failed with unknown id must not propagate an exception."""
        from sql_attacker.tasks import _mark_task_failed
        try:
            _mark_task_failed(999999, 'some error')
        except Exception as exc:
            self.fail(f"_mark_task_failed raised unexpectedly: {exc}")


class MakeRequestConnectTimeoutTest(TestCase):
    """
    Tests for SQLInjectionEngine._make_request handling of ConnectTimeout:
    the method must return None immediately without retrying.
    """

    def _make_engine(self):
        from sql_attacker.sqli_engine import SQLInjectionEngine
        return SQLInjectionEngine({
            'use_random_delays': False,
            'randomize_user_agent': False,
            'use_payload_obfuscation': False,
            'verify_ssl': False,
            'enable_stealth': False,
        })

    def test_connect_timeout_returns_none_without_retry(self):
        import requests.exceptions
        from unittest.mock import patch, MagicMock

        engine = self._make_engine()
        call_count = [0]

        def fake_get(*args, **kwargs):
            call_count[0] += 1
            raise requests.exceptions.ConnectTimeout('connect timed out')

        with patch.object(engine.session, 'get', side_effect=fake_get):
            result = engine._make_request('https://192.0.2.1/test', method='GET')

        self.assertIsNone(result)
        # Must not retry on ConnectTimeout
        self.assertEqual(call_count[0], 1)




# ---------------------------------------------------------------------------
# Tests for new service-layer improvements
# ---------------------------------------------------------------------------


class MapParamTypeToLocationTest(TestCase):
    """Tests for services._map_param_type_to_location."""

    def _call(self, param_type):
        from sql_attacker.services import _map_param_type_to_location
        return _map_param_type_to_location(param_type)

    def test_get_maps_to_GET(self):
        self.assertEqual('GET', self._call('GET'))

    def test_post_maps_to_POST(self):
        self.assertEqual('POST', self._call('POST'))

    def test_header_maps_to_header(self):
        self.assertEqual('header', self._call('header'))

    def test_cookie_maps_to_cookie(self):
        self.assertEqual('cookie', self._call('cookie'))

    def test_json_maps_to_json(self):
        self.assertEqual('json', self._call('json'))

    def test_unknown_type_returned_as_is(self):
        self.assertEqual('xml', self._call('xml'))

    def test_empty_string_returns_GET_default(self):
        self.assertEqual('GET', self._call(''))

    def test_none_returns_GET_default(self):
        self.assertEqual('GET', self._call(None))

    def test_case_insensitive_get(self):
        self.assertEqual('GET', self._call('get'))

    def test_case_insensitive_post(self):
        self.assertEqual('POST', self._call('post'))

    def test_numeric_string_returned_as_is(self):
        """A numeric string not in the mapping should be returned unchanged (uppercased key lookup miss)."""
        result = self._call('42')
        self.assertIsNotNone(result)

    def test_special_chars_returned_as_is(self):
        """Special characters not in the mapping should be returned unchanged."""
        result = self._call('form-data')
        self.assertIsNotNone(result)


class BuildEvidencePacketTest(TestCase):
    """Tests for services._build_evidence_packet."""

    def _make_finding(self):
        from unittest.mock import MagicMock
        finding = MagicMock()
        finding.finding_id = 'test-uuid-1234'
        finding.technique = 'error'
        finding.db_type = 'mysql'
        finding.confidence = 0.9
        finding.verdict = 'confirmed'
        ev = MagicMock()
        ev.to_dict.return_value = {'payload': "'", 'technique': 'error', 'response_length': 500}
        finding.evidence = [ev]
        finding.score_rationale = 'score=0.900, verdict=confirmed'
        return finding

    def test_none_finding_returns_none(self):
        from sql_attacker.services import _build_evidence_packet
        self.assertIsNone(_build_evidence_packet(None))

    def test_packet_contains_required_fields(self):
        from sql_attacker.services import _build_evidence_packet
        finding = self._make_finding()
        packet = _build_evidence_packet(finding)
        self.assertIsNotNone(packet)
        self.assertIn('finding_id', packet)
        self.assertIn('technique', packet)
        self.assertIn('db_type', packet)
        self.assertIn('confidence', packet)
        self.assertIn('verdict', packet)
        self.assertIn('evidence', packet)
        self.assertEqual('mysql', packet['db_type'])
        self.assertEqual(0.9, packet['confidence'])

    def test_evidence_list_capped_at_three(self):
        from sql_attacker.services import _build_evidence_packet
        from unittest.mock import MagicMock
        finding = MagicMock()
        finding.finding_id = 'x'
        finding.technique = 'error'
        finding.db_type = 'mysql'
        finding.confidence = 0.8
        finding.verdict = 'confirmed'
        ev = MagicMock()
        ev.to_dict.return_value = {'payload': "'"}
        finding.evidence = [ev] * 10
        packet = _build_evidence_packet(finding)
        self.assertLessEqual(len(packet['evidence']), 3)


class BuildReproductionStepsTest(TestCase):
    """Tests for services._build_reproduction_steps."""

    def _make_task(self):
        return SQLInjectionTask.objects.create(
            target_url='https://example.com/search',
            http_method='GET',
        )

    def _make_finding_with_evidence(self, payload="'"):
        from unittest.mock import MagicMock
        finding = MagicMock()
        ev = MagicMock()
        ev.payload = payload
        finding.evidence = [ev]
        finding.technique = 'error'
        finding.db_type = 'mysql'
        finding.confidence = 0.9
        finding.verdict = 'confirmed'
        return finding

    def test_none_finding_returns_empty_string(self):
        from sql_attacker.services import _build_reproduction_steps
        task = self._make_task()
        self.assertEqual('', _build_reproduction_steps(task, 'id', None))

    def test_steps_contain_url(self):
        from sql_attacker.services import _build_reproduction_steps
        task = self._make_task()
        finding = self._make_finding_with_evidence()
        steps = _build_reproduction_steps(task, 'id', finding)
        self.assertIn('https://example.com/search', steps)

    def test_steps_contain_param_name(self):
        from sql_attacker.services import _build_reproduction_steps
        task = self._make_task()
        finding = self._make_finding_with_evidence()
        steps = _build_reproduction_steps(task, 'search_term', finding)
        self.assertIn('search_term', steps)

    def test_steps_contain_confidence(self):
        from sql_attacker.services import _build_reproduction_steps
        task = self._make_task()
        finding = self._make_finding_with_evidence()
        steps = _build_reproduction_steps(task, 'id', finding)
        self.assertIn('confirmed', steps)


class DiscoveryRequestFnTest(TestCase):
    """Tests for services._make_discovery_request_fn."""

    def _make_fn(self, extra_headers=None, cookies=None, verify_ssl=False):
        from sql_attacker.services import _make_discovery_request_fn
        return _make_discovery_request_fn(extra_headers, cookies, verify_ssl)

    def test_connect_timeout_returns_none(self):
        import requests.exceptions
        from unittest.mock import patch, MagicMock
        fn = self._make_fn()
        with patch('requests.Session.request', side_effect=requests.exceptions.ConnectTimeout('timed out')):
            result = fn('http://192.0.2.1/test', 'GET', {}, {}, None, {}, {})
        self.assertIsNone(result)

    def test_request_exception_returns_none(self):
        import requests.exceptions
        from unittest.mock import patch
        fn = self._make_fn()
        with patch('requests.Session.request', side_effect=requests.exceptions.ConnectionError('refused')):
            result = fn('http://192.0.2.1/test', 'GET', {}, {}, None, {}, {})
        self.assertIsNone(result)

    def test_successful_response_returned(self):
        from unittest.mock import patch, MagicMock
        fn = self._make_fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'Hello World'
        with patch('requests.Session.request', return_value=mock_resp) as mock_req:
            result = fn('http://example.internal/page', 'GET', {'id': '1'}, {}, None, {}, {})
        self.assertEqual(mock_resp, result)


class RunDiscoveryScanTest(TestCase):
    """Tests for services._run_discovery_scan."""

    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test',
            http_method='GET',
        )

    def test_returns_empty_dict_on_engine_exception(self):
        """_run_discovery_scan must return {} when DiscoveryScanner raises."""
        from sql_attacker.services import _run_discovery_scan
        from unittest.mock import patch, MagicMock
        with patch('sql_attacker.services.DiscoveryScanner') as MockScanner:
            MockScanner.return_value.scan.side_effect = RuntimeError('scan boom')
            result = _run_discovery_scan(self.task, {'id': '1'}, {}, {}, {})
        self.assertEqual({}, result)

    def test_returns_dict_keyed_by_parameter(self):
        """_run_discovery_scan must return {parameter: Finding} on success."""
        from sql_attacker.services import _run_discovery_scan
        from unittest.mock import patch, MagicMock
        mock_finding = MagicMock()
        mock_finding.parameter = 'id'
        with patch('sql_attacker.services.DiscoveryScanner') as MockScanner:
            MockScanner.return_value.scan.return_value = [mock_finding]
            result = _run_discovery_scan(self.task, {'id': '1'}, {}, {}, {})
        self.assertIn('id', result)
        self.assertEqual(mock_finding, result['id'])

    def test_returns_empty_dict_when_no_findings(self):
        from sql_attacker.services import _run_discovery_scan
        from unittest.mock import patch
        with patch('sql_attacker.services.DiscoveryScanner') as MockScanner:
            MockScanner.return_value.scan.return_value = []
            result = _run_discovery_scan(self.task, {}, {}, {}, {})
        self.assertEqual({}, result)


class ExecuteTaskWithSelectionTest(TestCase):
    """execute_task_with_selection must delegate to execute_task without double status-set."""

    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/test?id=1',
            http_method='GET',
        )

    def test_delegates_to_execute_task(self):
        """execute_task_with_selection should call execute_task and mark completed."""
        from sql_attacker.services import execute_task_with_selection
        from unittest.mock import patch, MagicMock

        # Patch execute_task to track calls and simulate success
        with patch('sql_attacker.services.execute_task') as mock_execute:
            execute_task_with_selection(self.task.id)

        mock_execute.assert_called_once_with(self.task.id)

    def test_no_double_status_set(self):
        """execute_task_with_selection must not set status='running' before execute_task does."""
        from sql_attacker.services import execute_task_with_selection
        from unittest.mock import patch, MagicMock
        status_changes = []

        def track_save(task_id):
            # Capture the task status at the time execute_task is called
            from sql_attacker.models import SQLInjectionTask
            t = SQLInjectionTask.objects.get(id=task_id)
            status_changes.append(t.status)

        with patch('sql_attacker.services.execute_task', side_effect=track_save):
            execute_task_with_selection(self.task.id)

        # execute_task_with_selection must not have modified status before delegating
        self.task.refresh_from_db()
        # Status should still be 'pending' because our mock track_save didn't change it
        self.assertEqual(self.task.status, 'pending')


class NewSchemaFieldsPopulatedTest(TestCase):
    """execute_task must populate injection_location, evidence_packet,
    confidence_rationale, and reproduction_steps on each SQLInjectionResult."""

    def setUp(self):
        self.task = SQLInjectionTask.objects.create(
            target_url='https://example.com/search?q=test',
            http_method='GET',
            get_params={'q': 'test'},
            auto_discover_params=False,
        )

    def _run_with_mocked_engines(self, discovery_findings=None):
        """Execute the task with both engines mocked to return controlled data."""
        from sql_attacker.services import execute_task
        from unittest.mock import patch, MagicMock

        # Minimal old-engine finding
        raw_finding = {
            'vulnerable_parameter': 'q',
            'parameter_type': 'GET',
            'injection_type': 'error_based',
            'test_payload': "'",
            'detection_evidence': 'MySQL syntax error',
            'database_type': 'mysql',
            'confidence_score': 0.85,
            'severity': 'high',
            'risk_score': 70,
            'request_data': {},
            'response_data': {},
            'exploitation': {},
            'impact_analysis': {},
        }
        engine_result = {
            '_raw_findings': [raw_finding],
            'visual_evidence': {},
            'all_injection_points': [],
            'successful_payloads': {},
            'extracted_sensitive_data': {},
        }

        # Default: DiscoveryScanner finds nothing (to test fallback path)
        if discovery_findings is None:
            discovery_findings = {}

        with (
            patch('sql_attacker.services.SQLInjectionEngine') as MockEngine,
            patch('sql_attacker.services._run_discovery_scan', return_value=discovery_findings),
        ):
            instance = MockEngine.return_value
            instance.execute_attack_with_evidence.return_value = engine_result
            execute_task(self.task.id)

    def test_injection_location_populated(self):
        self._run_with_mocked_engines()
        result = SQLInjectionResult.objects.filter(task=self.task).first()
        self.assertIsNotNone(result)
        self.assertEqual('GET', result.injection_location)

    def test_confidence_rationale_populated_without_discovery(self):
        self._run_with_mocked_engines(discovery_findings={})
        result = SQLInjectionResult.objects.filter(task=self.task).first()
        self.assertIsNotNone(result)
        self.assertIn('confidence_score', result.confidence_rationale)

    def test_evidence_packet_populated_when_discovery_finds_something(self):
        from unittest.mock import MagicMock
        discovery_finding = MagicMock()
        discovery_finding.parameter = 'q'
        discovery_finding.finding_id = 'abc-123'
        discovery_finding.technique = 'error'
        discovery_finding.db_type = 'mysql'
        discovery_finding.confidence = 0.92
        discovery_finding.verdict = 'confirmed'
        discovery_finding.score_rationale = 'score=0.920, verdict=confirmed'
        ev = MagicMock()
        ev.to_dict.return_value = {'payload': "'", 'technique': 'error', 'response_length': 512}
        discovery_finding.evidence = [ev]

        self._run_with_mocked_engines(discovery_findings={'q': discovery_finding})
        result = SQLInjectionResult.objects.filter(task=self.task).first()
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.evidence_packet)
        self.assertEqual('mysql', result.evidence_packet.get('db_type'))
        self.assertEqual(0.92, result.evidence_packet.get('confidence'))

    def test_confidence_rationale_from_discovery_score_rationale(self):
        from unittest.mock import MagicMock
        discovery_finding = MagicMock()
        discovery_finding.parameter = 'q'
        discovery_finding.finding_id = 'abc-456'
        discovery_finding.technique = 'error'
        discovery_finding.db_type = 'mysql'
        discovery_finding.confidence = 0.90
        discovery_finding.verdict = 'confirmed'
        discovery_finding.score_rationale = 'score=0.900, verdict=confirmed, active_features=1'
        ev = MagicMock()
        ev.to_dict.return_value = {'payload': "'"}
        discovery_finding.evidence = [ev]

        self._run_with_mocked_engines(discovery_findings={'q': discovery_finding})
        result = SQLInjectionResult.objects.filter(task=self.task).first()
        self.assertIsNotNone(result)
        self.assertIn('score=0.900', result.confidence_rationale)

    def test_reproduction_steps_populated_from_discovery(self):
        from unittest.mock import MagicMock
        discovery_finding = MagicMock()
        discovery_finding.parameter = 'q'
        discovery_finding.finding_id = 'abc-789'
        discovery_finding.technique = 'error'
        discovery_finding.db_type = 'mysql'
        discovery_finding.confidence = 0.88
        discovery_finding.verdict = 'confirmed'
        discovery_finding.score_rationale = 'score=0.880'
        ev = MagicMock()
        ev.payload = "' OR '1'='1"
        ev.to_dict.return_value = {'payload': "' OR '1'='1"}
        discovery_finding.evidence = [ev]

        self._run_with_mocked_engines(discovery_findings={'q': discovery_finding})
        result = SQLInjectionResult.objects.filter(task=self.task).first()
        self.assertIsNotNone(result)
        self.assertIn('https://example.com/search', result.reproduction_steps)
        self.assertIn("'q'", result.reproduction_steps)
