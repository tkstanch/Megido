"""
Tests for PoC evidence improvements:

- ExploitPlugin._build_poc_step() helper
- SecurityMisconfigurationPlugin._probe_framework_endpoints() and updated verify()
- InfoDisclosurePlugin: curl_command and poc_steps in execute_attack() results
- CachePoisoningPlugin: cache-persistence verification in execute_attack() and verify()
- OtherPlugin: tightened verify() logic per vulnerability type
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.plugins.exploit_plugin import ExploitPlugin
from scanner.plugins.exploits.security_misconfiguration_plugin import SecurityMisconfigurationPlugin
from scanner.plugins.exploits.info_disclosure_plugin import InfoDisclosurePlugin
from scanner.plugins.exploits.cache_poisoning_plugin import CachePoisoningPlugin
from scanner.plugins.exploits.other_plugin import OtherPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_http_response(text='', status_code=200, headers=None, url='http://example.com'):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.request = MagicMock()
    resp.request.headers = {}
    return resp


# ---------------------------------------------------------------------------
# A. ExploitPlugin._build_poc_step()
# ---------------------------------------------------------------------------

class TestBuildPocStep:
    """Test the _build_poc_step() helper added to ExploitPlugin."""

    # Use a concrete subclass for testing
    plugin = SecurityMisconfigurationPlugin()

    def test_returns_required_keys(self):
        step = self.plugin._build_poc_step(
            step_number=1,
            title='Test step',
            description='A description',
        )
        assert step['step_number'] == 1
        assert step['title'] == 'Test step'
        assert step['description'] == 'A description'
        assert step['verified'] is False

    def test_request_field_set_when_url_provided(self):
        step = self.plugin._build_poc_step(
            step_number=1,
            title='T',
            description='D',
            request_url='https://example.com/path',
            request_method='POST',
        )
        assert 'request' in step
        assert 'POST' in step['request']
        assert 'https://example.com/path' in step['request']

    def test_no_request_field_without_url(self):
        step = self.plugin._build_poc_step(1, 'T', 'D')
        assert 'request' not in step

    def test_response_snippet_includes_status_and_body(self):
        step = self.plugin._build_poc_step(
            step_number=1, title='T', description='D',
            request_url='https://example.com',
            response_status=200,
            response_body_snippet='{"status":"UP"}',
        )
        assert 'response_snippet' in step
        assert 'HTTP 200' in step['response_snippet']
        assert '{"status":"UP"}' in step['response_snippet']

    def test_response_snippet_truncated_to_500_chars(self):
        long_body = 'x' * 600
        step = self.plugin._build_poc_step(
            step_number=1, title='T', description='D',
            request_url='https://example.com',
            response_status=200,
            response_body_snippet=long_body,
        )
        # The snippet should be at most 500 chars of the body + "HTTP 200\n" prefix
        assert len(step['response_snippet']) <= len('HTTP 200\n') + 500

    def test_curl_command_included(self):
        step = self.plugin._build_poc_step(
            step_number=1, title='T', description='D',
            curl_command='curl -sk "https://example.com"',
        )
        assert step['curl_command'] == 'curl -sk "https://example.com"'

    def test_verified_flag_propagated(self):
        step = self.plugin._build_poc_step(1, 'T', 'D', verified=True)
        assert step['verified'] is True

    def test_request_headers_included(self):
        step = self.plugin._build_poc_step(
            step_number=1, title='T', description='D',
            request_url='https://example.com',
            request_headers={'Authorization': 'Bearer token123'},
        )
        assert step['request_headers'] == {'Authorization': 'Bearer token123'}


# ---------------------------------------------------------------------------
# B. SecurityMisconfigurationPlugin._probe_framework_endpoints()
# ---------------------------------------------------------------------------

class TestProbeFrameworkEndpoints:
    plugin = SecurityMisconfigurationPlugin()

    def _make_responses(self, hit_path, body='{"status":"UP","components":{"diskSpace":{"status":"UP"}}}'):
        """Return a side-effect that returns 200 for hit_path and 404 for others."""
        hit_resp = _mock_http_response(text=body, status_code=200,
                                       headers={'Content-Type': 'application/json'})
        miss_resp = _mock_http_response(text='Not Found', status_code=404)

        def side_effect(url, **kwargs):
            if url.endswith(hit_path):
                return hit_resp
            return miss_resp

        return side_effect

    def test_returns_empty_when_no_accessible_endpoints(self):
        with patch('requests.get', return_value=_mock_http_response(text='x', status_code=404)):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})
        assert result['endpoints_found'] == []
        assert result['poc_steps'] == []
        assert result['repeater_requests'] == []
        assert result['highest_severity'] is None

    def test_accessible_actuator_health_recorded(self):
        with patch('requests.get', side_effect=self._make_responses('/actuator/health')):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})

        assert len(result['endpoints_found']) == 1
        ep = result['endpoints_found'][0]
        assert '/actuator/health' in ep['url']
        assert ep['status_code'] == 200
        assert ep['severity'] == 'high'
        assert 'curl_command' in ep

    def test_heapdump_classified_as_critical(self):
        body = 'JAVA_PROFILE_HEAP_DATA' + 'x' * 100
        with patch('requests.get',
                   side_effect=self._make_responses('/actuator/heapdump', body=body)):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})

        assert result['highest_severity'] == 'critical'
        assert result['endpoints_found'][0]['severity'] == 'critical'

    def test_env_endpoint_with_secrets_is_critical(self):
        env_body = (
            'spring.datasource.password=supersecretvalue123\n'
            'spring.datasource.url=jdbc:postgresql://prod.db.internal:5432/app\n'
            'server.port=8080\n'
            'spring.application.name=my-service\n'
            'management.endpoints.web.exposure.include=*\n'
        )
        with patch('requests.get',
                   side_effect=self._make_responses('/actuator/env', body=env_body)):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})

        ep = result['endpoints_found'][0]
        assert ep['severity'] == 'critical'
        assert ep['has_sensitive_data'] is True

    def test_poc_steps_built_for_each_endpoint(self):
        with patch('requests.get', side_effect=self._make_responses('/actuator/health')):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})

        assert len(result['poc_steps']) == 1
        step = result['poc_steps'][0]
        assert step['step_number'] == 1
        assert 'actuator/health' in step['request']
        assert step['verified'] is True
        assert 'curl_command' in step

    def test_repeater_requests_include_curl_command(self):
        with patch('requests.get', side_effect=self._make_responses('/actuator/health')):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})

        rr = result['repeater_requests'][0]
        assert 'curl_command' in rr
        assert 'curl' in rr['curl_command']

    def test_small_response_bodies_ignored(self):
        """Endpoints returning < 50 bytes should not be recorded."""
        tiny_resp = _mock_http_response(text='OK', status_code=200)
        with patch('requests.get', return_value=tiny_resp):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})
        assert result['endpoints_found'] == []

    def test_non_200_responses_ignored(self):
        resp_401 = _mock_http_response(text='Unauthorized' * 20, status_code=401)
        with patch('requests.get', return_value=resp_401):
            result = self.plugin._probe_framework_endpoints('https://example.com', {})
        assert result['endpoints_found'] == []


class TestSecurityMisconfigExecuteAttackWithFrameworkProbe:
    plugin = SecurityMisconfigurationPlugin()

    def _mock_headers_result(self, missing=None):
        return {
            'missing_headers': missing or [],
            'weak_headers': [],
            'weak_csp': None,
            'header_values': {},
        }

    def test_execute_attack_calls_probe_framework_endpoints(self):
        framework_result = {
            'endpoints_found': [{'url': 'https://example.com/actuator/health',
                                  'path': '/actuator/health', 'status_code': 200,
                                  'severity': 'high', 'label': 'Spring Boot health',
                                  'has_sensitive_data': False, 'body_snippet': '{"status":"UP"}',
                                  'content_type': 'application/json',
                                  'curl_command': 'curl -sk "https://example.com/actuator/health"'}],
            'repeater_requests': [{}],
            'poc_steps': [{'step_number': 1}],
            'highest_severity': 'high',
        }
        with patch.object(self.plugin, '_check_security_headers',
                          return_value=self._mock_headers_result()), \
             patch.object(self.plugin, '_probe_framework_endpoints',
                          return_value=framework_result) as mock_probe:
            result = self.plugin.execute_attack('https://example.com', {})

        mock_probe.assert_called_once()
        assert result['success'] is True
        assert result['poc_steps'] == [{'step_number': 1}]
        assert 'repeater_requests' in result

    def test_verify_includes_endpoints_in_proof(self):
        result = {
            'success': True,
            'evidence': {
                'headers': {'missing_headers': [], 'weak_headers': []},
                'framework_endpoints': {
                    'endpoints_found': [{
                        'url': 'https://example.com/actuator/env',
                        'path': '/actuator/env',
                        'status_code': 200,
                        'severity': 'critical',
                        'label': 'Spring Boot env',
                        'has_sensitive_data': True,
                        'body_snippet': '{"password":"secret"}',
                        'curl_command': 'curl -sk "https://example.com/actuator/env"',
                        'content_type': 'application/json',
                    }],
                    'highest_severity': 'critical',
                }
            },
            'misconfigurations': [],
            'attack_scenarios': [],
        }
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True
        assert 'actuator/env' in proof
        assert 'CRITICAL' in proof
        assert 'SENSITIVE DATA DETECTED' in proof
        assert 'curl' in proof

    def test_verify_bounty_eligible_when_endpoints_found(self):
        result = {
            'success': True,
            'evidence': {
                'headers': {'missing_headers': [], 'weak_headers': []},
                'framework_endpoints': {
                    'endpoints_found': [{
                        'url': 'https://example.com/actuator/health',
                        'path': '/actuator/health',
                        'status_code': 200,
                        'severity': 'high',
                        'label': 'health',
                        'has_sensitive_data': False,
                        'body_snippet': '{"status":"UP"}',
                        'curl_command': 'curl -sk "https://example.com/actuator/health"',
                        'content_type': 'application/json',
                    }],
                    'highest_severity': 'high',
                }
            },
            'misconfigurations': [],
            'attack_scenarios': [],
        }
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True
        assert 'bounty_eligible: True' in proof


# ---------------------------------------------------------------------------
# C. InfoDisclosurePlugin: curl_command and poc_steps
# ---------------------------------------------------------------------------

class TestInfoDisclosurePocSteps:
    plugin = InfoDisclosurePlugin()

    def test_execute_attack_result_includes_poc_steps(self):
        """When a sensitive file is found, result must contain poc_steps."""
        mock_response = _mock_http_response(
            text='DB_PASSWORD=prod_secret123\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n',
            status_code=200,
            headers={'Content-Type': 'text/plain'},
        )

        def fake_adaptive(url, **kwargs):
            if '/.env' in url:
                return mock_response
            return None

        with patch.object(self.plugin, '_adaptive_request', side_effect=fake_adaptive), \
             patch.object(self.plugin, '_detect_error_evidence', return_value=(False, '')), \
             patch('scanner.plugins.exploits.info_disclosure_plugin.get_advanced_info_disclosure_exploit') as mock_adv:
            mock_adv.return_value.__enter__ = MagicMock(return_value=MagicMock(
                attempt_info_disclosure_exploitation=MagicMock(return_value={'exploited': False})
            ))
            mock_adv.return_value.__exit__ = MagicMock(return_value=False)

            result = self.plugin.execute_attack(
                'https://example.com', {}, config={'enable_advanced_exploit': False}
            )

        assert result['success'] is True
        assert 'poc_steps' in result
        assert len(result['poc_steps']) > 0

        step = result['poc_steps'][0]
        assert 'step_number' in step
        assert 'curl_command' in step
        assert 'curl' in step['curl_command']

    def test_repeater_requests_include_curl_command(self):
        """repeater_requests entries must contain a curl_command field."""
        mock_response = _mock_http_response(
            text='api_key=supersecret12345\n',
            status_code=200,
            headers={'Content-Type': 'text/plain'},
        )

        def fake_adaptive(url, **kwargs):
            if '/.env' in url:
                return mock_response
            return None

        with patch.object(self.plugin, '_adaptive_request', side_effect=fake_adaptive), \
             patch.object(self.plugin, '_detect_error_evidence', return_value=(False, '')), \
             patch('scanner.plugins.exploits.info_disclosure_plugin.get_advanced_info_disclosure_exploit') as mock_adv:
            mock_adv.return_value.__enter__ = MagicMock(return_value=MagicMock(
                attempt_info_disclosure_exploitation=MagicMock(return_value={'exploited': False})
            ))
            mock_adv.return_value.__exit__ = MagicMock(return_value=False)

            result = self.plugin.execute_attack(
                'https://example.com', {}, config={'enable_advanced_exploit': False}
            )

        assert result['success'] is True
        assert 'repeater_requests' in result
        for rr in result['repeater_requests']:
            assert 'curl_command' in rr, f"repeater_request missing curl_command: {rr}"

    def test_poc_step_is_verified_only_for_sensitive_content(self):
        """PoC steps for Tier-1 (sensitive) files should have verified=True."""
        mock_response = _mock_http_response(
            text='password=mysecret123\n',
            status_code=200,
            headers={'Content-Type': 'text/plain'},
        )

        def fake_adaptive(url, **kwargs):
            if '/.env' in url:
                return mock_response
            return None

        with patch.object(self.plugin, '_adaptive_request', side_effect=fake_adaptive), \
             patch.object(self.plugin, '_detect_error_evidence', return_value=(False, '')), \
             patch('scanner.plugins.exploits.info_disclosure_plugin.get_advanced_info_disclosure_exploit') as mock_adv:
            mock_adv.return_value.__enter__ = MagicMock(return_value=MagicMock(
                attempt_info_disclosure_exploitation=MagicMock(return_value={'exploited': False})
            ))
            mock_adv.return_value.__exit__ = MagicMock(return_value=False)

            result = self.plugin.execute_attack(
                'https://example.com', {}, config={'enable_advanced_exploit': False}
            )

        steps = result.get('poc_steps', [])
        # At least one step should be verified (Tier 1 sensitive file)
        assert any(s.get('verified') for s in steps)


# ---------------------------------------------------------------------------
# D. CachePoisoningPlugin: cache-persistence verification
# ---------------------------------------------------------------------------

class TestCachePoisoningPersistence:
    plugin = CachePoisoningPlugin()
    attacker = 'attacker.example.com'

    def _make_poison_resp(self, contains_attacker=True):
        text = f'Hello {self.attacker} world' if contains_attacker else 'Hello world'
        return _mock_http_response(text=text, status_code=200)

    def test_cache_persistence_confirmed_when_clean_reflects(self):
        """When the clean request also contains the injected value, cache_persisted=True."""
        poison_resp = self._make_poison_resp(contains_attacker=True)
        clean_resp = self._make_poison_resp(contains_attacker=True)  # cached!

        call_count = [0]

        def side_effect(url, headers=None, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return poison_resp  # first = poisoning request
            return clean_resp  # second = clean request

        with patch('requests.get', side_effect=side_effect):
            result = self.plugin.execute_attack(
                'https://example.com', {},
                config={'attacker_host': self.attacker, 'timeout': 1}
            )

        assert result['success'] is True
        assert result['cache_persisted'] is True
        assert 'confirmed' in result['evidence'].lower()

    def test_cache_not_persisted_when_clean_is_clean(self):
        """When the clean request does NOT contain the injected value, cache_persisted=False."""
        poison_resp = self._make_poison_resp(contains_attacker=True)
        clean_resp = self._make_poison_resp(contains_attacker=False)  # not cached

        call_count = [0]

        def side_effect(url, headers=None, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return poison_resp
            return clean_resp

        with patch('requests.get', side_effect=side_effect):
            result = self.plugin.execute_attack(
                'https://example.com', {},
                config={'attacker_host': self.attacker, 'timeout': 1}
            )

        assert result['success'] is True
        assert result['cache_persisted'] is False
        assert result.get('confidence') == 'potential'

    def test_execute_attack_includes_poc_steps_for_both_requests(self):
        """execute_attack() must return poc_steps with both the poison and verification steps."""
        poison_resp = self._make_poison_resp(contains_attacker=True)
        clean_resp = self._make_poison_resp(contains_attacker=True)

        call_count = [0]

        def side_effect(url, headers=None, **kwargs):
            call_count[0] += 1
            return poison_resp if call_count[0] == 1 else clean_resp

        with patch('requests.get', side_effect=side_effect):
            result = self.plugin.execute_attack(
                'https://example.com', {},
                config={'attacker_host': self.attacker, 'timeout': 1}
            )

        assert 'poc_steps' in result
        assert len(result['poc_steps']) == 2
        assert result['poc_steps'][0]['step_number'] == 1
        assert result['poc_steps'][1]['step_number'] == 2

    def test_execute_attack_includes_repeater_requests(self):
        """execute_attack() must return two repeater_requests entries."""
        poison_resp = self._make_poison_resp(contains_attacker=True)
        clean_resp = self._make_poison_resp(contains_attacker=False)

        call_count = [0]

        def side_effect(url, headers=None, **kwargs):
            call_count[0] += 1
            return poison_resp if call_count[0] == 1 else clean_resp

        with patch('requests.get', side_effect=side_effect):
            result = self.plugin.execute_attack(
                'https://example.com', {},
                config={'attacker_host': self.attacker, 'timeout': 1}
            )

        assert 'repeater_requests' in result
        assert len(result['repeater_requests']) == 2

    def test_verify_returns_true_only_when_cache_persisted(self):
        result_persisted = {
            'success': True,
            'injected_header': 'X-Forwarded-Host',
            'injected_value': self.attacker,
            'cache_persisted': True,
            'confidence': 'confirmed',
            'evidence': 'Cache confirmed',
        }
        verified, proof = self.plugin.verify(result_persisted, 'https://example.com', {})
        assert verified is True
        assert '✓ VERIFIED' in proof

    def test_verify_returns_false_when_not_cached(self):
        result_potential = {
            'success': True,
            'injected_header': 'X-Forwarded-Host',
            'injected_value': self.attacker,
            'cache_persisted': False,
            'confidence': 'potential',
            'evidence': 'Reflection only',
        }
        verified, proof = self.plugin.verify(result_potential, 'https://example.com', {})
        assert verified is False
        assert 'POTENTIAL' in proof
        assert 'not verified' in proof.lower() or 'not confirmed' in proof.lower()

    def test_verify_returns_false_when_no_success(self):
        result = {'success': False}
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False
        assert proof is None


# ---------------------------------------------------------------------------
# E. OtherPlugin.verify() — tightened per-type logic
# ---------------------------------------------------------------------------

class TestOtherPluginVerify:
    plugin = OtherPlugin()

    def _make_result(self, vuln_type, evidence, response_text=None):
        vuln = {
            'type': vuln_type,
            'evidence': evidence,
            'payload': '/?debug=true',
            'description': 'test',
        }
        if response_text is not None:
            vuln['response_text'] = response_text
        return {
            'success': True,
            'evidence': evidence,
            'vulnerability_type': 'other',
            'vulnerabilities': [vuln],
        }

    # --- debug_mode ---

    def test_debug_mode_not_verified_with_short_evidence(self):
        """debug_mode with a generic 20-char string must NOT be verified."""
        result = self._make_result('debug_mode', 'debug mode is active!')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False

    def test_debug_mode_verified_with_traceback(self):
        """debug_mode with an actual traceback MUST be verified."""
        tb = "Traceback (most recent call last):\n  File '/app/views.py', line 42, in get"
        result = self._make_result('debug_mode', tb, response_text=tb)
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True
        assert 'debug_mode' in proof.lower() or 'DEBUG_MODE' in proof

    def test_debug_mode_verified_via_response_text_not_only_evidence(self):
        """debug_mode should check response_text even if evidence string is short."""
        tb = 'File "/app/views.py", line 10, in handler'
        result = self._make_result('debug_mode', 'Debug info exposed', response_text=tb)
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True

    # --- exposed_admin ---

    def test_exposed_admin_not_verified_for_login_form(self):
        """Admin path returning only a login form should NOT be verified."""
        login_html = (
            "<form><input type='password' name='pass'>"
            "<button>Sign in</button></form>"
        )
        result = self._make_result(
            'exposed_admin',
            'Admin panel accessible',
            response_text=login_html,
        )
        # Override requires_authentication flag - not set means we rely on response
        result['vulnerabilities'][0]['requires_authentication'] = True
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False

    def test_exposed_admin_verified_for_dashboard(self):
        """Admin panel with privileged content should be verified."""
        dashboard_html = (
            "<h1>Admin Dashboard</h1>"
            "<a href='/logout'>Logged in as admin</a>"
            "<a href='/admin/users'>Manage users</a>"
        )
        result = self._make_result(
            'exposed_admin',
            'Admin panel accessible without authentication at /admin',
            response_text=dashboard_html,
        )
        result['vulnerabilities'][0]['requires_authentication'] = False
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True
        assert 'EXPOSED_ADMIN' in proof

    # --- directory_listing ---

    def test_directory_listing_not_verified_without_indicator(self):
        result = self._make_result('directory_listing', 'Directory may be listed')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False

    def test_directory_listing_verified_with_index_of(self):
        text = "<h1>Index of /uploads</h1><ul><li>file.txt</li></ul>"
        result = self._make_result('directory_listing', text, response_text=text)
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True

    # --- verbose_errors ---

    def test_verbose_errors_not_verified_with_generic_text(self):
        result = self._make_result('verbose_errors', 'Error in application (verbose errors exposed)')
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False

    def test_verbose_errors_verified_with_php_error(self):
        php_err = "Fatal error: Uncaught Exception in /var/www/html/index.php on line 42"
        result = self._make_result('verbose_errors', php_err, response_text=php_err)
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True

    def test_verbose_errors_verified_with_sql_query(self):
        sql_err = "mysql_error: You have an error in your SQL syntax near SELECT * FROM users"
        result = self._make_result('verbose_errors', sql_err, response_text=sql_err)
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True

    # --- proof content ---

    def test_verified_proof_includes_url_and_curl_command(self):
        tb = "Traceback (most recent call last):\n  File '/app/views.py', line 1"
        result = self._make_result('debug_mode', tb, response_text=tb)
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is True
        assert 'https://example.com' in proof
        assert 'curl' in proof

    def test_no_success_returns_false(self):
        result = {'success': False}
        verified, proof = self.plugin.verify(result, 'https://example.com', {})
        assert verified is False
        assert proof is None
