"""
Tests for scanner/scope_validator.py and the scan start scope integration.
"""

import unittest
from unittest.mock import MagicMock, patch
from scanner.scope_validator import ScopeValidator, _domain_matches, _is_domain_in_list


# ---------------------------------------------------------------------------
# Unit tests for domain matching helpers
# ---------------------------------------------------------------------------

class TestDomainMatches(unittest.TestCase):
    """Tests for the _domain_matches helper."""

    def test_exact_match(self):
        self.assertTrue(_domain_matches('example.com', 'example.com'))

    def test_exact_no_match(self):
        self.assertFalse(_domain_matches('other.com', 'example.com'))

    def test_wildcard_subdomain_match(self):
        self.assertTrue(_domain_matches('sub.example.com', '*.example.com'))

    def test_wildcard_deeper_subdomain_no_match(self):
        # Wildcards only match a single subdomain level
        self.assertFalse(_domain_matches('a.b.example.com', '*.example.com'))

    def test_wildcard_root_no_match(self):
        self.assertFalse(_domain_matches('example.com', '*.example.com'))

    def test_pattern_as_full_url(self):
        # The hostname is extracted from a full URL pattern
        self.assertTrue(_domain_matches('example.com', 'https://example.com/path'))

    def test_case_insensitive(self):
        self.assertTrue(_domain_matches('EXAMPLE.COM', 'example.com'))


class TestIsDomainInList(unittest.TestCase):
    """Tests for the _is_domain_in_list helper."""

    def test_empty_list(self):
        self.assertFalse(_is_domain_in_list('https://example.com', []))

    def test_matching_entry(self):
        self.assertTrue(_is_domain_in_list('https://sub.example.com', ['*.example.com']))

    def test_non_matching_entry(self):
        self.assertFalse(_is_domain_in_list('https://other.com', ['*.example.com']))

    def test_multiple_entries_one_matches(self):
        self.assertTrue(
            _is_domain_in_list('https://api.example.com', ['other.com', '*.example.com'])
        )


# ---------------------------------------------------------------------------
# Unit tests for ScopeValidator
# ---------------------------------------------------------------------------

def _make_scope(**kwargs):
    """Create a mock ProgramScope with sensible defaults."""
    scope = MagicMock()
    scope.in_scope_domains = kwargs.get('in_scope_domains', [])
    scope.out_of_scope_domains = kwargs.get('out_of_scope_domains', [])
    scope.allowed_vulnerability_types = kwargs.get('allowed_vulnerability_types', [])
    scope.disallowed_vulnerability_types = kwargs.get('disallowed_vulnerability_types', [])
    scope.max_requests_per_second = kwargs.get('max_requests_per_second', None)
    scope.testing_window_start = kwargs.get('testing_window_start', None)
    scope.testing_window_end = kwargs.get('testing_window_end', None)
    return scope


class TestScopeValidatorNoScope(unittest.TestCase):
    """Validation passes (with warning) when no scope is provided."""

    def test_no_scope_is_valid(self):
        validator = ScopeValidator('https://example.com', None)
        result = validator.validate()
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['violations'], [])
        self.assertTrue(len(result['warnings']) > 0)
        self.assertIn('No program scope defined', result['warnings'][0])


class TestScopeValidatorInScope(unittest.TestCase):
    """Tests for in-scope domain validation."""

    def test_target_in_scope_passes(self):
        scope = _make_scope(in_scope_domains=['*.example.com'])
        result = ScopeValidator('https://sub.example.com/path', scope).validate()
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['violations'], [])

    def test_target_not_in_scope_fails(self):
        scope = _make_scope(in_scope_domains=['*.example.com'])
        result = ScopeValidator('https://other.com', scope).validate()
        self.assertFalse(result['is_valid'])
        self.assertTrue(len(result['violations']) > 0)

    def test_empty_in_scope_list_allows_all(self):
        scope = _make_scope(in_scope_domains=[])
        result = ScopeValidator('https://anything.com', scope).validate()
        self.assertTrue(result['is_valid'])


class TestScopeValidatorOutOfScope(unittest.TestCase):
    """Tests for out-of-scope domain rejection."""

    def test_target_in_out_of_scope_fails(self):
        scope = _make_scope(out_of_scope_domains=['admin.example.com'])
        result = ScopeValidator('https://admin.example.com', scope).validate()
        self.assertFalse(result['is_valid'])
        self.assertTrue(any('out-of-scope' in v for v in result['violations']))

    def test_wildcard_out_of_scope(self):
        scope = _make_scope(out_of_scope_domains=['*.internal.example.com'])
        result = ScopeValidator('https://db.internal.example.com', scope).validate()
        self.assertFalse(result['is_valid'])

    def test_non_matching_out_of_scope_passes(self):
        scope = _make_scope(out_of_scope_domains=['admin.example.com'])
        result = ScopeValidator('https://app.example.com', scope).validate()
        self.assertTrue(result['is_valid'])


class TestScopeValidatorVulnTypes(unittest.TestCase):
    """Tests for vulnerability type filtering."""

    def test_allowed_vuln_type_passes(self):
        scope = _make_scope(allowed_vulnerability_types=['xss', 'sqli'])
        result = ScopeValidator('https://example.com', scope).validate(
            requested_vuln_types=['xss']
        )
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['violations'], [])

    def test_disallowed_vuln_type_fails(self):
        scope = _make_scope(disallowed_vulnerability_types=['dos'])
        result = ScopeValidator('https://example.com', scope).validate(
            requested_vuln_types=['dos']
        )
        self.assertFalse(result['is_valid'])

    def test_type_not_in_allowed_list_fails(self):
        scope = _make_scope(allowed_vulnerability_types=['xss'])
        result = ScopeValidator('https://example.com', scope).validate(
            requested_vuln_types=['sqli']
        )
        self.assertFalse(result['is_valid'])

    def test_empty_allowed_list_allows_all_types(self):
        scope = _make_scope(allowed_vulnerability_types=[])
        result = ScopeValidator('https://example.com', scope).validate(
            requested_vuln_types=['sqli', 'xss']
        )
        self.assertTrue(result['is_valid'])

    def test_no_requested_vuln_types_skips_check(self):
        scope = _make_scope(allowed_vulnerability_types=['xss'])
        result = ScopeValidator('https://example.com', scope).validate(
            requested_vuln_types=None
        )
        self.assertTrue(result['is_valid'])


class TestScopeValidatorWarnings(unittest.TestCase):
    """Tests for advisory warnings."""

    def test_rate_limit_warning(self):
        scope = _make_scope(max_requests_per_second=2.0)
        result = ScopeValidator('https://example.com', scope).validate()
        self.assertTrue(any('Rate limit' in w for w in result['warnings']))

    def test_testing_window_warning(self):
        scope = _make_scope(testing_window_start='09:00', testing_window_end='17:00')
        result = ScopeValidator('https://example.com', scope).validate()
        self.assertTrue(any('Testing window' in w for w in result['warnings']))

    def test_no_warnings_when_no_limits(self):
        scope = _make_scope()
        result = ScopeValidator('https://example.com', scope).validate()
        self.assertEqual(result['warnings'], [])


# ---------------------------------------------------------------------------
# Integration-style tests using Django's test client
# ---------------------------------------------------------------------------

class TestStartScanScopeIntegration(unittest.TestCase):
    """Integration tests for scope validation in the start_scan view."""

    def test_start_scan_no_scope_adds_warning(self):
        """When no scope_id is passed the scan is created with a no-scope warning."""
        from unittest.mock import patch, MagicMock

        mock_scan = MagicMock()
        mock_scan.id = 42
        mock_scan.warnings = []

        mock_task = MagicMock()
        mock_task.id = 'celery-task-id'

        mock_target = MagicMock()
        mock_target.url = 'https://example.com'

        with patch('scanner.views.ScanTarget.objects.get', return_value=mock_target), \
             patch('scanner.views.Scan.objects.create', return_value=mock_scan), \
             patch('scanner.views.async_scan_task') as mock_async_task:

            mock_async_task.delay.return_value = mock_task

            from rest_framework.test import APIRequestFactory
            from scanner.views import start_scan

            factory = APIRequestFactory()
            request = factory.post('/api/targets/1/scan/', {}, format='json')
            # Simulate authenticated user
            request.user = MagicMock(is_authenticated=True)

            response = start_scan(request, target_id=1)

            self.assertEqual(response.status_code, 201)
            # The no-scope warning should be present in the response
            data = response.data
            self.assertIn('warnings', data)
            self.assertTrue(any('No program scope defined' in w for w in data['warnings']))

    def test_start_scan_invalid_scope_returns_400(self):
        """When the target is out of scope, start_scan returns 400."""
        from unittest.mock import patch, MagicMock

        mock_scope = _make_scope(in_scope_domains=['*.allowed.com'])
        mock_target = MagicMock()
        mock_target.url = 'https://forbidden.com'

        with patch('scanner.views.ScanTarget.objects.get', return_value=mock_target), \
             patch('scanner.views.ProgramScope.objects.get', return_value=mock_scope):

            from rest_framework.test import APIRequestFactory
            from scanner.views import start_scan

            factory = APIRequestFactory()
            request = factory.post('/api/targets/1/scan/', {'scope_id': 99}, format='json')
            request.user = MagicMock(is_authenticated=True)

            response = start_scan(request, target_id=1)

            self.assertEqual(response.status_code, 400)
            self.assertIn('violations', response.data)


if __name__ == '__main__':
    unittest.main()
