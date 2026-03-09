from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from .models import RepeaterRequest, RepeaterResponse, RepeaterTab
from .utils import (
    parse_raw_request,
    build_raw_request,
    compare_responses,
    url_encode,
    url_decode,
    base64_encode,
    base64_decode,
    unicode_escape,
    unicode_unescape,
    update_content_length,
    update_content_length_in_raw,
    hexdump,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class RepeaterTabModelTest(TestCase):
    def test_create_tab_defaults(self):
        tab = RepeaterTab.objects.create(name='My Tab')
        self.assertEqual(tab.name, 'My Tab')
        self.assertTrue(tab.follow_redirects)
        self.assertEqual(tab.max_redirects, 10)
        self.assertEqual(tab.timeout, 30.0)
        self.assertFalse(tab.verify_ssl)
        self.assertTrue(tab.auto_content_length)

    def test_tab_config_dict(self):
        tab = RepeaterTab.objects.create(name='T', timeout=15.0, verify_ssl=True)
        cfg = tab.to_config_dict()
        self.assertEqual(cfg['timeout'], 15.0)
        self.assertTrue(cfg['verify_ssl'])
        self.assertIn('follow_redirects', cfg)

    def test_tab_str(self):
        tab = RepeaterTab.objects.create(name='Debug', order=2)
        self.assertIn('Debug', str(tab))

    def test_request_linked_to_tab(self):
        tab = RepeaterTab.objects.create(name='Tab 1')
        req = RepeaterRequest.objects.create(
            url='http://example.com',
            method='GET',
            headers='{}',
            tab=tab,
            tab_history_index=0,
        )
        self.assertEqual(req.tab, tab)
        self.assertEqual(req.tab_history_index, 0)

    def test_request_tab_nullable(self):
        req = RepeaterRequest.objects.create(
            url='http://example.com',
            method='GET',
            headers='{}',
        )
        self.assertIsNone(req.tab)


# ---------------------------------------------------------------------------
# Utils: raw request parsing
# ---------------------------------------------------------------------------

class ParseRawRequestTest(TestCase):
    def test_basic_get(self):
        raw = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
        result = parse_raw_request(raw)
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['headers']['Host'], 'example.com')
        self.assertIn('example.com', result['url'])

    def test_post_with_body(self):
        raw = 'POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=foo&pass=bar'
        result = parse_raw_request(raw)
        self.assertEqual(result['method'], 'POST')
        self.assertEqual(result['body'], 'user=foo&pass=bar')

    def test_https_url_construction(self):
        raw = 'GET /path HTTP/1.1\r\nHost: secure.example.com:443\r\n\r\n'
        result = parse_raw_request(raw)
        self.assertTrue(result['url'].startswith('https://'))

    def test_missing_host(self):
        raw = 'DELETE /resource HTTP/1.1\r\n\r\n'
        result = parse_raw_request(raw)
        self.assertEqual(result['method'], 'DELETE')
        self.assertEqual(result['url'], '/resource')


class BuildRawRequestTest(TestCase):
    def test_basic_get(self):
        raw = build_raw_request('GET', 'http://example.com/path', {'Accept': 'text/html'})
        self.assertIn('GET /path HTTP/1.1', raw)
        self.assertIn('Host: example.com', raw)
        self.assertIn('Accept: text/html', raw)

    def test_post_with_query(self):
        raw = build_raw_request('POST', 'http://example.com/submit?x=1', {}, 'body data')
        self.assertIn('POST /submit?x=1 HTTP/1.1', raw)
        self.assertIn('body data', raw)


# ---------------------------------------------------------------------------
# Utils: compare_responses
# ---------------------------------------------------------------------------

class CompareResponsesTest(TestCase):
    def test_identical_responses(self):
        resp = {'status_code': 200, 'headers': '{"Content-Type": "text/html"}', 'body': 'Hello'}
        diff = compare_responses(resp, resp)
        self.assertFalse(diff['status_code']['changed'])
        self.assertEqual(diff['headers'], {})
        self.assertFalse(diff['body_changed'])

    def test_different_status(self):
        a = {'status_code': 200, 'headers': '{}', 'body': 'ok'}
        b = {'status_code': 404, 'headers': '{}', 'body': 'not found'}
        diff = compare_responses(a, b)
        self.assertTrue(diff['status_code']['changed'])
        self.assertEqual(diff['status_code']['a'], 200)
        self.assertEqual(diff['status_code']['b'], 404)

    def test_different_body(self):
        a = {'status_code': 200, 'headers': '{}', 'body': 'line1\nline2\n'}
        b = {'status_code': 200, 'headers': '{}', 'body': 'line1\nline3\n'}
        diff = compare_responses(a, b)
        self.assertTrue(diff['body_changed'])
        self.assertIn('line3', diff['body_diff'])

    def test_different_headers(self):
        a = {'status_code': 200, 'headers': '{"X-Custom": "alpha"}', 'body': ''}
        b = {'status_code': 200, 'headers': '{"X-Custom": "beta"}', 'body': ''}
        diff = compare_responses(a, b)
        self.assertIn('X-Custom', diff['headers'])


# ---------------------------------------------------------------------------
# Utils: encoding helpers
# ---------------------------------------------------------------------------

class EncodingHelpersTest(TestCase):
    def test_url_encode_decode(self):
        original = 'hello world & more=stuff'
        encoded = url_encode(original)
        self.assertNotIn(' ', encoded)
        self.assertEqual(url_decode(encoded), original)

    def test_base64_round_trip(self):
        original = 'secret payload'
        encoded = base64_encode(original)
        self.assertEqual(base64_decode(encoded), original)

    def test_base64_decode_invalid(self):
        with self.assertRaises(ValueError):
            base64_decode('!!!not_valid_base64!!!')

    def test_unicode_escape_unescape(self):
        original = 'caf\u00e9'
        escaped = unicode_escape(original)
        self.assertNotIn('\u00e9', escaped)
        self.assertEqual(unicode_unescape(escaped), original)


# ---------------------------------------------------------------------------
# Utils: content-length helpers
# ---------------------------------------------------------------------------

class ContentLengthTest(TestCase):
    def test_update_content_length(self):
        headers = {'Content-Type': 'application/json'}
        updated = update_content_length(headers, '{"key": "value"}')
        self.assertEqual(updated['Content-Length'], str(len('{"key": "value"}'.encode('utf-8'))))

    def test_update_content_length_in_raw(self):
        raw = 'POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\nbody data here'
        updated = update_content_length_in_raw(raw)
        self.assertIn(f'Content-Length: {len("body data here")}', updated)


# ---------------------------------------------------------------------------
# Utils: hexdump
# ---------------------------------------------------------------------------

class HexdumpTest(TestCase):
    def test_basic(self):
        result = hexdump('Hello')
        self.assertIn('48', result)  # 'H' in hex
        self.assertIn('Hello', result)

    def test_empty(self):
        result = hexdump('')
        self.assertEqual(result, '')


# ---------------------------------------------------------------------------
# API endpoint smoke tests
# ---------------------------------------------------------------------------

class TabAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_list_tabs_empty(self):
        resp = self.client.get('/repeater/api/tabs/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_create_tab(self):
        resp = self.client.post('/repeater/api/tabs/', {'name': 'Test Tab'}, format='json')
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()['name'], 'Test Tab')

    def test_get_tab(self):
        tab = RepeaterTab.objects.create(name='Tab A')
        resp = self.client.get(f'/repeater/api/tabs/{tab.id}/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['name'], 'Tab A')

    def test_patch_tab(self):
        tab = RepeaterTab.objects.create(name='Old Name')
        resp = self.client.patch(f'/repeater/api/tabs/{tab.id}/', {'name': 'New Name'}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['name'], 'New Name')

    def test_delete_tab(self):
        tab = RepeaterTab.objects.create(name='To Delete')
        resp = self.client.delete(f'/repeater/api/tabs/{tab.id}/')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(RepeaterTab.objects.filter(id=tab.id).exists())

    def test_tab_not_found(self):
        resp = self.client.get('/repeater/api/tabs/9999/')
        self.assertEqual(resp.status_code, 404)


class TabHistoryAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.tab = RepeaterTab.objects.create(name='History Tab')

    def test_empty_history(self):
        resp = self.client.get(f'/repeater/api/tabs/{self.tab.id}/history/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['count'], 0)

    def test_history_with_requests(self):
        RepeaterRequest.objects.create(
            url='http://example.com', method='GET', headers='{}', tab=self.tab, tab_history_index=0
        )
        resp = self.client.get(f'/repeater/api/tabs/{self.tab.id}/history/')
        self.assertEqual(resp.json()['count'], 1)


class EncodeDecodeAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_url_encode(self):
        resp = self.client.post(
            '/repeater/api/encode-decode/',
            {'operation': 'url_encode', 'value': 'hello world'},
            format='json',
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['result'], 'hello%20world')

    def test_base64_encode(self):
        resp = self.client.post(
            '/repeater/api/encode-decode/',
            {'operation': 'base64_encode', 'value': 'test'},
            format='json',
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['result'], 'dGVzdA==')

    def test_unknown_operation(self):
        resp = self.client.post(
            '/repeater/api/encode-decode/',
            {'operation': 'invalid_op', 'value': 'test'},
            format='json',
        )
        self.assertEqual(resp.status_code, 400)


class ParseRawAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_parse_raw(self):
        resp = self.client.post(
            '/repeater/api/parse-raw/',
            {'raw': 'GET /index HTTP/1.1\r\nHost: example.com\r\n\r\n'},
            format='json',
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['method'], 'GET')

    def test_build_raw(self):
        resp = self.client.post(
            '/repeater/api/build-raw/',
            {'method': 'POST', 'url': 'http://example.com/path', 'headers': {}, 'body': 'data'},
            format='json',
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn('POST /path HTTP/1.1', resp.json()['raw'])


class CompareAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_compare_missing_ids(self):
        resp = self.client.post('/repeater/api/compare/', {}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_compare_not_found(self):
        resp = self.client.post(
            '/repeater/api/compare/',
            {'response_a_id': 9999, 'response_b_id': 9998},
            format='json',
        )
        self.assertEqual(resp.status_code, 404)

    def test_compare_two_responses(self):
        req = RepeaterRequest.objects.create(url='http://example.com', method='GET', headers='{}')
        r_a = RepeaterResponse.objects.create(request=req, status_code=200, headers='{}', body='aaa', response_time=10)
        r_b = RepeaterResponse.objects.create(request=req, status_code=404, headers='{}', body='bbb', response_time=20)
        resp = self.client.post(
            '/repeater/api/compare/',
            {'response_a_id': r_a.id, 'response_b_id': r_b.id},
            format='json',
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data['status_code']['changed'])
        self.assertTrue(data['body_changed'])


class SendToToolAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.req = RepeaterRequest.objects.create(url='http://example.com', method='GET', headers='{}')

    def test_unknown_tool(self):
        resp = self.client.post(f'/repeater/api/requests/{self.req.id}/send-to/unknown_tool/')
        self.assertEqual(resp.status_code, 400)

    def test_send_to_interceptor(self):
        resp = self.client.post(f'/repeater/api/requests/{self.req.id}/send-to/interceptor/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('interceptor', resp.json()['message'].lower())


# ---------------------------------------------------------------------------
# Bypass integration tests
# ---------------------------------------------------------------------------

class ApplyBypassTechniquesTest(TestCase):
    """Unit tests for the apply_bypass_techniques helper."""

    def setUp(self):
        from repeater.views import apply_bypass_techniques
        self.fn = apply_bypass_techniques

    def test_returns_dict_structure(self):
        result = self.fn('hello', ['url_encode'])
        self.assertIn('original', result)
        self.assertIn('transformed', result)
        self.assertIn('techniques_applied', result)

    def test_original_preserved(self):
        result = self.fn('hello world', ['url_encode'])
        self.assertEqual(result['original'], 'hello world')

    def test_url_encode_applied(self):
        result = self.fn('hello world', ['url_encode'])
        self.assertNotIn(' ', result['transformed'])
        self.assertIn('url_encode', result['techniques_applied'])

    def test_unknown_technique_skipped(self):
        result = self.fn('hello', ['nonexistent_technique'])
        self.assertEqual(result['transformed'], 'hello')
        self.assertEqual(result['techniques_applied'], [])

    def test_no_techniques_passthrough(self):
        result = self.fn('hello', [])
        self.assertEqual(result['transformed'], 'hello')
        self.assertEqual(result['techniques_applied'], [])

    def test_multiple_techniques_sequential(self):
        result = self.fn('hello', ['upper', 'reverse'])
        self.assertIn('upper', result['techniques_applied'])
        self.assertIn('reverse', result['techniques_applied'])
        self.assertEqual(result['transformed'], 'OLLEH')


class BypassTechniquesAPITest(TestCase):
    """Tests for the GET /repeater/api/bypass-techniques/ endpoint."""

    def setUp(self):
        self.client = APIClient()

    def test_returns_200(self):
        resp = self.client.get('/repeater/api/bypass-techniques/')
        self.assertEqual(resp.status_code, 200)

    def test_returns_list(self):
        resp = self.client.get('/repeater/api/bypass-techniques/')
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_items_have_name_and_description(self):
        resp = self.client.get('/repeater/api/bypass-techniques/')
        for item in resp.json():
            self.assertIn('name', item)
            self.assertIn('description', item)

    def test_known_techniques_present(self):
        resp = self.client.get('/repeater/api/bypass-techniques/')
        names = [t['name'] for t in resp.json()]
        self.assertIn('url_encode', names)
        self.assertIn('html_decimal', names)


class SendRequestBypassModeTest(TestCase):
    """Tests for send_request with bypass_mode parameter."""

    def setUp(self):
        self.client = APIClient()

    def test_send_without_bypass_mode_backward_compatible(self):
        """Sending without bypass_mode must not break existing behaviour."""
        req = RepeaterRequest.objects.create(
            url='http://example.com/path',
            method='GET',
            headers='{}',
        )
        # Without mocking the actual HTTP call, we expect a network error (500).
        # We only verify the response is not a 404 (i.e. the endpoint was found).
        resp = self.client.post(
            f'/repeater/api/requests/{req.id}/send/',
            {},
            format='json',
        )
        self.assertNotEqual(resp.status_code, 404)

    def test_send_with_bypass_mode_not_found(self):
        resp = self.client.post(
            '/repeater/api/requests/999999/send/',
            {'bypass_mode': {'enabled': True, 'techniques': ['url_encode'], 'apply_to': ['url']}},
            format='json',
        )
        self.assertEqual(resp.status_code, 404)

    def test_send_with_bypass_mode_disabled_no_effect(self):
        """bypass_mode.enabled=false should behave same as no bypass_mode."""
        req = RepeaterRequest.objects.create(
            url='http://example.com/path?q=hello world',
            method='GET',
            headers='{}',
        )
        resp = self.client.post(
            f'/repeater/api/requests/{req.id}/send/',
            {'bypass_mode': {'enabled': False, 'techniques': ['url_encode'], 'apply_to': ['url']}},
            format='json',
        )
        # Should attempt to send (network error is acceptable here)
        self.assertNotEqual(resp.status_code, 404)


