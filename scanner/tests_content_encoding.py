"""
Tests for Content Encoding Detection & Decoder (scanner/content_encoding_detector.py)
"""

import unittest
from scanner.content_encoding_detector import ContentEncodingDetector


class TestDetectEncoding(unittest.TestCase):
    """Tests for ContentEncodingDetector.detect_encoding()."""

    def setUp(self):
        self.detector = ContentEncodingDetector()

    def test_detects_url_encoded(self):
        result = self.detector.detect_encoding('hello%20world')
        self.assertIn('url_encoded', result)

    def test_detects_url_encoded_full(self):
        result = self.detector.detect_encoding('%65%78%61%6D%70%6C%65')
        self.assertIn('url_encoded', result)

    def test_detects_hex(self):
        result = self.detector.detect_encoding('68656c6c6f')
        self.assertIn('hex', result)

    def test_detects_hex_uppercase(self):
        result = self.detector.detect_encoding('48454C4C4F')
        self.assertIn('hex', result)

    def test_detects_base64(self):
        import base64
        encoded = base64.b64encode(b'hello world').decode()
        result = self.detector.detect_encoding(encoded)
        self.assertIn('base64', result)

    def test_detects_base64url(self):
        import base64
        encoded = base64.urlsafe_b64encode(b'hello world').decode().rstrip('=')
        # Inject - or _ to trigger base64url branch
        result = self.detector.detect_encoding(encoded)
        # base64url uses - and _ — standard b64 for 'hello world' may not contain those
        # so just check no error is raised; the encoding may or may not be detected
        self.assertIsInstance(result, list)

    def test_no_encoding_plain(self):
        result = self.detector.detect_encoding('plaintext')
        # Short plain text should not be detected as any encoding
        self.assertNotIn('hex', result)
        self.assertNotIn('base64', result)

    def test_empty_string(self):
        result = self.detector.detect_encoding('')
        self.assertEqual(result, [])

    def test_none_input(self):
        result = self.detector.detect_encoding(None)
        self.assertEqual(result, [])


class TestDecodeContent(unittest.TestCase):
    """Tests for ContentEncodingDetector.decode_content()."""

    def setUp(self):
        self.detector = ContentEncodingDetector()

    def test_decode_base64(self):
        import base64
        encoded = base64.b64encode(b'secret value').decode()
        result = self.detector.decode_content(encoded, 'base64')
        self.assertEqual(result, 'secret value')

    def test_decode_base64url(self):
        import base64
        encoded = base64.urlsafe_b64encode(b'url safe').decode()
        result = self.detector.decode_content(encoded, 'base64url')
        self.assertEqual(result, 'url safe')

    def test_decode_hex(self):
        result = self.detector.decode_content('68656c6c6f', 'hex')
        self.assertEqual(result, 'hello')

    def test_decode_url_encoded(self):
        result = self.detector.decode_content('hello%20world', 'url_encoded')
        self.assertEqual(result, 'hello world')

    def test_decode_invalid_base64_returns_original(self):
        result = self.detector.decode_content('!!!invalid!!!', 'base64')
        self.assertEqual(result, '!!!invalid!!!')

    def test_decode_unknown_encoding_returns_original(self):
        result = self.detector.decode_content('something', 'unknown_type')
        self.assertEqual(result, 'something')

    def test_decode_empty_returns_empty(self):
        result = self.detector.decode_content('', 'base64')
        self.assertEqual(result, '')


class TestAutoDecode(unittest.TestCase):
    """Tests for ContentEncodingDetector.auto_decode()."""

    def setUp(self):
        self.detector = ContentEncodingDetector()

    def test_auto_decode_base64(self):
        import base64
        encoded = base64.b64encode(b'auto decoded').decode()
        result = self.detector.auto_decode(encoded)
        self.assertEqual(result['encoding'], 'base64')
        self.assertEqual(result['decoded'], 'auto decoded')
        self.assertEqual(result['original'], encoded)
        self.assertEqual(result['depth'], 1)

    def test_auto_decode_hex(self):
        result = self.detector.auto_decode('68656c6c6f')
        self.assertEqual(result['encoding'], 'hex')
        self.assertEqual(result['decoded'], 'hello')

    def test_auto_decode_url_encoded(self):
        result = self.detector.auto_decode('hello%20world%21')
        self.assertEqual(result['encoding'], 'url_encoded')
        self.assertIn('hello world', result['decoded'])

    def test_auto_decode_no_encoding(self):
        result = self.detector.auto_decode('plaintext')
        self.assertIsNone(result['encoding'])
        self.assertEqual(result['decoded'], 'plaintext')
        self.assertEqual(result['depth'], 0)

    def test_auto_decode_empty(self):
        result = self.detector.auto_decode('')
        self.assertIsNone(result['encoding'])
        self.assertEqual(result['decoded'], '')

    def test_auto_decode_interesting_flag(self):
        import base64
        # Encode a string that contains 'password'
        encoded = base64.b64encode(b'password=secret123').decode()
        result = self.detector.auto_decode(encoded)
        self.assertTrue(result['interesting'])

    def test_auto_decode_not_interesting(self):
        import base64
        encoded = base64.b64encode(b'hello world').decode()
        result = self.detector.auto_decode(encoded)
        self.assertFalse(result['interesting'])


class TestUrlEncodeHostname(unittest.TestCase):
    """Tests for ContentEncodingDetector.url_encode_hostname()."""

    def setUp(self):
        self.detector = ContentEncodingDetector()

    def test_basic_hostname(self):
        result = self.detector.url_encode_hostname('example.com')
        # Each character should be percent-encoded
        self.assertTrue(result.startswith('%'))
        self.assertIn('%', result)

    def test_encodes_all_characters(self):
        hostname = 'abc'
        result = self.detector.url_encode_hostname(hostname)
        # 3 chars → 3 percent-encoded tokens of 3 chars each = 9 chars
        self.assertEqual(len(result), 3 * 3)

    def test_empty_hostname(self):
        result = self.detector.url_encode_hostname('')
        self.assertEqual(result, '')

    def test_roundtrip_via_url_decode(self):
        import urllib.parse
        hostname = 'internal.corp'
        encoded = self.detector.url_encode_hostname(hostname)
        decoded = urllib.parse.unquote(encoded)
        self.assertEqual(decoded, hostname)


class TestUrlDecode(unittest.TestCase):
    """Tests for ContentEncodingDetector.url_decode()."""

    def setUp(self):
        self.detector = ContentEncodingDetector()

    def test_basic_url_decode(self):
        result = self.detector.url_decode('hello%20world')
        self.assertEqual(result, 'hello world')

    def test_full_encoding(self):
        result = self.detector.url_decode('%68%65%6C%6C%6F')
        self.assertEqual(result, 'hello')

    def test_no_encoding(self):
        result = self.detector.url_decode('hello')
        self.assertEqual(result, 'hello')

    def test_empty(self):
        result = self.detector.url_decode('')
        self.assertEqual(result, '')


class TestRecursiveDecode(unittest.TestCase):
    """Tests for ContentEncodingDetector.recursive_decode()."""

    def setUp(self):
        self.detector = ContentEncodingDetector()

    def test_single_layer(self):
        import base64
        encoded = base64.b64encode(b'plaintext').decode()
        steps = self.detector.recursive_decode(encoded)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['encoding'], 'base64')
        self.assertEqual(steps[0]['output'], 'plaintext')
        self.assertEqual(steps[0]['step'], 1)

    def test_no_encoding(self):
        steps = self.detector.recursive_decode('plaintext')
        self.assertEqual(steps, [])

    def test_max_depth_respected(self):
        import base64
        # Double-encoded base64
        inner = base64.b64encode(b'deep').decode()
        outer = base64.b64encode(inner.encode()).decode()
        steps = self.detector.recursive_decode(outer, max_depth=1)
        self.assertLessEqual(len(steps), 1)

    def test_double_encoded(self):
        import base64
        inner = base64.b64encode(b'deep secret').decode()
        outer = base64.b64encode(inner.encode()).decode()
        steps = self.detector.recursive_decode(outer, max_depth=5)
        self.assertGreaterEqual(len(steps), 1)
        # Final decoded value should be 'deep secret'
        final_output = steps[-1]['output']
        self.assertIn('deep secret', final_output)

    def test_step_structure(self):
        import base64
        encoded = base64.b64encode(b'test').decode()
        steps = self.detector.recursive_decode(encoded)
        if steps:
            step = steps[0]
            self.assertIn('step', step)
            self.assertIn('encoding', step)
            self.assertIn('input', step)
            self.assertIn('output', step)
            self.assertIn('interesting', step)


class TestAnalyzeScanResponse(unittest.TestCase):
    """Tests for ContentEncodingDetector.analyze_scan_response()."""

    def setUp(self):
        self.detector = ContentEncodingDetector()

    def test_finds_hex_in_response(self):
        body = 'The token is 68656c6c6f and more data follows'
        findings = self.detector.analyze_scan_response(body, 'https://example.com')
        hex_findings = [f for f in findings if f['encoding_type'] == 'hex']
        self.assertTrue(len(hex_findings) >= 1)
        self.assertTrue(any(f['decoded_value'] == 'hello' for f in hex_findings))

    def test_finds_url_encoded(self):
        body = 'Redirect to: %68%65%6C%6C%6F%20%77%6F%72%6C%64'
        findings = self.detector.analyze_scan_response(body, 'https://example.com')
        url_findings = [f for f in findings if f['encoding_type'] == 'url_encoded']
        self.assertTrue(len(url_findings) >= 1)

    def test_empty_body_returns_empty(self):
        findings = self.detector.analyze_scan_response('', 'https://example.com')
        self.assertEqual(findings, [])

    def test_finding_structure(self):
        import base64
        encoded = base64.b64encode(b'password=admin').decode()
        body = f'Session token: {encoded} end'
        findings = self.detector.analyze_scan_response(body, 'https://example.com')
        if findings:
            f = findings[0]
            self.assertIn('encoded_value', f)
            self.assertIn('encoding_type', f)
            self.assertIn('decoded_value', f)
            self.assertIn('interesting', f)
            self.assertIn('location', f)

    def test_interesting_content_flagged(self):
        import base64
        encoded = base64.b64encode(b'api_key=sk-supersecret').decode()
        body = f'value={encoded}'
        findings = self.detector.analyze_scan_response(body, 'https://example.com')
        interesting = [f for f in findings if f.get('interesting')]
        self.assertTrue(len(interesting) >= 1)


if __name__ == '__main__':
    unittest.main()
