"""
Tests for the Heat Map Analyzer (scanner/heat_map_analyzer.py)
"""

import unittest
from unittest.mock import patch, MagicMock
from scanner.heat_map_analyzer import (
    HeatMapAnalyzer,
    HotSpot,
    HOTSPOT_CATEGORIES,
)


class TestHotSpotToDict(unittest.TestCase):
    """Tests for HotSpot.to_dict()."""

    def test_to_dict_contains_expected_keys(self):
        hs = HotSpot(
            category='api_endpoints',
            url='https://example.com/api/users/',
            parameter='id',
            risk_score=8,
            priority='Critical',
            vulnerabilities=['idor', 'missing_auth'],
            payloads=['PUT /api/users/1'],
            description='API endpoint found',
            evidence='Pattern matched',
        )
        d = hs.to_dict()
        self.assertEqual(d['category'], 'api_endpoints')
        self.assertEqual(d['url'], 'https://example.com/api/users/')
        self.assertEqual(d['parameter'], 'id')
        self.assertEqual(d['risk_score'], 8)
        self.assertEqual(d['priority'], 'Critical')
        self.assertIn('idor', d['vulnerabilities'])
        self.assertEqual(d['description'], 'API endpoint found')

    def test_to_dict_category_label_populated(self):
        hs = HotSpot(
            category='content_xml',
            url='https://example.com/upload',
        )
        d = hs.to_dict()
        # Should pull label from HOTSPOT_CATEGORIES
        self.assertEqual(d['category_label'], HOTSPOT_CATEGORIES['content_xml']['label'])


class TestHeatMapAnalyzerUrlAnalysis(unittest.TestCase):
    """Tests for URL-based (passive) hot spot detection."""

    def setUp(self):
        self.analyzer = HeatMapAnalyzer()

    def test_api_url_detected(self):
        hotspots = self.analyzer._check_api_pattern('https://example.com/api/v1/users/')
        categories = [h.category for h in hotspots]
        self.assertIn('api_endpoints', categories)

    def test_graphql_url_detected(self):
        hotspots = self.analyzer._check_api_pattern('https://example.com/graphql')
        categories = [h.category for h in hotspots]
        self.assertIn('api_endpoints', categories)

    def test_non_api_url_not_detected(self):
        hotspots = self.analyzer._check_api_pattern('https://example.com/home')
        self.assertEqual(hotspots, [])

    def test_profile_url_detected(self):
        hotspots = self.analyzer._check_account_pattern('https://example.com/profile/edit', '')
        categories = [h.category for h in hotspots]
        self.assertIn('account_profile', categories)

    def test_settings_url_detected(self):
        hotspots = self.analyzer._check_account_pattern('https://example.com/settings', '')
        categories = [h.category for h in hotspots]
        self.assertIn('account_profile', categories)

    def test_non_account_url_not_detected(self):
        hotspots = self.analyzer._check_account_pattern('https://example.com/blog', '')
        self.assertEqual(hotspots, [])

    def test_url_param_ssrf_detected(self):
        hotspots = self.analyzer._check_url_params('https://example.com/fetch?url=https://other.com')
        categories = [h.category for h in hotspots]
        self.assertIn('url_path_params', categories)

    def test_redirect_param_detected(self):
        hotspots = self.analyzer._check_url_params('https://example.com/login?redirect=https://other.com')
        categories = [h.category for h in hotspots]
        self.assertIn('url_path_params', categories)

    def test_no_params_no_hotspot(self):
        hotspots = self.analyzer._check_url_params('https://example.com/page')
        self.assertEqual(hotspots, [])


class TestHeatMapAnalyzerContentType(unittest.TestCase):
    """Tests for content-type-based hot spot detection."""

    def setUp(self):
        self.analyzer = HeatMapAnalyzer()

    def test_multipart_form_detected(self):
        hotspots = self.analyzer._check_content_type(
            'https://example.com/upload',
            'multipart/form-data; boundary=----abc',
            '',
        )
        categories = [h.category for h in hotspots]
        self.assertIn('content_multipart', categories)

    def test_xml_content_type_detected(self):
        hotspots = self.analyzer._check_content_type(
            'https://example.com/xml',
            'application/xml',
            '',
        )
        categories = [h.category for h in hotspots]
        self.assertIn('content_xml', categories)

    def test_json_content_type_detected(self):
        hotspots = self.analyzer._check_content_type(
            'https://example.com/api/',
            'application/json',
            '',
        )
        categories = [h.category for h in hotspots]
        self.assertIn('content_json', categories)

    def test_text_xml_detected(self):
        hotspots = self.analyzer._check_content_type(
            'https://example.com/feed',
            'text/xml',
            '',
        )
        categories = [h.category for h in hotspots]
        self.assertIn('content_xml', categories)

    def test_plain_text_no_hotspot(self):
        hotspots = self.analyzer._check_content_type(
            'https://example.com/',
            'text/html',
            '',
        )
        self.assertEqual(hotspots, [])


class TestHeatMapAnalyzerUploadForms(unittest.TestCase):
    """Tests for upload form hot spot detection."""

    def setUp(self):
        self.analyzer = HeatMapAnalyzer()

    def test_file_input_xml_detected(self):
        body = '<form><input type="file" accept=".xml,.svg"/></form>'
        hotspots = self.analyzer._check_upload_forms('https://example.com/upload', body)
        categories = [h.category for h in hotspots]
        self.assertIn('upload_xml', categories)

    def test_file_input_image_detected(self):
        body = '<form><input type="file" accept=".png,.jpg"/></form>'
        hotspots = self.analyzer._check_upload_forms('https://example.com/avatar', body)
        categories = [h.category for h in hotspots]
        self.assertIn('upload_image', categories)

    def test_s3_bucket_reference_detected(self):
        body = '<input type="file"><img src="https://mybucket.s3.amazonaws.com/img.png"/>'
        hotspots = self.analyzer._check_upload_forms('https://example.com/upload', body)
        categories = [h.category for h in hotspots]
        self.assertIn('upload_s3', categories)

    def test_no_file_input_no_hotspot(self):
        body = '<form><input type="text" name="name"/></form>'
        hotspots = self.analyzer._check_upload_forms('https://example.com/', body)
        self.assertEqual(hotspots, [])


class TestHeatMapAnalyzerWebhook(unittest.TestCase):
    """Tests for webhook / integration hot spot detection."""

    def setUp(self):
        self.analyzer = HeatMapAnalyzer()

    def test_webhook_url_detected(self):
        hotspots = self.analyzer._check_webhook_pattern(
            'https://example.com/settings/webhook', ''
        )
        categories = [h.category for h in hotspots]
        self.assertIn('account_integrations', categories)

    def test_callback_param_in_body_detected(self):
        body = '<input name="callback_url" type="text"/>'
        hotspots = self.analyzer._check_webhook_pattern('https://example.com/', body)
        categories = [h.category for h in hotspots]
        self.assertIn('account_integrations', categories)

    def test_no_webhook_no_hotspot(self):
        hotspots = self.analyzer._check_webhook_pattern('https://example.com/about', '')
        self.assertEqual(hotspots, [])


class TestHeatMapAnalyzerSummary(unittest.TestCase):
    """Tests for summary and risk score helpers."""

    def setUp(self):
        self.analyzer = HeatMapAnalyzer()

    def test_build_summary_counts(self):
        hotspots = [
            HotSpot('api_endpoints', 'https://example.com/api/', risk_score=8, priority='Critical'),
            HotSpot('api_endpoints', 'https://example.com/api/v2/', risk_score=7, priority='High'),
            HotSpot('content_json', 'https://example.com/api/', risk_score=7, priority='High'),
        ]
        summary = self.analyzer._build_summary(hotspots)
        self.assertEqual(summary['by_category']['api_endpoints'], 2)
        self.assertEqual(summary['by_category']['content_json'], 1)
        self.assertEqual(summary['total'], 3)

    def test_risk_scores_averaged(self):
        hotspots = [
            HotSpot('api_endpoints', 'https://example.com/', risk_score=8, priority='Critical'),
            HotSpot('api_endpoints', 'https://example.com/v2/', risk_score=6, priority='High'),
        ]
        scores = self.analyzer._risk_scores(hotspots)
        self.assertAlmostEqual(scores['api_endpoints'], 7.0)

    def test_empty_hotspots_summary(self):
        summary = self.analyzer._build_summary([])
        self.assertEqual(summary['total'], 0)
        self.assertEqual(summary['by_category'], {})


class TestHeatMapAnalyzerAnalyzeResponse(unittest.TestCase):
    """Integration tests for analyze_response()."""

    def setUp(self):
        self.analyzer = HeatMapAnalyzer()

    def test_analyze_response_returns_list(self):
        result = self.analyzer.analyze_response(
            'https://example.com/api/users/',
            '<html></html>',
        )
        self.assertIsInstance(result, list)

    def test_api_and_json_detected(self):
        hotspots = self.analyzer.analyze_response(
            'https://example.com/api/data/',
            '{"key":"value"}',
            headers={'Content-Type': 'application/json'},
        )
        categories = [h.category for h in hotspots]
        self.assertIn('api_endpoints', categories)
        self.assertIn('content_json', categories)

    def test_multipart_upload_page(self):
        body = '<form enctype="multipart/form-data"><input type="file" accept=".png"/></form>'
        hotspots = self.analyzer.analyze_response(
            'https://example.com/upload',
            body,
            headers={'Content-Type': 'text/html'},
        )
        categories = [h.category for h in hotspots]
        self.assertIn('content_multipart', categories)
        self.assertIn('upload_image', categories)


class TestHeatMapAnalyzerAnalyze(unittest.TestCase):
    """Tests for the top-level analyze() method (no real HTTP calls)."""

    def setUp(self):
        self.analyzer = HeatMapAnalyzer()

    @patch('scanner.heat_map_analyzer._HAS_REQUESTS', False)
    def test_analyze_without_requests(self):
        """When requests is unavailable, analysis should still succeed using URL analysis."""
        result = self.analyzer.analyze('https://example.com/api/v1/users/?redirect=https://evil.com')
        self.assertIn('target_url', result)
        self.assertIn('hotspots', result)
        self.assertIn('summary', result)
        self.assertIn('generated_at', result)
        # Should detect api_endpoints and url_path_params from URL alone
        categories = [h['category'] for h in result['hotspots']]
        self.assertIn('api_endpoints', categories)
        self.assertIn('url_path_params', categories)

    def test_analyze_result_structure(self):
        with patch('scanner.heat_map_analyzer._HAS_REQUESTS', False):
            result = self.analyzer.analyze('https://example.com/')
        self.assertIsInstance(result['hotspots'], list)
        self.assertIsInstance(result['summary'], dict)
        self.assertIsInstance(result['risk_scores'], dict)
        self.assertIsInstance(result['total_hotspots'], int)


class TestHotspotCategoriesDefinition(unittest.TestCase):
    """Validate the HOTSPOT_CATEGORIES constant is correctly defined."""

    def test_all_categories_have_required_keys(self):
        required_keys = {'label', 'vulnerabilities', 'description', 'payloads', 'base_risk', 'priority'}
        for cat_id, cat_def in HOTSPOT_CATEGORIES.items():
            for key in required_keys:
                self.assertIn(key, cat_def, f"Category '{cat_id}' missing key '{key}'")

    def test_risk_scores_in_range(self):
        for cat_id, cat_def in HOTSPOT_CATEGORIES.items():
            self.assertGreaterEqual(cat_def['base_risk'], 1, f"{cat_id} risk too low")
            self.assertLessEqual(cat_def['base_risk'], 10, f"{cat_id} risk too high")

    def test_priority_valid_values(self):
        valid = {'Critical', 'High', 'Medium', 'Low'}
        for cat_id, cat_def in HOTSPOT_CATEGORIES.items():
            self.assertIn(cat_def['priority'], valid, f"{cat_id} has invalid priority")


if __name__ == '__main__':
    unittest.main()
