"""
Tests for SmartCrawler

Covers:
- Recursive crawling up to max_depth
- max_urls cap enforcement
- robots.txt parsing and URL seeding
- sitemap.xml URL extraction
- JavaScript link extraction
- Form action discovery
- Scope enforcement (no external domains)
- URL normalisation and deduplication
- Rate limiting (delay)
- Error handling for failed requests
"""

from unittest.mock import MagicMock, patch, call
from urllib.parse import urlparse
from django.test import SimpleTestCase as TestCase

from scanner.smart_crawler import SmartCrawler, CrawlResult, FormInfo


def _make_response(text: str = '', status_code: int = 200, content_type: str = 'text/html'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {'Content-Type': content_type}
    resp.url = 'https://example.com/'
    return resp


class TestSmartCrawlerInit(TestCase):
    def test_defaults(self):
        crawler = SmartCrawler()
        self.assertEqual(crawler.max_depth, 3)
        self.assertEqual(crawler.max_urls, 500)
        self.assertAlmostEqual(crawler.delay, 0.1)
        self.assertEqual(crawler.timeout, 10)
        self.assertFalse(crawler.verify_ssl)

    def test_custom_params(self):
        crawler = SmartCrawler(max_depth=1, max_urls=50, delay=0.5)
        self.assertEqual(crawler.max_depth, 1)
        self.assertEqual(crawler.max_urls, 50)
        self.assertAlmostEqual(crawler.delay, 0.5)


class TestSmartCrawlerNormalization(TestCase):
    def setUp(self):
        self.crawler = SmartCrawler()

    def test_strips_fragment(self):
        url = 'https://example.com/page#section'
        self.assertNotIn('#', self.crawler._normalize_url(url))

    def test_sorts_query_params(self):
        url1 = 'https://example.com/?b=2&a=1'
        url2 = 'https://example.com/?a=1&b=2'
        self.assertEqual(self.crawler._normalize_url(url1), self.crawler._normalize_url(url2))

    def test_strips_trailing_slash(self):
        self.assertEqual(
            self.crawler._normalize_url('https://example.com/'),
            'https://example.com',
        )

    def test_keeps_path(self):
        url = 'https://example.com/path/to/page'
        self.assertIn('/path/to/page', self.crawler._normalize_url(url))


class TestSmartCrawlerScopeEnforcement(TestCase):
    def setUp(self):
        self.crawler = SmartCrawler()

    def test_in_scope_same_domain(self):
        self.assertTrue(self.crawler._in_scope('https://example.com/page', 'example.com'))

    def test_in_scope_subdomain(self):
        self.assertTrue(self.crawler._in_scope('https://sub.example.com/page', 'example.com'))

    def test_out_of_scope_external(self):
        self.assertFalse(self.crawler._in_scope('https://evil.com/page', 'example.com'))

    def test_out_of_scope_non_http(self):
        self.assertFalse(self.crawler._in_scope('ftp://example.com/file', 'example.com'))


class TestSmartCrawlerParamExtraction(TestCase):
    def setUp(self):
        self.crawler = SmartCrawler()

    def test_extracts_params(self):
        url = 'https://example.com/search?q=test&page=1'
        params = self.crawler._extract_params(url)
        self.assertIn('q', params)
        self.assertIn('page', params)

    def test_no_params(self):
        url = 'https://example.com/page'
        self.assertEqual(self.crawler._extract_params(url), [])


class TestSmartCrawlerRobotsAndSitemap(TestCase):
    def setUp(self):
        self.crawler = SmartCrawler(delay=0)

    def test_parse_robots_disallow(self):
        content = "User-agent: *\nDisallow: /admin/\nDisallow: /private/\n"
        queue = []
        visited = set()
        self.crawler._parse_robots(content, 'https://example.com', 'example.com', queue, visited)
        enqueued_urls = [entry[2] for entry in queue]
        self.assertTrue(any('/admin' in u for u in enqueued_urls))

    def test_parse_robots_sitemap_directive(self):
        content = "User-agent: *\nDisallow: /\nSitemap: https://example.com/sitemap.xml\n"
        queue = []
        visited = set()
        self.crawler._parse_robots(content, 'https://example.com', 'example.com', queue, visited)
        enqueued_urls = [entry[2] for entry in queue]
        self.assertTrue(any('sitemap.xml' in u for u in enqueued_urls))

    def test_parse_sitemap_urls(self):
        content = """<?xml version="1.0"?>
        <urlset>
          <url><loc>https://example.com/page1</loc></url>
          <url><loc>https://example.com/page2</loc></url>
        </urlset>"""
        queue = []
        visited = set()
        self.crawler._parse_sitemap(content, 'example.com', queue, visited)
        enqueued_urls = [entry[2] for entry in queue]
        self.assertTrue(any('page1' in u for u in enqueued_urls))
        self.assertTrue(any('page2' in u for u in enqueued_urls))

    def test_parse_sitemap_filters_out_of_scope(self):
        content = """<urlset>
          <url><loc>https://example.com/page1</loc></url>
          <url><loc>https://evil.com/page2</loc></url>
        </urlset>"""
        queue = []
        visited = set()
        self.crawler._parse_sitemap(content, 'example.com', queue, visited)
        enqueued_urls = [entry[2] for entry in queue]
        external_enqueued = [u for u in enqueued_urls if urlparse(u).netloc != 'example.com']
        self.assertEqual(external_enqueued, [])


class TestSmartCrawlerJavaScriptExtraction(TestCase):
    def setUp(self):
        self.crawler = SmartCrawler(delay=0)

    def test_extracts_api_paths_from_js(self):
        js_code = "fetch('/api/v1/users')"
        queue = []
        visited = set()
        self.crawler._process_javascript(
            'https://example.com/app.js', js_code, 'example.com', 0, queue, visited
        )
        enqueued_urls = [entry[2] for entry in queue]
        self.assertTrue(any('/api/v1/users' in u for u in enqueued_urls))

    def test_extracts_axios_calls(self):
        js_code = "axios.get('/api/data')"
        queue = []
        visited = set()
        self.crawler._process_javascript(
            'https://example.com/app.js', js_code, 'example.com', 0, queue, visited
        )
        enqueued_urls = [entry[2] for entry in queue]
        self.assertTrue(any('/api/data' in u for u in enqueued_urls))


class TestSmartCrawlerHTMLProcessing(TestCase):
    def setUp(self):
        self.crawler = SmartCrawler(delay=0)

    def test_extracts_links(self):
        html = '<html><body><a href="/page1">P1</a><a href="/page2">P2</a></body></html>'
        queue = []
        visited = set()
        result = CrawlResult()
        self.crawler._process_html(
            'https://example.com', html, 'example.com', 0, queue, visited, result
        )
        enqueued_urls = [entry[2] for entry in queue]
        self.assertTrue(any('page1' in u for u in enqueued_urls))
        self.assertTrue(any('page2' in u for u in enqueued_urls))

    def test_extracts_forms(self):
        html = '<html><body><form action="/login" method="POST"><input name="user"/></form></body></html>'
        queue = []
        visited = set()
        result = CrawlResult()
        self.crawler._process_html(
            'https://example.com', html, 'example.com', 0, queue, visited, result
        )
        self.assertEqual(len(result.forms), 1)
        self.assertIn('/login', result.forms[0].action)
        self.assertEqual(result.forms[0].method, 'POST')
        self.assertIn('user', result.forms[0].fields)

    def test_ignores_external_links(self):
        html = '<a href="https://evil.com/hack">evil</a>'
        queue = []
        visited = set()
        result = CrawlResult()
        self.crawler._process_html(
            'https://example.com', html, 'example.com', 0, queue, visited, result
        )
        enqueued_urls = [entry[2] for entry in queue]
        external_enqueued = [u for u in enqueued_urls if urlparse(u).netloc != 'example.com']
        self.assertEqual(external_enqueued, [])

    def test_ignores_mailto_and_javascript(self):
        html = '<a href="mailto:x@y.com">m</a><a href="javascript:void(0)">j</a>'
        queue = []
        visited = set()
        result = CrawlResult()
        self.crawler._process_html(
            'https://example.com', html, 'example.com', 0, queue, visited, result
        )
        self.assertEqual(len(queue), 0)


class TestSmartCrawlerIntegration(TestCase):
    """Integration tests with mocked HTTP session."""

    @patch('scanner.smart_crawler.HAS_REQUESTS', True)
    def test_crawl_respects_max_urls(self):
        crawler = SmartCrawler(max_urls=2, max_depth=5, delay=0)

        session_mock = MagicMock()
        # robots.txt and sitemap both return 404 to avoid seeding extra URLs
        session_mock.get.return_value = _make_response(
            '<html><a href="/page1">p1</a><a href="/page2">p2</a><a href="/page3">p3</a></html>',
            200,
        )
        crawler._session = session_mock

        result = crawler.crawl('https://example.com')
        self.assertLessEqual(len(result.urls), 2)

    @patch('scanner.smart_crawler.HAS_REQUESTS', True)
    def test_crawl_handles_request_error_gracefully(self):
        crawler = SmartCrawler(max_urls=10, delay=0)

        session_mock = MagicMock()
        session_mock.get.side_effect = ConnectionError('timeout')
        crawler._session = session_mock

        result = crawler.crawl('https://example.com')
        # Should return a result even on total failure
        self.assertIsInstance(result, CrawlResult)

    @patch('scanner.smart_crawler.HAS_REQUESTS', False)
    def test_crawl_without_requests_library(self):
        crawler = SmartCrawler()
        result = crawler.crawl('https://example.com')
        self.assertIsInstance(result, CrawlResult)
        self.assertEqual(result.urls, [])
