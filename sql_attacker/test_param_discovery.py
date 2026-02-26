"""
Tests for Parameter Discovery Engine
"""

import socket
from django.test import TestCase
from unittest.mock import Mock, patch
import requests
from sql_attacker.param_discovery import ParameterDiscoveryEngine, DiscoveredParameter


class DiscoveredParameterTest(TestCase):
    """Test DiscoveredParameter class"""
    
    def test_parameter_creation(self):
        """Test creating a discovered parameter"""
        param = DiscoveredParameter(
            name='user_id',
            value='123',
            source='form',
            method='POST',
            field_type='text'
        )
        
        self.assertEqual(param.name, 'user_id')
        self.assertEqual(param.value, '123')
        self.assertEqual(param.source, 'form')
        self.assertEqual(param.method, 'POST')
        self.assertEqual(param.field_type, 'text')
    
    def test_parameter_to_dict(self):
        """Test converting parameter to dictionary"""
        param = DiscoveredParameter(
            name='token',
            value='abc123',
            source='hidden',
            method='POST',
            field_type='hidden'
        )
        
        param_dict = param.to_dict()
        
        self.assertEqual(param_dict['name'], 'token')
        self.assertEqual(param_dict['value'], 'abc123')
        self.assertEqual(param_dict['source'], 'hidden')
        self.assertEqual(param_dict['method'], 'POST')
        self.assertEqual(param_dict['field_type'], 'hidden')
    
    def test_parameter_repr(self):
        """Test string representation"""
        param = DiscoveredParameter(
            name='search',
            value='query',
            source='link'
        )
        
        repr_str = repr(param)
        self.assertIn('search', repr_str)
        self.assertIn('query', repr_str)
        self.assertIn('link', repr_str)


class ParameterDiscoveryEngineTest(TestCase):
    """Test ParameterDiscoveryEngine"""
    
    def setUp(self):
        """Set up test engine"""
        self.engine = ParameterDiscoveryEngine(timeout=10, verify_ssl=False)
    
    def test_engine_initialization(self):
        """Test engine initialization"""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.timeout, 10)
        self.assertFalse(self.engine.verify_ssl)
    
    def test_discover_from_forms_visible_fields(self):
        """Test discovering parameters from visible form fields"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <form method="POST" action="/submit">
                    <input type="text" name="username" value="admin">
                    <input type="password" name="password" value="">
                    <textarea name="comment"></textarea>
                    <select name="category">
                        <option value="1">Category 1</option>
                    </select>
                </form>
            </body>
        </html>
        """
        
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_forms(soup)
        
        self.assertEqual(len(params), 4)
        
        # Check username field
        username_param = next(p for p in params if p.name == 'username')
        self.assertEqual(username_param.value, 'admin')
        self.assertEqual(username_param.source, 'form')
        self.assertEqual(username_param.method, 'POST')
        
        # Check password field
        password_param = next(p for p in params if p.name == 'password')
        self.assertEqual(password_param.source, 'form')
        self.assertEqual(password_param.field_type, 'password')
    
    def test_discover_from_forms_hidden_fields(self):
        """Test discovering hidden form fields"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <form method="POST" action="/submit">
                    <input type="text" name="visible_field" value="test">
                    <input type="hidden" name="csrf_token" value="abc123xyz">
                    <input type="hidden" name="session_id" value="sess_456">
                </form>
            </body>
        </html>
        """
        
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_forms(soup)
        
        # Check hidden fields are properly identified
        hidden_params = [p for p in params if p.source == 'hidden']
        self.assertEqual(len(hidden_params), 2)
        
        csrf_param = next(p for p in params if p.name == 'csrf_token')
        self.assertEqual(csrf_param.source, 'hidden')
        self.assertEqual(csrf_param.value, 'abc123xyz')
        self.assertEqual(csrf_param.field_type, 'hidden')
    
    def test_discover_from_links(self):
        """Test discovering parameters from links"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <a href="/page?id=1&type=article">Article 1</a>
                <a href="http://example.com/search?q=test&lang=en">Search</a>
                <a href="/relative?param=value">Relative</a>
            </body>
        </html>
        """
        
        base_url = 'http://example.com/'
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_links(soup, base_url)
        
        # Should discover multiple parameters
        self.assertGreater(len(params), 0)
        
        # Check for specific parameters
        param_names = [p.name for p in params]
        self.assertIn('id', param_names)
        self.assertIn('type', param_names)
        self.assertIn('q', param_names)
        self.assertIn('lang', param_names)
        
        # All link params should be GET
        for param in params:
            self.assertEqual(param.method, 'GET')
            self.assertEqual(param.source, 'link')
    
    def test_discover_from_inline_js_variables(self):
        """Test discovering parameters from JavaScript variables"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <script>
                    var userId = "12345";
                    let apiKey = "key_abcdef";
                    const sessionToken = "token_xyz";
                    var endpoint = "/api/data";
                </script>
            </body>
        </html>
        """
        
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_inline_js(soup)
        
        # Should discover JS variables
        param_names = [p.name for p in params]
        self.assertIn('userId', param_names)
        self.assertIn('apiKey', param_names)
        self.assertIn('sessionToken', param_names)
        
        # Check values are extracted
        user_id_param = next(p for p in params if p.name == 'userId')
        self.assertEqual(user_id_param.value, '12345')
        self.assertEqual(user_id_param.source, 'js')
    
    def test_discover_from_inline_js_parameter_patterns(self):
        """Test discovering parameter names from JS code patterns"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <script>
                    var url = "/api?userId=123&token=abc";
                    data.get("articleId");
                    params["categoryId"] = 5;
                    request.getParameter("searchQuery");
                </script>
            </body>
        </html>
        """
        
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_inline_js(soup)
        
        # Should discover parameter names from patterns
        param_names = [p.name for p in params]
        self.assertIn('userId', param_names)
        self.assertIn('token', param_names)
        self.assertIn('articleId', param_names)
        self.assertIn('categoryId', param_names)
        self.assertIn('searchQuery', param_names)
    
    def test_discover_from_url(self):
        """Test discovering parameters from the URL itself"""
        url = 'http://example.com/page?id=123&category=news&sort=date'
        
        params = self.engine._discover_from_url(url)
        
        self.assertEqual(len(params), 3)
        
        # Check parameters
        id_param = next(p for p in params if p.name == 'id')
        self.assertEqual(id_param.value, '123')
        self.assertEqual(id_param.source, 'url')
        self.assertEqual(id_param.method, 'GET')
        
        category_param = next(p for p in params if p.name == 'category')
        self.assertEqual(category_param.value, 'news')
    
    def test_is_likely_parameter_filters_common_vars(self):
        """Test filtering of common non-parameter variables"""
        # Should accept these
        self.assertTrue(self.engine._is_likely_parameter('userId'))
        self.assertTrue(self.engine._is_likely_parameter('apiKey'))
        self.assertTrue(self.engine._is_likely_parameter('searchQuery'))
        
        # Should reject these
        self.assertFalse(self.engine._is_likely_parameter('i'))
        self.assertFalse(self.engine._is_likely_parameter('window'))
        self.assertFalse(self.engine._is_likely_parameter('document'))
        self.assertFalse(self.engine._is_likely_parameter('this'))
        self.assertFalse(self.engine._is_likely_parameter('error'))
        self.assertFalse(self.engine._is_likely_parameter('function'))
    
    def test_deduplicate_parameters(self):
        """Test deduplication of parameters"""
        params = [
            DiscoveredParameter('id', '1', 'form', 'GET'),
            DiscoveredParameter('id', '2', 'link', 'GET'),  # Duplicate
            DiscoveredParameter('name', 'test', 'form', 'GET'),
            DiscoveredParameter('id', '3', 'hidden', 'POST'),  # Different method
        ]
        
        unique_params = self.engine._deduplicate_parameters(params)
        
        # Should have 3 unique parameters (id-GET, name-GET, id-POST)
        self.assertEqual(len(unique_params), 3)
        
        # First occurrence should be kept
        id_get = next(p for p in unique_params if p.name == 'id' and p.method == 'GET')
        self.assertEqual(id_get.value, '1')  # First value kept
    
    def test_create_merged_params(self):
        """Test creating merged parameter dictionary"""
        params = [
            DiscoveredParameter('search', 'query', 'link', 'GET'),
            DiscoveredParameter('page', '1', 'url', 'GET'),
            DiscoveredParameter('username', 'admin', 'form', 'POST'),
            DiscoveredParameter('token', 'abc', 'hidden', 'POST'),
        ]
        
        merged = self.engine._create_merged_params(params)
        
        # Should have GET and POST dicts
        self.assertIn('GET', merged)
        self.assertIn('POST', merged)
        
        # Check GET params
        self.assertIn('search', merged['GET'])
        self.assertIn('page', merged['GET'])
        self.assertEqual(merged['GET']['search'], 'query')
        
        # Check POST params
        self.assertIn('username', merged['POST'])
        self.assertIn('token', merged['POST'])
        self.assertEqual(merged['POST']['token'], 'abc')
    
    @patch('sql_attacker.param_discovery.requests.Session.get')
    def test_discover_parameters_integration(self, mock_get):
        """Test full parameter discovery integration"""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
            <body>
                <form method="POST">
                    <input type="text" name="username" value="">
                    <input type="hidden" name="csrf" value="token123">
                </form>
                <a href="/page?id=1">Link</a>
                <script>
                    var apiKey = "key_abc";
                </script>
            </body>
        </html>
        """
        mock_get.return_value = mock_response
        
        url = 'http://example.com/test?search=query'
        merged_params, discovered_params = self.engine.discover_parameters(url)
        
        # Should discover multiple parameters
        self.assertGreater(len(discovered_params), 0)
        
        # Should have both GET and POST params
        self.assertIn('GET', merged_params)
        self.assertIn('POST', merged_params)
        
        # Check for expected parameters
        param_names = [p.name for p in discovered_params]
        self.assertIn('username', param_names)
        self.assertIn('csrf', param_names)
        self.assertIn('id', param_names)
        self.assertIn('search', param_names)
        self.assertIn('apiKey', param_names)
    
    @patch('sql_attacker.param_discovery.requests.Session.get')
    def test_discover_parameters_handles_errors(self, mock_get):
        """Test that parameter discovery handles errors gracefully"""
        # Mock HTTP error
        mock_get.side_effect = Exception("Connection error")
        
        url = 'http://example.com/test'
        merged_params, discovered_params = self.engine.discover_parameters(url)
        
        # Should return empty results on error
        self.assertEqual(len(discovered_params), 0)
        self.assertEqual(merged_params, {})
    
    @patch('sql_attacker.param_discovery.requests.Session.get')
    def test_discover_parameters_non_200_status(self, mock_get):
        """Test handling of non-200 status codes"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        url = 'http://example.com/notfound'
        merged_params, discovered_params = self.engine.discover_parameters(url)
        
        # Should return empty results for non-200
        self.assertEqual(len(discovered_params), 0)
        self.assertEqual(merged_params, {})

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_private_ip_skips_request(self, mock_dns):
        """Hostname resolving to an RFC1918 private IP should fast-fail without an HTTP request"""
        mock_dns.return_value = '10.15.250.220'  # RFC1918 address

        url = 'https://internal.example.com/page?id=1'
        with patch.object(self.engine.session, 'get') as mock_get:
            merged_params, discovered_params = self.engine.discover_parameters(url)
            mock_get.assert_not_called()

        self.assertEqual(merged_params, {})
        self.assertEqual(discovered_params, [])

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_loopback_ip_skips_request(self, mock_dns):
        """Hostname resolving to loopback (127.x) should fast-fail"""
        mock_dns.return_value = '127.0.0.1'

        url = 'http://localhost/page'
        with patch.object(self.engine.session, 'get') as mock_get:
            merged_params, discovered_params = self.engine.discover_parameters(url)
            mock_get.assert_not_called()

        self.assertEqual(merged_params, {})
        self.assertEqual(discovered_params, [])

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_public_ip_proceeds(self, mock_dns):
        """Hostname resolving to a public IP should proceed with the HTTP request"""
        mock_dns.return_value = '93.184.216.34'  # example.com public IP

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><body></body></html>'

        with patch.object(self.engine.session, 'get', return_value=mock_response) as mock_get:
            merged_params, discovered_params = self.engine.discover_parameters(
                'http://example.com/page?id=1'
            )
            mock_get.assert_called_once()

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_connect_timeout(self, mock_dns):
        """ConnectTimeout should be handled gracefully and return empty results"""
        mock_dns.return_value = '93.184.216.34'

        with patch.object(
            self.engine.session,
            'get',
            side_effect=requests.exceptions.ConnectTimeout(),
        ):
            merged_params, discovered_params = self.engine.discover_parameters(
                'https://example.com/page'
            )

        self.assertEqual(merged_params, {})
        self.assertEqual(discovered_params, [])

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_read_timeout(self, mock_dns):
        """ReadTimeout should be handled gracefully and return empty results"""
        mock_dns.return_value = '93.184.216.34'

        with patch.object(
            self.engine.session,
            'get',
            side_effect=requests.exceptions.ReadTimeout(),
        ):
            merged_params, discovered_params = self.engine.discover_parameters(
                'https://example.com/page'
            )

        self.assertEqual(merged_params, {})
        self.assertEqual(discovered_params, [])

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_connection_error(self, mock_dns):
        """ConnectionError should be handled gracefully and return empty results"""
        mock_dns.return_value = '93.184.216.34'

        with patch.object(
            self.engine.session,
            'get',
            side_effect=requests.exceptions.ConnectionError('refused'),
        ):
            merged_params, discovered_params = self.engine.discover_parameters(
                'https://example.com/page'
            )

        self.assertEqual(merged_params, {})
        self.assertEqual(discovered_params, [])

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_ssl_error(self, mock_dns):
        """SSLError should be handled gracefully and return empty results"""
        mock_dns.return_value = '93.184.216.34'

        with patch.object(
            self.engine.session,
            'get',
            side_effect=requests.exceptions.SSLError('cert verify failed'),
        ):
            merged_params, discovered_params = self.engine.discover_parameters(
                'https://example.com/page'
            )

        self.assertEqual(merged_params, {})
        self.assertEqual(discovered_params, [])

    @patch('sql_attacker.param_discovery.socket.gethostbyname')
    def test_discover_parameters_dns_failure_proceeds(self, mock_dns):
        """If DNS resolution fails, discovery should proceed (let requests handle it)"""
        mock_dns.side_effect = socket.gaierror('Name or service not known')

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><body></body></html>'

        with patch.object(self.engine.session, 'get', return_value=mock_response) as mock_get:
            self.engine.discover_parameters('http://nonexistent.invalid/page')
            mock_get.assert_called_once()


class ParameterDiscoveryComplexCasesTest(TestCase):
    """Test complex parameter discovery scenarios"""
    
    def setUp(self):
        """Set up test engine"""
        self.engine = ParameterDiscoveryEngine()
    
    def test_discover_complex_form(self):
        """Test discovery from complex form with multiple field types"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <form method="POST">
                    <input type="text" name="email" value="user@example.com">
                    <input type="checkbox" name="remember" value="1">
                    <input type="radio" name="gender" value="M">
                    <input type="radio" name="gender" value="F">
                    <input type="file" name="avatar">
                    <input type="hidden" name="redirect" value="/dashboard">
                    <button type="submit">Submit</button>
                </form>
            </body>
        </html>
        """
        
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_forms(soup)
        
        # Should discover all input fields with names
        param_names = [p.name for p in params]
        self.assertIn('email', param_names)
        self.assertIn('remember', param_names)
        self.assertIn('gender', param_names)
        self.assertIn('avatar', param_names)
        self.assertIn('redirect', param_names)
        
        # Check hidden field is identified
        redirect_param = next(p for p in params if p.name == 'redirect')
        self.assertEqual(redirect_param.source, 'hidden')
    
    def test_discover_multiple_forms(self):
        """Test discovery from multiple forms"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <form id="login" method="POST">
                    <input type="text" name="username">
                    <input type="password" name="password">
                </form>
                <form id="search" method="GET">
                    <input type="text" name="q">
                    <input type="text" name="filter">
                </form>
            </body>
        </html>
        """
        
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_forms(soup)
        
        # Should discover from both forms
        self.assertEqual(len(params), 4)
        
        # Check POST params
        post_params = [p for p in params if p.method == 'POST']
        self.assertEqual(len(post_params), 2)
        
        # Check GET params
        get_params = [p for p in params if p.method == 'GET']
        self.assertEqual(len(get_params), 2)
    
    def test_discover_from_script_sources(self):
        """Test discovery from script and image sources"""
        from bs4 import BeautifulSoup
        
        html = """
        <html>
            <body>
                <script src="/js/app.js?version=1.2.3&debug=true"></script>
                <img src="/img/logo.png?size=large&format=webp">
                <iframe src="/embed?video_id=abc123"></iframe>
            </body>
        </html>
        """
        
        base_url = 'http://example.com/'
        soup = BeautifulSoup(html, 'html.parser')
        params = self.engine._discover_from_links(soup, base_url)
        
        # Should discover parameters from src attributes
        param_names = [p.name for p in params]
        self.assertIn('version', param_names)
        self.assertIn('debug', param_names)
        self.assertIn('size', param_names)
        self.assertIn('format', param_names)
        self.assertIn('video_id', param_names)
