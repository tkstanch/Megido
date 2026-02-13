from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from .models import (
    ProxyRequest, ProxyResponse, ProxyConfiguration,
    WebSocketMessage, ProxyError, AuthenticationAttempt
)
from .replay_utils import RequestReplayer
from .logging_utils import ProxyLogger
import json
import tempfile
import shutil
from pathlib import Path


User = get_user_model()


class ProxyRequestModelTest(TestCase):
    """Test ProxyRequest model"""
    
    def setUp(self):
        self.request = ProxyRequest.objects.create(
            url='https://api.example.com/users',
            method='GET',
            headers='{"User-Agent": "Test"}',
            body='',
            host='api.example.com',
            port=443,
            protocol='HTTPS',
            source_ip='192.168.1.100',
            request_size=256,
            user_agent='Test Agent'
        )
    
    def test_request_creation(self):
        """Test request is created correctly"""
        self.assertEqual(self.request.method, 'GET')
        self.assertEqual(self.request.protocol, 'HTTPS')
        self.assertEqual(self.request.source_ip, '192.168.1.100')
    
    def test_get_headers_dict(self):
        """Test headers parsing"""
        headers = self.request.get_headers_dict()
        self.assertIsInstance(headers, dict)
        self.assertEqual(headers.get('User-Agent'), 'Test')
    
    def test_replay_tracking(self):
        """Test replay relationship"""
        replay = ProxyRequest.objects.create(
            url=self.request.url,
            method=self.request.method,
            headers=self.request.headers,
            body=self.request.body,
            host=self.request.host,
            port=self.request.port,
            is_replay=True,
            original_request=self.request
        )
        
        self.assertTrue(replay.is_replay)
        self.assertEqual(replay.original_request, self.request)


class ProxyResponseModelTest(TestCase):
    """Test ProxyResponse model"""
    
    def setUp(self):
        self.request = ProxyRequest.objects.create(
            url='https://api.example.com/users',
            method='GET',
            headers='{}',
            body='',
            host='api.example.com',
            port=443
        )
        
        self.response = ProxyResponse.objects.create(
            request=self.request,
            status_code=200,
            headers='{"Content-Type": "application/json"}',
            body='{"users": []}',
            response_time=123.45,
            response_size=1024
        )
    
    def test_response_creation(self):
        """Test response is created correctly"""
        self.assertEqual(self.response.status_code, 200)
        self.assertEqual(self.response.response_time, 123.45)
        self.assertEqual(self.response.request, self.request)
    
    def test_response_relationship(self):
        """Test one-to-one relationship"""
        self.assertTrue(hasattr(self.request, 'response'))
        self.assertEqual(self.request.response, self.response)


class WebSocketMessageModelTest(TestCase):
    """Test WebSocketMessage model"""
    
    def test_websocket_message_creation(self):
        """Test WebSocket message creation"""
        message = WebSocketMessage.objects.create(
            connection_id='ws_12345',
            url='wss://api.example.com/socket',
            direction='SEND',
            message_type='TEXT',
            payload='{"type": "ping"}',
            payload_size=16,
            source_ip='192.168.1.100'
        )
        
        self.assertEqual(message.direction, 'SEND')
        self.assertEqual(message.message_type, 'TEXT')
        self.assertEqual(message.connection_id, 'ws_12345')


class ProxyErrorModelTest(TestCase):
    """Test ProxyError model"""
    
    def test_error_creation(self):
        """Test error logging"""
        error = ProxyError.objects.create(
            error_type='TIMEOUT',
            error_message='Connection timed out',
            url='https://api.example.com/slow',
            source_ip='192.168.1.100'
        )
        
        self.assertEqual(error.error_type, 'TIMEOUT')
        self.assertIn('timed out', error.error_message)


class ProxyConfigurationModelTest(TestCase):
    """Test ProxyConfiguration model"""
    
    def test_config_creation(self):
        """Test configuration creation"""
        config = ProxyConfiguration.objects.create(
            auth_enabled=True,
            auth_token='test-token',
            logging_enabled=True,
            websocket_enabled=True
        )
        
        self.assertTrue(config.auth_enabled)
        self.assertEqual(config.auth_token, 'test-token')
    
    def test_ip_whitelist_parsing(self):
        """Test IP whitelist parsing"""
        config = ProxyConfiguration.objects.create(
            ip_whitelist='192.168.1.100, 10.0.0.50, 172.16.0.1'
        )
        
        ips = config.get_whitelist_ips()
        self.assertEqual(len(ips), 3)
        self.assertIn('192.168.1.100', ips)
        self.assertIn('10.0.0.50', ips)


class ProxyViewsTest(TestCase):
    """Test proxy API views"""
    
    def setUp(self):
        self.client = Client()
        
        # Create test requests
        for i in range(5):
            ProxyRequest.objects.create(
                url=f'https://api.example.com/endpoint{i}',
                method='GET',
                headers='{}',
                body='',
                host='api.example.com',
                port=443
            )
    
    def test_list_requests(self):
        """Test listing requests"""
        response = self.client.get('/proxy/api/requests/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        data = response.json()
        self.assertIn('requests', data)
        self.assertEqual(data['total'], 5)
    
    def test_list_requests_with_filters(self):
        """Test listing with filters"""
        response = self.client.get('/proxy/api/requests/?method=GET&limit=2')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        data = response.json()
        self.assertLessEqual(len(data['requests']), 2)
    
    def test_get_request_detail(self):
        """Test getting request details"""
        request = ProxyRequest.objects.first()
        response = self.client.get(f'/proxy/api/requests/{request.id}/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data['id'], request.id)
        self.assertEqual(data['method'], 'GET')
    
    def test_create_request(self):
        """Test creating request via API"""
        data = {
            'url': 'https://test.example.com/api',
            'method': 'POST',
            'headers': '{"Content-Type": "application/json"}',
            'body': '{"test": true}',
            'host': 'test.example.com',
            'port': 443,
            'protocol': 'HTTPS',
            'source_ip': '192.168.1.100'
        }
        
        response = self.client.post(
            '/proxy/api/requests/',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.json())
    
    def test_create_response(self):
        """Test creating response via API"""
        request = ProxyRequest.objects.first()
        
        data = {
            'request': request.id,
            'status_code': 200,
            'headers': '{}',
            'body': '{"success": true}',
            'response_time': 150.5,
            'response_size': 18
        }
        
        response = self.client.post(
            '/proxy/api/responses/',
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    
    def test_proxy_stats(self):
        """Test statistics endpoint"""
        response = self.client.get('/proxy/api/stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        data = response.json()
        self.assertIn('total_requests', data)
        self.assertEqual(data['total_requests'], 5)


class RequestReplayerTest(TestCase):
    """Test request replay functionality"""
    
    def setUp(self):
        self.replayer = RequestReplayer(verify_ssl=False)
    
    def test_filter_headers(self):
        """Test header filtering"""
        headers = {
            'User-Agent': 'Test',
            'Host': 'example.com',
            'Content-Type': 'application/json',
            'Connection': 'keep-alive'
        }
        
        filtered = self.replayer._filter_headers(headers)
        
        self.assertIn('User-Agent', filtered)
        self.assertIn('Content-Type', filtered)
        self.assertNotIn('Host', filtered)  # Should be excluded
        self.assertNotIn('Connection', filtered)  # Should be excluded
    
    def test_modify_url_for_testing(self):
        """Test URL modification for testing"""
        original = 'https://api.example.com/users?page=1'
        modified = self.replayer.modify_url_for_testing(
            original,
            test_host='localhost',
            test_port=3000,
            use_https=False
        )
        
        self.assertIn('localhost:3000', modified)
        self.assertIn('page=1', modified)
        self.assertTrue(modified.startswith('http://'))


class ProxyLoggerTest(TestCase):
    """Test logging utility"""
    
    def setUp(self):
        # Create temporary log directory
        self.temp_dir = tempfile.mkdtemp()
        self.logger = ProxyLogger(log_directory=self.temp_dir)
    
    def tearDown(self):
        # Clean up temporary directory
        shutil.rmtree(self.temp_dir)
    
    def test_log_directory_creation(self):
        """Test log directories are created"""
        log_path = Path(self.temp_dir)
        self.assertTrue(log_path.exists())
        self.assertTrue((log_path / 'requests').exists())
        self.assertTrue((log_path / 'responses').exists())
        self.assertTrue((log_path / 'websockets').exists())
        self.assertTrue((log_path / 'errors').exists())
        self.assertTrue((log_path / 'auth').exists())
    
    def test_log_request(self):
        """Test request logging"""
        request_data = {
            'id': 123,
            'url': 'https://api.example.com/test',
            'method': 'GET',
            'source_ip': '192.168.1.100',
            'protocol': 'HTTPS'
        }
        
        filepath = self.logger.log_request(request_data)
        self.assertTrue(Path(filepath).exists())
        
        # Read and verify log file
        with open(filepath, 'r') as f:
            logged = json.load(f)
            self.assertEqual(logged['id'], 123)
            self.assertEqual(logged['method'], 'GET')
            self.assertEqual(logged['type'], 'request')
    
    def test_log_response(self):
        """Test response logging"""
        response_data = {
            'id': 456,
            'request_id': 123,
            'status_code': 200,
            'response_time': 150.5
        }
        
        filepath = self.logger.log_response(response_data)
        self.assertTrue(Path(filepath).exists())
    
    def test_log_websocket(self):
        """Test WebSocket logging"""
        ws_data = {
            'connection_id': 'ws_12345',
            'direction': 'SEND',
            'message_type': 'TEXT'
        }
        
        filepath = self.logger.log_websocket(ws_data)
        self.assertTrue(Path(filepath).exists())
        
        # Verify connection-specific directory created
        conn_dir = Path(self.temp_dir) / 'websockets' / 'ws_12345'
        self.assertTrue(conn_dir.exists())
    
    def test_log_error(self):
        """Test error logging"""
        error_data = {
            'error_type': 'TIMEOUT',
            'error_message': 'Connection timed out'
        }
        
        filepath = self.logger.log_error(error_data)
        self.assertTrue(Path(filepath).exists())
    
    def test_get_recent_logs(self):
        """Test retrieving recent logs"""
        # Create some test logs
        for i in range(3):
            self.logger.log_request({
                'id': i,
                'url': f'https://test.com/{i}',
                'method': 'GET'
            })
        
        # Retrieve logs
        logs = self.logger.get_recent_logs('requests', limit=2)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]['type'], 'request')


class AuthenticationAttemptTest(TestCase):
    """Test authentication attempt logging"""
    
    def test_auth_attempt_creation(self):
        """Test logging auth attempts"""
        attempt = AuthenticationAttempt.objects.create(
            username='testuser',
            source_ip='192.168.1.100',
            success=True
        )
        
        self.assertTrue(attempt.success)
        self.assertEqual(attempt.username, 'testuser')
    
    def test_failed_auth_attempt(self):
        """Test logging failed auth attempts"""
        attempt = AuthenticationAttempt.objects.create(
            username='baduser',
            source_ip='192.168.1.200',
            success=False,
            failure_reason='Invalid credentials'
        )
        
        self.assertFalse(attempt.success)
        self.assertEqual(attempt.failure_reason, 'Invalid credentials')


class ProxyIntegrationTest(TestCase):
    """Integration tests for complete proxy workflow"""
    
    def test_complete_request_response_cycle(self):
        """Test complete request-response logging cycle"""
        # Create request
        request = ProxyRequest.objects.create(
            url='https://api.example.com/users',
            method='GET',
            headers='{}',
            body='',
            host='api.example.com',
            port=443,
            source_ip='192.168.1.100'
        )
        
        # Create response
        response = ProxyResponse.objects.create(
            request=request,
            status_code=200,
            headers='{}',
            body='{"users": []}',
            response_time=100.0
        )
        
        # Verify relationship
        self.assertEqual(request.response, response)
        self.assertEqual(response.request, request)
        
        # Test via API
        api_response = self.client.get(f'/proxy/api/requests/{request.id}/')
        self.assertEqual(api_response.status_code, status.HTTP_200_OK)
        
        data = api_response.json()
        self.assertIn('response', data)
        self.assertEqual(data['response']['status_code'], 200)
    
    def test_websocket_connection_lifecycle(self):
        """Test WebSocket connection tracking"""
        connection_id = 'ws_test_12345'
        
        # Create messages
        WebSocketMessage.objects.create(
            connection_id=connection_id,
            url='wss://api.example.com/ws',
            direction='SEND',
            message_type='TEXT',
            payload='{"type": "subscribe"}',
            payload_size=22
        )
        
        WebSocketMessage.objects.create(
            connection_id=connection_id,
            url='wss://api.example.com/ws',
            direction='RECEIVE',
            message_type='TEXT',
            payload='{"type": "ack"}',
            payload_size=15
        )
        
        # Query messages
        messages = WebSocketMessage.objects.filter(connection_id=connection_id)
        self.assertEqual(messages.count(), 2)
        
        send_msg = messages.filter(direction='SEND').first()
        self.assertEqual(send_msg.message_type, 'TEXT')
    
    def test_error_handling_workflow(self):
        """Test error logging workflow"""
        # Create request
        request = ProxyRequest.objects.create(
            url='https://slow.example.com/api',
            method='GET',
            headers='{}',
            body='',
            host='slow.example.com',
            port=443
        )
        
        # Log error
        error = ProxyError.objects.create(
            error_type='TIMEOUT',
            error_message='Request timed out after 30 seconds',
            url=request.url,
            request=request
        )
        
        # Verify error is linked to request
        self.assertEqual(error.request, request)
        self.assertTrue(request.errors.exists())
        self.assertEqual(request.errors.first().error_type, 'TIMEOUT')

