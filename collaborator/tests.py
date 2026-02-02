from django.test import TestCase, Client
from django.urls import reverse
from .models import CollaboratorServer, Interaction
import json


class CollaboratorServerModelTest(TestCase):
    def test_create_server(self):
        """Test creating a collaborator server"""
        server = CollaboratorServer.objects.create(
            domain='test.example.com',
            ip_address='192.168.1.1',
            description='Test server'
        )
        self.assertEqual(server.domain, 'test.example.com')
        self.assertEqual(server.ip_address, '192.168.1.1')
        self.assertTrue(server.is_active)
        
    def test_server_string_representation(self):
        """Test server string representation"""
        server = CollaboratorServer.objects.create(
            domain='test.example.com',
            ip_address='192.168.1.1'
        )
        self.assertIn('test.example.com', str(server))


class InteractionModelTest(TestCase):
    def setUp(self):
        self.server = CollaboratorServer.objects.create(
            domain='test.example.com',
            ip_address='192.168.1.1'
        )
        
    def test_create_http_interaction(self):
        """Test creating an HTTP interaction"""
        interaction = Interaction.objects.create(
            server=self.server,
            interaction_type='http',
            source_ip='10.0.0.1',
            raw_data='GET / HTTP/1.1',
            http_method='GET',
            http_path='/',
            http_headers='Host: test.example.com'
        )
        self.assertEqual(interaction.interaction_type, 'http')
        self.assertEqual(interaction.source_ip, '10.0.0.1')
        self.assertEqual(interaction.http_method, 'GET')
        
    def test_create_dns_interaction(self):
        """Test creating a DNS interaction"""
        interaction = Interaction.objects.create(
            server=self.server,
            interaction_type='dns',
            source_ip='10.0.0.1',
            raw_data='DNS Query',
            dns_query_type='A',
            dns_query_name='test.example.com'
        )
        self.assertEqual(interaction.interaction_type, 'dns')
        self.assertEqual(interaction.dns_query_type, 'A')


class CollaboratorAPITest(TestCase):
    def setUp(self):
        self.client = Client()
        
    def test_list_servers(self):
        """Test listing collaborator servers"""
        CollaboratorServer.objects.create(
            domain='test1.example.com',
            ip_address='192.168.1.1'
        )
        CollaboratorServer.objects.create(
            domain='test2.example.com',
            ip_address='192.168.1.2'
        )
        
        response = self.client.get('/collaborator/api/servers/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 2)
        
    def test_create_server(self):
        """Test creating a server via API"""
        data = {
            'domain': 'api-test.example.com',
            'ip_address': '192.168.1.10',
            'description': 'API test server'
        }
        response = self.client.post(
            '/collaborator/api/servers/',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(CollaboratorServer.objects.filter(domain='api-test.example.com').exists())
        
    def test_get_server_detail(self):
        """Test getting server details"""
        server = CollaboratorServer.objects.create(
            domain='test.example.com',
            ip_address='192.168.1.1'
        )
        
        response = self.client.get(f'/collaborator/api/servers/{server.id}/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['domain'], 'test.example.com')
        
    def test_log_interaction(self):
        """Test logging an interaction"""
        server = CollaboratorServer.objects.create(
            domain='test.example.com',
            ip_address='192.168.1.1'
        )
        
        data = {
            'interaction_type': 'http',
            'source_ip': '10.0.0.1',
            'raw_data': 'GET / HTTP/1.1',
            'http_method': 'GET',
            'http_path': '/'
        }
        response = self.client.post(
            f'/collaborator/api/servers/{server.id}/interactions/log/',
            data=json.dumps(data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Interaction.objects.count(), 1)
        
    def test_get_interactions(self):
        """Test getting interactions for a server"""
        server = CollaboratorServer.objects.create(
            domain='test.example.com',
            ip_address='192.168.1.1'
        )
        Interaction.objects.create(
            server=server,
            interaction_type='http',
            source_ip='10.0.0.1',
            raw_data='GET / HTTP/1.1',
            http_method='GET',
            http_path='/'
        )
        
        response = self.client.get(f'/collaborator/api/servers/{server.id}/interactions/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        
    def test_clear_interactions(self):
        """Test clearing interactions"""
        server = CollaboratorServer.objects.create(
            domain='test.example.com',
            ip_address='192.168.1.1'
        )
        Interaction.objects.create(
            server=server,
            interaction_type='http',
            source_ip='10.0.0.1',
            raw_data='test'
        )
        
        response = self.client.delete(f'/collaborator/api/servers/{server.id}/interactions/clear/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(server.interactions.count(), 0)


class CollaboratorViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
        
    def test_dashboard_view(self):
        """Test dashboard renders correctly"""
        response = self.client.get('/collaborator/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Collaborator')
        self.assertContains(response, 'Configure Collaborator Server')
