from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch
import json

from .models import (
    ScanTarget, ScanResult, PortScan, ServiceDetection,
    OSFingerprint, PacketCapture, StealthConfiguration, ScanLog
)
from .engine import (
    HostDiscovery, PortScanner, ServiceDetector,
    OSFingerprinter, PacketAnalyzer, StealthManager
)


class ScanTargetTestCase(TestCase):
    """Test ScanTarget model."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
    
    def test_scan_target_creation(self):
        """Test creating a scan target."""
        scan = ScanTarget.objects.create(
            target='192.168.1.1',
            created_by=self.user,
            scan_type='comprehensive',
            stealth_mode=True,
            notes='Test scan'
        )
        
        self.assertEqual(scan.target, '192.168.1.1')
        self.assertEqual(scan.status, 'pending')
        self.assertTrue(scan.stealth_mode)
    
    def test_scan_target_string_representation(self):
        """Test string representation of scan target."""
        scan = ScanTarget.objects.create(
            target='example.com',
            created_by=self.user,
            status='running'
        )
        
        self.assertEqual(str(scan), 'example.com - running')


class ScanResultTestCase(TestCase):
    """Test ScanResult model."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
        self.scan_target = ScanTarget.objects.create(
            target='192.168.1.1',
            created_by=self.user
        )
    
    def test_scan_result_creation(self):
        """Test creating a scan result."""
        result = ScanResult.objects.create(
            scan_target=self.scan_target,
            host_discovered=True,
            open_ports_count=5
        )
        
        self.assertTrue(result.host_discovered)
        self.assertEqual(result.open_ports_count, 5)
    
    def test_scan_duration_calculation(self):
        """Test scan duration calculation."""
        result = ScanResult.objects.create(
            scan_target=self.scan_target,
            started_at=timezone.now(),
            completed_at=timezone.now() + timedelta(seconds=30)
        )
        
        result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
        result.save()
        
        self.assertGreater(result.duration_seconds, 29)  # Allow for timing precision


class PortScanTestCase(TestCase):
    """Test PortScan model."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
        self.scan_target = ScanTarget.objects.create(
            target='192.168.1.1',
            created_by=self.user
        )
        self.scan_result = ScanResult.objects.create(
            scan_target=self.scan_target
        )
    
    def test_port_scan_creation(self):
        """Test creating a port scan result."""
        port_scan = PortScan.objects.create(
            scan_result=self.scan_result,
            port=80,
            protocol='tcp',
            state='open',
            scan_type='syn'
        )
        
        self.assertEqual(port_scan.port, 80)
        self.assertEqual(port_scan.state, 'open')


class ServiceDetectionTestCase(TestCase):
    """Test ServiceDetection model."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
        self.scan_target = ScanTarget.objects.create(
            target='192.168.1.1',
            created_by=self.user
        )
        self.scan_result = ScanResult.objects.create(
            scan_target=self.scan_target
        )
        self.port_scan = PortScan.objects.create(
            scan_result=self.scan_result,
            port=80,
            protocol='tcp',
            state='open',
            scan_type='connect'
        )
    
    def test_service_detection_creation(self):
        """Test creating service detection result."""
        service = ServiceDetection.objects.create(
            port_scan=self.port_scan,
            service_name='http',
            service_version='2.4.41',
            product='Apache',
            confidence=90
        )
        
        self.assertEqual(service.service_name, 'http')
        self.assertEqual(service.confidence, 90)


class OSFingerprintTestCase(TestCase):
    """Test OSFingerprint model."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
        self.scan_target = ScanTarget.objects.create(
            target='192.168.1.1',
            created_by=self.user
        )
        self.scan_result = ScanResult.objects.create(
            scan_target=self.scan_target
        )
    
    def test_os_fingerprint_creation(self):
        """Test creating OS fingerprint result."""
        os_fp = OSFingerprint.objects.create(
            scan_result=self.scan_result,
            os_name='Linux',
            os_family='linux',
            accuracy=85,
            fingerprint_method='tcp_ip_stack'
        )
        
        self.assertEqual(os_fp.os_name, 'Linux')
        self.assertEqual(os_fp.accuracy, 85)


class HostDiscoveryTestCase(TestCase):
    """Test HostDiscovery engine."""
    
    def test_host_discovery_initialization(self):
        """Test host discovery initialization."""
        discovery = HostDiscovery()
        
        self.assertIsNotNone(discovery)
        self.assertEqual(len(discovery.discovery_results), 0)
    
    def test_parse_single_ip(self):
        """Test parsing single IP address."""
        discovery = HostDiscovery()
        ips = discovery._parse_target_range('192.168.1.1')
        
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0], '192.168.1.1')
    
    def test_parse_ip_range(self):
        """Test parsing IP range."""
        discovery = HostDiscovery()
        ips = discovery._parse_target_range('192.168.1.1-5')
        
        self.assertGreater(len(ips), 0)
        self.assertIn('192.168.1.1', ips)

    def test_connection_refused_codes_are_treated_as_host_up(self):
        """Connection refused should be interpreted as host reachable across platforms."""
        discovery = HostDiscovery()
        self.assertTrue(discovery._is_connection_refused(111))
        self.assertTrue(discovery._is_connection_refused(10061))
        self.assertFalse(discovery._is_connection_refused(110))


class PortScannerTestCase(TestCase):
    """Test PortScanner engine."""
    
    def test_port_scanner_initialization(self):
        """Test port scanner initialization."""
        scanner = PortScanner()
        
        self.assertIsNotNone(scanner)
        self.assertEqual(len(scanner.scan_results), 0)
    
    def test_common_ports_list(self):
        """Test common ports list."""
        scanner = PortScanner()
        
        self.assertGreater(len(scanner.COMMON_PORTS), 0)
        self.assertIn(80, scanner.COMMON_PORTS)
        self.assertIn(443, scanner.COMMON_PORTS)


class ServiceDetectorTestCase(TestCase):
    """Test ServiceDetector engine."""
    
    def test_service_detector_initialization(self):
        """Test service detector initialization."""
        detector = ServiceDetector()
        
        self.assertIsNotNone(detector)
        self.assertEqual(len(detector.detection_results), 0)
    
    def test_service_signatures(self):
        """Test service signatures."""
        detector = ServiceDetector()
        
        self.assertIn(80, detector.SERVICE_SIGNATURES)
        self.assertIn(443, detector.SERVICE_SIGNATURES)
        self.assertIn(22, detector.SERVICE_SIGNATURES)


class OSFingerprinterTestCase(TestCase):
    """Test OSFingerprinter engine."""
    
    def test_os_fingerprinter_initialization(self):
        """Test OS fingerprinter initialization."""
        fingerprinter = OSFingerprinter()
        
        self.assertIsNotNone(fingerprinter)
        self.assertEqual(len(fingerprinter.fingerprint_results), 0)
    
    def test_os_signatures(self):
        """Test OS signatures."""
        fingerprinter = OSFingerprinter()
        
        self.assertIn('linux', fingerprinter.OS_SIGNATURES)
        self.assertIn('windows', fingerprinter.OS_SIGNATURES)


class PacketAnalyzerTestCase(TestCase):
    """Test PacketAnalyzer engine."""
    
    def test_packet_analyzer_initialization(self):
        """Test packet analyzer initialization."""
        analyzer = PacketAnalyzer()
        
        self.assertIsNotNone(analyzer)
        self.assertEqual(len(analyzer.captured_packets), 0)
    
    def test_determine_relevance(self):
        """Test packet relevance determination."""
        analyzer = PacketAnalyzer()
        
        # High relevance packet (SYN to port 80)
        packet_info = {
            'packet_type': 'tcp',
            'flags': ['SYN'],
            'destination_port': 80
        }
        
        relevance = analyzer._determine_relevance(packet_info)
        self.assertEqual(relevance, 'high')


class StealthManagerTestCase(TestCase):
    """Test StealthManager engine."""
    
    def test_stealth_manager_initialization(self):
        """Test stealth manager initialization."""
        manager = StealthManager(timing_template=2)
        
        self.assertIsNotNone(manager)
        self.assertEqual(manager.timing_template, 2)
    
    def test_timing_templates(self):
        """Test timing templates."""
        manager = StealthManager()
        
        self.assertIn(0, manager.TIMING_TEMPLATES)  # Paranoid
        self.assertIn(3, manager.TIMING_TEMPLATES)  # Normal
        self.assertIn(5, manager.TIMING_TEMPLATES)  # Insane
    
    def test_randomize_order(self):
        """Test target randomization."""
        manager = StealthManager()
        targets = [1, 2, 3, 4, 5]
        randomized = manager.randomize_target_order(targets)
        
        self.assertEqual(len(randomized), len(targets))
        self.assertEqual(set(randomized), set(targets))
    
    def test_decoy_ip_generation(self):
        """Test decoy IP generation."""
        manager = StealthManager()
        decoys = manager.generate_decoy_ips(count=5)
        
        self.assertEqual(len(decoys), 5)
        for ip in decoys:
            parts = ip.split('.')
            self.assertEqual(len(parts), 4)


class DataTracerViewsTestCase(TestCase):
    """Test Data Tracer views."""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
    
    def test_home_view(self):
        """Test home view."""
        response = self.client.get('/data-tracer/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Data Tracer')
    
    def test_create_scan_requires_login(self):
        """Test that create scan requires login."""
        response = self.client.get('/data-tracer/create/')
        
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_create_scan_authenticated(self):
        """Test create scan when authenticated."""
        self.client.login(username='testuser', password='testpass123!')
        response = self.client.get('/data-tracer/create/')
        
        self.assertEqual(response.status_code, 200)
    
    def test_scan_list_requires_login(self):
        """Test that scan list requires login."""
        response = self.client.get('/data-tracer/scans/')
        
        self.assertEqual(response.status_code, 302)  # Redirect to login

    @patch('data_tracer.views.OSFingerprinter')
    @patch('data_tracer.views.ServiceDetector')
    @patch('data_tracer.views.PortScanner')
    @patch('data_tracer.views.HostDiscovery')
    def test_execute_scan_records_discovered_host_results(
        self,
        mock_host_discovery_cls,
        mock_port_scanner_cls,
        mock_service_detector_cls,
        mock_os_fingerprinter_cls,
    ):
        """Execute scan should persist real discovered-host data and logs."""
        self.client.login(username='testuser', password='testpass123!')
        scan_target = ScanTarget.objects.create(
            target='localhost',
            created_by=self.user,
            scan_type='comprehensive',
            stealth_mode=False,
        )

        mock_host_discovery_cls.return_value.discover_hosts.return_value = [
            {'ip': '127.0.0.1', 'status': 'up', 'method': 'icmp_ping'}
        ]
        mock_port_scanner_cls.return_value.scan_ports.return_value = [
            {'port': 22, 'protocol': 'tcp', 'state': 'open', 'banner': 'OpenSSH'}
        ]
        mock_service_detector_cls.return_value.detect_service.return_value = {
            'service_name': 'ssh',
            'service_version': '9.0',
            'product': 'OpenSSH',
            'confidence': 95,
        }
        mock_os_fingerprinter_cls.return_value.fingerprint_os.return_value = [
            {'os_name': 'Linux', 'os_family': 'linux', 'accuracy': 90, 'method': 'tcp_ip_stack'}
        ]

        response = self.client.post(f'/data-tracer/scan/{scan_target.id}/execute/')
        self.assertEqual(response.status_code, 302)

        scan_result = ScanResult.objects.get(scan_target=scan_target)
        self.assertTrue(scan_result.host_discovered)
        self.assertEqual(scan_result.open_ports_count, 1)
        self.assertIn('Host is up', scan_result.summary)
        self.assertIn('open port(s) discovered', scan_result.summary)

        logs = list(scan_result.logs.values_list('message', flat=True))
        self.assertIn('Starting host discovery', logs)
        self.assertIn('Discovered 1 host(s)', logs)
        self.assertNotIn('No hosts discovered', logs)

        raw_data = json.loads(scan_result.raw_output)
        self.assertEqual(raw_data['scan_host'], '127.0.0.1')
        self.assertEqual(len(raw_data['discovered_hosts']), 1)

    def test_api_scan_result_includes_discovered_hosts(self):
        """API scan result should expose discovered hosts from raw output."""
        self.client.login(username='testuser', password='testpass123!')
        scan_target = ScanTarget.objects.create(
            target='127.0.0.1',
            created_by=self.user,
            status='completed',
        )
        scan_result = ScanResult.objects.create(
            scan_target=scan_target,
            host_discovered=True,
            open_ports_count=1,
            summary='Host is up. 1 open port(s) discovered',
            raw_output=json.dumps({
                'requested_target': '127.0.0.1',
                'scan_host': '127.0.0.1',
                'discovered_hosts': [{'ip': '127.0.0.1', 'status': 'up', 'method': 'tcp_connect_fallback'}],
            }),
        )
        PortScan.objects.create(
            scan_result=scan_result,
            port=80,
            protocol='tcp',
            state='open',
            scan_type='connect',
        )

        response = self.client.get(f'/data-tracer/api/result/{scan_result.id}/')
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload['host_discovered'])
        self.assertEqual(len(payload['discovered_hosts']), 1)
        self.assertEqual(payload['discovered_hosts'][0]['ip'], '127.0.0.1')
