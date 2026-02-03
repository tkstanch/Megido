from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

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
