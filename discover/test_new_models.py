"""
Tests for the new OSINT models added in the discover app.
"""
import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from discover.models import (
    Scan,
    Subdomain,
    DNSRecord,
    Certificate,
    Technology,
    EmailAddress,
    SocialProfile,
    CloudResource,
    PortService,
    ThreatIntelIndicator,
    ScanModule,
    CorrelationLink,
    ReconReport,
)


class TestScanModels(TestCase):
    """Tests for the original Scan model (sanity check)."""

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_scan_str(self):
        self.assertIn('example.com', str(self.scan))

    def test_scan_defaults(self):
        self.assertFalse(self.scan.sensitive_scan_completed)
        self.assertEqual(self.scan.total_findings, 0)


class TestSubdomainModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_subdomain(self):
        sub = Subdomain.objects.create(
            scan=self.scan,
            subdomain='api.example.com',
            ip_address='1.2.3.4',
            source='crt.sh',
        )
        self.assertEqual(str(sub), 'api.example.com')

    def test_subdomain_unique_together(self):
        Subdomain.objects.create(scan=self.scan, subdomain='api.example.com')
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            Subdomain.objects.create(scan=self.scan, subdomain='api.example.com')

    def test_subdomain_str(self):
        sub = Subdomain(subdomain='mail.example.com')
        self.assertEqual(str(sub), 'mail.example.com')


class TestDNSRecordModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_dns_record(self):
        record = DNSRecord.objects.create(
            scan=self.scan,
            record_type='A',
            name='example.com',
            value='1.2.3.4',
            ttl=300,
        )
        self.assertIn('A', str(record))
        self.assertIn('1.2.3.4', str(record))

    def test_all_record_types_valid(self):
        valid_types = [choice[0] for choice in DNSRecord.RECORD_TYPE_CHOICES]
        for rtype in valid_types:
            DNSRecord.objects.create(
                scan=self.scan,
                record_type=rtype,
                name=f'{rtype.lower()}.example.com',
                value='value',
            )
        self.assertEqual(DNSRecord.objects.filter(scan=self.scan).count(), len(valid_types))


class TestCertificateModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_certificate(self):
        cert = Certificate.objects.create(
            scan=self.scan,
            subject='CN=example.com',
            issuer="CN=Let's Encrypt",
            sans=json.dumps(['example.com', 'www.example.com']),
            is_expired=False,
            is_self_signed=False,
        )
        self.assertIn('CN=example.com', str(cert))

    def test_expired_certificate_flag(self):
        cert = Certificate.objects.create(
            scan=self.scan,
            subject='CN=old.example.com',
            is_expired=True,
        )
        self.assertTrue(cert.is_expired)


class TestTechnologyModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_technology(self):
        tech = Technology.objects.create(
            scan=self.scan,
            name='WordPress',
            category='CMS',
            confidence='high',
        )
        self.assertIn('WordPress', str(tech))

    def test_technology_unique_together(self):
        Technology.objects.create(scan=self.scan, name='Nginx', category='Server', url='https://example.com')
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            Technology.objects.create(scan=self.scan, name='Nginx', category='Server', url='https://example.com')


class TestEmailAddressModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_email(self):
        email = EmailAddress.objects.create(
            scan=self.scan,
            email='john.doe@example.com',
            source='hunter.io',
        )
        self.assertEqual(str(email), 'john.doe@example.com')

    def test_email_unique_together(self):
        EmailAddress.objects.create(scan=self.scan, email='test@example.com')
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            EmailAddress.objects.create(scan=self.scan, email='test@example.com')


class TestSocialProfileModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_social_profile(self):
        profile = SocialProfile.objects.create(
            scan=self.scan,
            platform='GitHub',
            username='exampleorg',
            url='https://github.com/exampleorg',
        )
        self.assertIn('GitHub', str(profile))
        self.assertIn('exampleorg', str(profile))


class TestCloudResourceModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_open_s3_bucket(self):
        resource = CloudResource.objects.create(
            scan=self.scan,
            resource_type='s3_bucket',
            name='example-backup',
            url='https://example-backup.s3.amazonaws.com/',
            access_level='open',
        )
        self.assertIn('AWS S3 Bucket', str(resource))

    def test_access_level_choices_valid(self):
        for choice_value, _ in CloudResource.ACCESS_CHOICES:
            CloudResource.objects.create(
                scan=self.scan,
                resource_type='s3_bucket',
                name=f'bucket-{choice_value}',
                url=f'https://bucket-{choice_value}.s3.amazonaws.com/',
                access_level=choice_value,
            )


class TestPortServiceModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_port_service(self):
        svc = PortService.objects.create(
            scan=self.scan,
            ip_address='1.2.3.4',
            port=443,
            protocol='tcp',
            service_name='https',
        )
        self.assertIn('1.2.3.4', str(svc))
        self.assertIn('443', str(svc))

    def test_unique_together(self):
        PortService.objects.create(scan=self.scan, ip_address='1.2.3.4', port=80, protocol='tcp')
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            PortService.objects.create(scan=self.scan, ip_address='1.2.3.4', port=80, protocol='tcp')


class TestThreatIntelIndicatorModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_threat_indicator(self):
        indicator = ThreatIntelIndicator.objects.create(
            scan=self.scan,
            indicator_type='domain',
            value='example.com',
            source='VirusTotal',
            threat_score=75,
            malicious_votes=5,
        )
        self.assertIn('75', str(indicator))
        self.assertIn('domain', str(indicator))


class TestScanModuleModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_scan_module(self):
        module = ScanModule.objects.create(
            scan=self.scan,
            module_name='dns',
            status='completed',
            items_found=42,
            duration_seconds=1.5,
        )
        self.assertIn('dns', str(module))
        self.assertIn('completed', str(module))

    def test_status_transitions(self):
        module = ScanModule.objects.create(
            scan=self.scan,
            module_name='subdomains',
            status='pending',
        )
        module.status = 'running'
        module.save()
        module.status = 'completed'
        module.save()
        refreshed = ScanModule.objects.get(pk=module.pk)
        self.assertEqual(refreshed.status, 'completed')


class TestCorrelationLinkModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_correlation_link(self):
        link = CorrelationLink.objects.create(
            scan=self.scan,
            link_type='domain_ip',
            source_entity='example.com',
            source_type='domain',
            target_entity='1.2.3.4',
            target_type='ip',
            confidence=1.0,
        )
        self.assertIn('example.com', str(link))
        self.assertIn('1.2.3.4', str(link))


class TestReconReportModel(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def test_create_recon_report(self):
        report = ReconReport.objects.create(
            scan=self.scan,
            title='Example Recon Report',
            executive_summary='Scan found 5 issues.',
            risk_score=60,
            format='html',
        )
        self.assertIn('Example Recon Report', str(report))
        self.assertEqual(report.risk_score, 60)
