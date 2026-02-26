"""Tests for the Forensics app."""
from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone
from .models import (ForensicFile, ForensicCase, EvidenceItem, ChainOfCustodyEntry,
                     TimelineEvent, IOCIndicator, ForensicReport, AnalysisTask,
                     YARARule, HashSet, Artifact, NetworkConnection, ProcessInfo)
from .utils.parse import calculate_file_hash, get_hex_sample, detect_file_type, analyze_file
from .utils.entropy import calculate_entropy, is_likely_encrypted, is_likely_packed
from .utils.file_signatures import detect_by_magic_bytes
from .utils.ioc_extraction import extract_iocs, filter_false_positives
from .utils.hash_engine import calculate_hashes
from .utils.string_analysis import extract_ascii_strings, extract_unicode_strings
import hashlib


# ---- Model Tests ----

class ForensicCaseModelTest(TestCase):
    def test_create_case(self):
        case = ForensicCase.objects.create(
            case_number='CASE-001',
            title='Test Case',
            status='open',
            classification='unclassified',
        )
        self.assertEqual(str(case), 'CASE-001: Test Case')
        self.assertEqual(case.status, 'open')

    def test_case_unique_number(self):
        ForensicCase.objects.create(case_number='CASE-002', title='A')
        with self.assertRaises(Exception):
            ForensicCase.objects.create(case_number='CASE-002', title='B')


class EvidenceItemModelTest(TestCase):
    def setUp(self):
        self.case = ForensicCase.objects.create(case_number='CASE-003', title='Test')

    def test_create_evidence(self):
        ev = EvidenceItem.objects.create(
            case=self.case,
            name='Hard Drive Image',
            acquisition_type='dead',
        )
        self.assertIn('CASE-003', str(ev))
        self.assertEqual(ev.acquisition_type, 'dead')


class ChainOfCustodyModelTest(TestCase):
    def setUp(self):
        case = ForensicCase.objects.create(case_number='CASE-004', title='Test')
        self.evidence = EvidenceItem.objects.create(case=case, name='USB Drive', acquisition_type='live')

    def test_custody_entry(self):
        entry = ChainOfCustodyEntry.objects.create(
            evidence=self.evidence,
            action='Collected from scene',
            location='Crime scene',
        )
        self.assertEqual(entry.action, 'Collected from scene')


class ForensicFileModelTest(TestCase):
    def test_forensic_file_creation(self):
        forensic_file = ForensicFile.objects.create(
            original_filename='test.img',
            file_size=1024,
            sha256_hash='a' * 64,
        )
        self.assertEqual(forensic_file.original_filename, 'test.img')
        self.assertEqual(forensic_file.file_size, 1024)
        self.assertIsNotNone(forensic_file.upload_date)
        self.assertFalse(forensic_file.is_encrypted)
        self.assertFalse(forensic_file.is_packed)

    def test_forensic_file_str(self):
        f = ForensicFile.objects.create(original_filename='test.bin', file_size=100)
        self.assertIn('test.bin', str(f))


class IOCIndicatorModelTest(TestCase):
    def test_create_ioc(self):
        ioc = IOCIndicator.objects.create(
            ioc_type='ipv4',
            ioc_value='192.168.1.100',
            source='test',
            confidence='high',
        )
        self.assertEqual(ioc.ioc_type, 'ipv4')

    def test_ioc_unique_together(self):
        IOCIndicator.objects.create(ioc_type='ipv4', ioc_value='10.0.0.1', source='a')
        with self.assertRaises(Exception):
            IOCIndicator.objects.create(ioc_type='ipv4', ioc_value='10.0.0.1', source='b')


class YARARuleModelTest(TestCase):
    def test_create_rule(self):
        rule = YARARule.objects.create(
            name='test_rule',
            rule_content='rule test { condition: true }',
            author='tester',
        )
        self.assertEqual(rule.name, 'test_rule')
        self.assertTrue(rule.is_active)


class TimelineEventModelTest(TestCase):
    def setUp(self):
        self.ff = ForensicFile.objects.create(original_filename='test.bin', file_size=100)

    def test_create_event(self):
        ev = TimelineEvent.objects.create(
            forensic_file=self.ff,
            event_time=timezone.now(),
            event_type='created',
            source='upload',
            description='File uploaded',
        )
        self.assertIn('created', str(ev))


class AnalysisTaskModelTest(TestCase):
    def setUp(self):
        self.ff = ForensicFile.objects.create(original_filename='test.bin', file_size=100)

    def test_create_task(self):
        task = AnalysisTask.objects.create(
            forensic_file=self.ff,
            task_type='disk',
            status='pending',
        )
        self.assertEqual(task.status, 'pending')
        self.assertIn('disk', str(task))


class ArtifactModelTest(TestCase):
    def test_artifact(self):
        a = Artifact.objects.create(artifact_type='registry_key', name='HKLM\\Software\\Test')
        self.assertIn('registry_key', str(a))


class NetworkConnectionModelTest(TestCase):
    def test_network_connection(self):
        nc = NetworkConnection.objects.create(
            src_ip='192.168.1.1', src_port=1234,
            dst_ip='8.8.8.8', dst_port=443,
            protocol='tcp',
        )
        self.assertIn('192.168.1.1', str(nc))


class ProcessInfoModelTest(TestCase):
    def test_process_info(self):
        p = ProcessInfo.objects.create(pid=1234, name='explorer.exe')
        self.assertIn('1234', str(p))


class HashSetModelTest(TestCase):
    def test_hashset(self):
        hs = HashSet.objects.create(name='NSRL', hash_type='sha256', entry_count=100)
        self.assertIn('NSRL', str(hs))


# ---- Utility Tests ----

class ParseUtilsTest(TestCase):
    def test_calculate_file_hash(self):
        content = b'Test content for hashing'
        file_obj = SimpleUploadedFile('test.txt', content)
        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_md5 = hashlib.md5(content).hexdigest()
        self.assertEqual(calculate_file_hash(file_obj, 'sha256'), expected_sha256)
        self.assertEqual(calculate_file_hash(file_obj, 'md5'), expected_md5)

    def test_get_hex_sample(self):
        content = b'Hello World!'
        file_obj = SimpleUploadedFile('test.txt', content)
        hex_result = get_hex_sample(file_obj, num_bytes=12)
        expected = '48 65 6c 6c 6f 20 57 6f 72 6c 64 21'
        self.assertEqual(hex_result, expected)

    def test_detect_file_type(self):
        test_cases = [
            ('test.dd', 'Raw Disk Image'),
            ('backup.zip', 'Compressed Archive'),
            ('data.log', 'Log File'),
            ('unknown.xyz', 'Unknown (.xyz)'),
        ]
        for filename, expected_type in test_cases:
            file_type, mime_type = detect_file_type(filename)
            self.assertEqual(file_type, expected_type)


class EntropyUtilsTest(TestCase):
    def test_zero_entropy(self):
        data = b'\x00' * 1000
        ent = calculate_entropy(data)
        self.assertEqual(ent, 0.0)

    def test_max_entropy(self):
        # Random-ish data has higher entropy
        import os
        data = bytes(range(256)) * 4
        ent = calculate_entropy(data)
        self.assertGreater(ent, 7.0)

    def test_encrypted_detection(self):
        self.assertTrue(is_likely_encrypted(7.5))
        self.assertFalse(is_likely_encrypted(5.0))

    def test_packed_detection(self):
        self.assertTrue(is_likely_packed(7.0))
        self.assertFalse(is_likely_packed(5.0))

    def test_empty_data(self):
        self.assertEqual(calculate_entropy(b''), 0.0)


class FileSignaturesTest(TestCase):
    def test_detect_jpeg(self):
        data = b'\xff\xd8\xff\xe0' + b'\x00' * 28
        result = detect_by_magic_bytes(data)
        self.assertEqual(result.get('type'), 'JPEG')

    def test_detect_png(self):
        data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 24
        result = detect_by_magic_bytes(data)
        self.assertEqual(result.get('type'), 'PNG')

    def test_detect_zip(self):
        data = b'PK\x03\x04' + b'\x00' * 28
        result = detect_by_magic_bytes(data)
        self.assertEqual(result.get('type'), 'ZIP')

    def test_detect_pdf(self):
        data = b'%PDF-1.4' + b'\x00' * 24
        result = detect_by_magic_bytes(data)
        self.assertEqual(result.get('type'), 'PDF')

    def test_detect_pe(self):
        data = b'MZ' + b'\x00' * 30
        result = detect_by_magic_bytes(data)
        self.assertEqual(result.get('type'), 'PE')

    def test_unknown(self):
        data = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        result = detect_by_magic_bytes(data)
        self.assertEqual(result, {})

    def test_bytes_input(self):
        data = b'\xff\xd8\xff\xe0' + b'\x00' * 28
        result = detect_by_magic_bytes(data)
        self.assertIn('magic_hex', result)


class IOCExtractionTest(TestCase):
    def test_extract_ipv4(self):
        data = b'Found connection to 203.0.113.42 and 198.51.100.1'
        result = extract_iocs(data)
        self.assertIn('203.0.113.42', result.get('ipv4', []))

    def test_extract_url(self):
        data = b'visit http://example-malware.com/payload.exe now'
        result = extract_iocs(data)
        urls = result.get('url', [])
        self.assertTrue(any('example-malware.com' in u for u in urls))

    def test_extract_email(self):
        data = b'contact attacker@evil.com for instructions'
        result = extract_iocs(data)
        self.assertIn('attacker@evil.com', result.get('email', []))

    def test_extract_sha256(self):
        sha = 'a' * 64
        data = f'hash={sha}'.encode()
        result = extract_iocs(data)
        # sha256 list should not be all-same-char (filtered)
        # Use a real-looking hash
        real_sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        data2 = f'sha256: {real_sha}'.encode()
        result2 = extract_iocs(data2)
        self.assertIn(real_sha, result2.get('sha256', []))

    def test_filter_false_positives(self):
        iocs = {'ipv4': ['127.0.0.1', '0.0.0.0', '8.8.8.8']}
        filtered = filter_false_positives(iocs)
        self.assertNotIn('127.0.0.1', filtered['ipv4'])
        self.assertIn('8.8.8.8', filtered['ipv4'])


class HashEngineTest(TestCase):
    def test_calculate_hashes(self):
        content = b'Test data for hashing'
        file_obj = SimpleUploadedFile('test.bin', content)
        hashes = calculate_hashes(file_obj)
        self.assertEqual(hashes['md5'], hashlib.md5(content).hexdigest())
        self.assertEqual(hashes['sha1'], hashlib.sha1(content).hexdigest())
        self.assertEqual(hashes['sha256'], hashlib.sha256(content).hexdigest())
        self.assertIn('crc32', hashes)


class StringAnalysisTest(TestCase):
    def test_extract_ascii(self):
        data = b'Hello World test string here'
        strings = extract_ascii_strings(data, min_length=4)
        self.assertIn('Hello World test string here', strings)

    def test_extract_unicode(self):
        data = 'Hello\x00'.encode('utf-16-le') * 2
        strings = extract_unicode_strings(data, min_length=4)
        self.assertTrue(len(strings) > 0)

    def test_short_strings_filtered(self):
        data = b'ab' + b'\x00' * 10 + b'longstring'
        strings = extract_ascii_strings(data, min_length=4)
        self.assertNotIn('ab', strings)


# ---- View Tests ----

class ForensicsViewsTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_dashboard_view(self):
        response = self.client.get(reverse('forensics:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/dashboard.html')

    def test_upload_view_get(self):
        response = self.client.get(reverse('forensics:upload'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/upload.html')

    def test_upload_view_post(self):
        test_content = b'Test file content for forensic analysis'
        test_file = SimpleUploadedFile('test.bin', test_content)
        response = self.client.post(
            reverse('forensics:upload'),
            {'uploaded_file': test_file},
            follow=True
        )
        self.assertEqual(ForensicFile.objects.count(), 1)
        forensic_file = ForensicFile.objects.first()
        self.assertRedirects(response, reverse('forensics:file_detail', kwargs={'pk': forensic_file.pk}))
        self.assertEqual(forensic_file.original_filename, 'test.bin')
        self.assertEqual(forensic_file.file_size, len(test_content))
        self.assertIsNotNone(forensic_file.sha256_hash)
        self.assertIsNotNone(forensic_file.md5_hash)

    def test_file_list_view(self):
        response = self.client.get(reverse('forensics:file_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/list.html')

    def test_case_list_view(self):
        response = self.client.get(reverse('forensics:case_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/case_list.html')

    def test_case_create_get(self):
        response = self.client.get(reverse('forensics:case_create'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/case_create.html')

    def test_case_create_post(self):
        response = self.client.post(reverse('forensics:case_create'), {
            'case_number': 'TEST-001',
            'title': 'Test Investigation',
            'status': 'open',
            'classification': 'unclassified',
        }, follow=True)
        self.assertEqual(ForensicCase.objects.count(), 1)
        case = ForensicCase.objects.first()
        self.assertRedirects(response, reverse('forensics:case_detail', kwargs={'pk': case.pk}))

    def test_case_detail_view(self):
        case = ForensicCase.objects.create(case_number='CASE-101', title='Test')
        response = self.client.get(reverse('forensics:case_detail', kwargs={'pk': case.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/case_detail.html')

    def test_ioc_list_view(self):
        response = self.client.get(reverse('forensics:ioc_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/ioc_list.html')

    def test_report_list_view(self):
        response = self.client.get(reverse('forensics:report_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/report_list.html')

    def test_yara_rule_list_view(self):
        response = self.client.get(reverse('forensics:yara_rule_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/yara_rules.html')

    def test_evidence_detail_view(self):
        case = ForensicCase.objects.create(case_number='CASE-102', title='Test')
        ev = EvidenceItem.objects.create(case=case, name='USB Drive', acquisition_type='live')
        response = self.client.get(reverse('forensics:evidence_detail', kwargs={'pk': ev.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/evidence_detail.html')

    def test_file_detail_404(self):
        response = self.client.get(reverse('forensics:file_detail', kwargs={'pk': 9999}))
        self.assertEqual(response.status_code, 404)

    def test_case_detail_404(self):
        response = self.client.get(reverse('forensics:case_detail', kwargs={'pk': 9999}))
        self.assertEqual(response.status_code, 404)


# ---- API View Tests ----

class APIViewsTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_api_stats(self):
        response = self.client.get(reverse('forensics:api_stats'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('total_cases', data)
        self.assertIn('total_files', data)
        self.assertIn('total_iocs', data)

    def test_api_cases(self):
        ForensicCase.objects.create(case_number='API-001', title='API Test Case')
        response = self.client.get(reverse('forensics:api_cases'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('cases', data)
        self.assertEqual(len(data['cases']), 1)

    def test_api_case_detail(self):
        case = ForensicCase.objects.create(case_number='API-002', title='Test')
        response = self.client.get(reverse('forensics:api_case_detail', kwargs={'pk': case.pk}))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['case_number'], 'API-002')

    def test_api_files(self):
        response = self.client.get(reverse('forensics:api_files'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('files', data)

    def test_api_iocs(self):
        IOCIndicator.objects.create(ioc_type='ipv4', ioc_value='8.8.8.8', source='test')
        response = self.client.get(reverse('forensics:api_iocs'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('iocs', data)
        self.assertEqual(data['total'], 1)

    def test_api_iocs_filter_by_type(self):
        IOCIndicator.objects.create(ioc_type='ipv4', ioc_value='1.2.3.4', source='t')
        IOCIndicator.objects.create(ioc_type='domain', ioc_value='evil.com', source='t')
        response = self.client.get(reverse('forensics:api_iocs') + '?type=ipv4')
        data = response.json()
        self.assertEqual(data['total'], 1)

    def test_api_timeline(self):
        response = self.client.get(reverse('forensics:api_timeline'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('events', data)

    def test_api_evidence(self):
        response = self.client.get(reverse('forensics:api_evidence'))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('evidence', data)

    def test_ioc_export_json(self):
        IOCIndicator.objects.create(ioc_type='ipv4', ioc_value='5.5.5.5', source='test')
        response = self.client.get(reverse('forensics:ioc_export') + '?format=json')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('iocs', data)

    def test_ioc_export_csv(self):
        IOCIndicator.objects.create(ioc_type='ipv4', ioc_value='6.6.6.6', source='test')
        response = self.client.get(reverse('forensics:ioc_export') + '?format=csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

    def test_ioc_export_stix(self):
        IOCIndicator.objects.create(ioc_type='ipv4', ioc_value='7.7.7.7', source='test')
        response = self.client.get(reverse('forensics:ioc_export') + '?format=stix')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['type'], 'bundle')
