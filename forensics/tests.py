"""
Tests for the Forensics app.
"""
from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from .models import ForensicFile
from .utils.parse import calculate_file_hash, get_hex_sample, detect_file_type, analyze_file
import hashlib


class ForensicFileModelTest(TestCase):
    """Test ForensicFile model."""
    
    def test_forensic_file_creation(self):
        """Test creating a ForensicFile instance."""
        forensic_file = ForensicFile.objects.create(
            original_filename='test.img',
            file_size=1024,
            sha256_hash='a' * 64,
        )
        self.assertEqual(forensic_file.original_filename, 'test.img')
        self.assertEqual(forensic_file.file_size, 1024)
        self.assertIsNotNone(forensic_file.upload_date)


class ParseUtilsTest(TestCase):
    """Test utility functions in utils/parse.py."""
    
    def test_calculate_file_hash(self):
        """Test hash calculation."""
        content = b'Test content for hashing'
        file_obj = SimpleUploadedFile('test.txt', content)
        
        # Calculate expected hash
        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_md5 = hashlib.md5(content).hexdigest()
        
        # Test SHA256
        sha256_result = calculate_file_hash(file_obj, 'sha256')
        self.assertEqual(sha256_result, expected_sha256)
        
        # Test MD5
        md5_result = calculate_file_hash(file_obj, 'md5')
        self.assertEqual(md5_result, expected_md5)
    
    def test_get_hex_sample(self):
        """Test hex sample extraction."""
        content = b'Hello World!'
        file_obj = SimpleUploadedFile('test.txt', content)
        
        hex_result = get_hex_sample(file_obj, num_bytes=12)
        expected = '48 65 6c 6c 6f 20 57 6f 72 6c 64 21'
        self.assertEqual(hex_result, expected)
    
    def test_detect_file_type(self):
        """Test file type detection."""
        test_cases = [
            ('test.dd', 'Raw Disk Image'),
            ('backup.zip', 'Compressed Archive'),
            ('data.log', 'Log File'),
            ('unknown.xyz', 'Unknown (.xyz)'),
        ]
        
        for filename, expected_type in test_cases:
            file_type, mime_type = detect_file_type(filename)
            self.assertEqual(file_type, expected_type)


class ForensicsViewsTest(TestCase):
    """Test views for the Forensics app."""
    
    def setUp(self):
        """Set up test client."""
        self.client = Client()
    
    def test_dashboard_view(self):
        """Test dashboard view loads correctly."""
        response = self.client.get(reverse('forensics:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/dashboard.html')
    
    def test_upload_view_get(self):
        """Test upload view GET request."""
        response = self.client.get(reverse('forensics:upload'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/upload.html')
    
    def test_upload_view_post(self):
        """Test file upload functionality."""
        test_content = b'Test file content for forensic analysis'
        test_file = SimpleUploadedFile('test.bin', test_content)
        
        response = self.client.post(
            reverse('forensics:upload'),
            {'uploaded_file': test_file},
            follow=True
        )
        
        # Check if file was created
        self.assertEqual(ForensicFile.objects.count(), 1)
        
        # Check if redirected to detail page
        forensic_file = ForensicFile.objects.first()
        self.assertRedirects(response, reverse('forensics:file_detail', kwargs={'pk': forensic_file.pk}))
        
        # Verify file details
        self.assertEqual(forensic_file.original_filename, 'test.bin')
        self.assertEqual(forensic_file.file_size, len(test_content))
        self.assertIsNotNone(forensic_file.sha256_hash)
        self.assertIsNotNone(forensic_file.md5_hash)
    
    def test_file_list_view(self):
        """Test file list view."""
        response = self.client.get(reverse('forensics:file_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'forensics/list.html')
