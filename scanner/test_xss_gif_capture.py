"""
Unit tests for XSS GIF Capture Module

Tests the XSSGifCapture class with mocked browser interactions.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import shutil
import time
from io import BytesIO

# Import the module to test
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.xss_gif_capture import XSSGifCapture, get_xss_gif_capture


class TestXSSGifCapture(unittest.TestCase):
    """Test suite for XSSGifCapture class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary directory for test outputs
        self.test_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.test_dir) / 'xss_gif_proofs'
    
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary directory
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)
    
    def test_initialization(self):
        """Test XSSGifCapture initialization"""
        with patch('scanner.xss_gif_capture.HAS_PIL', True), \
             patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True):
            capture = XSSGifCapture(output_dir=str(self.output_dir))
            
            self.assertTrue(self.output_dir.exists())
            self.assertTrue(capture.use_playwright)
    
    def test_initialization_no_pil(self):
        """Test initialization fails without PIL"""
        with patch('scanner.xss_gif_capture.HAS_PIL', False):
            with self.assertRaises(ImportError):
                XSSGifCapture(output_dir=str(self.output_dir))
    
    def test_initialization_no_browsers(self):
        """Test initialization fails without browsers"""
        with patch('scanner.xss_gif_capture.HAS_PIL', True), \
             patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', False), \
             patch('scanner.xss_gif_capture.HAS_SELENIUM', False):
            with self.assertRaises(ImportError):
                XSSGifCapture(output_dir=str(self.output_dir))
    
    def test_url_sanitization_valid(self):
        """Test URL sanitization with valid URLs"""
        with patch('scanner.xss_gif_capture.HAS_PIL', True), \
             patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True):
            capture = XSSGifCapture(output_dir=str(self.output_dir))
            
            valid_urls = [
                'http://example.com',
                'https://example.com',
                'http://example.com/path',
                'https://example.com:8080/path?param=value',
                'http://192.168.1.1',
                'http://localhost:3000',
            ]
            
            for url in valid_urls:
                self.assertTrue(capture.sanitize_url(url), f"URL should be valid: {url}")
    
    def test_url_sanitization_invalid(self):
        """Test URL sanitization with invalid URLs"""
        with patch('scanner.xss_gif_capture.HAS_PIL', True), \
             patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True):
            capture = XSSGifCapture(output_dir=str(self.output_dir))
            
            invalid_urls = [
                '',
                None,
                'file:///etc/passwd',
                'javascript:alert(1)',
                'ftp://example.com',
                'not a url',
                'http://' + 'a' * 2048,  # Too long
            ]
            
            for url in invalid_urls:
                self.assertFalse(capture.sanitize_url(url), f"URL should be invalid: {url}")
    
    def test_filename_generation(self):
        """Test unique filename generation"""
        with patch('scanner.xss_gif_capture.HAS_PIL', True), \
             patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True):
            capture = XSSGifCapture(output_dir=str(self.output_dir))
            
            url = "http://example.com/test"
            payload = "<script>alert(1)</script>"
            
            filename1 = capture.generate_filename(url, payload)
            time.sleep(0.01)  # Small delay to ensure different timestamp
            filename2 = capture.generate_filename(url, payload)
            
            # Filenames should be different (due to timestamp)
            self.assertNotEqual(filename1, filename2)
            
            # Both should end with .gif
            self.assertTrue(filename1.endswith('.gif'))
            self.assertTrue(filename2.endswith('.gif'))
            
            # Both should start with xss_proof_
            self.assertTrue(filename1.startswith('xss_proof_'))
            self.assertTrue(filename2.startswith('xss_proof_'))
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True)
    def test_create_gif_success(self):
        """Test successful GIF creation from screenshots"""
        # Skip test if PIL not available
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("PIL not available")
        
        capture = XSSGifCapture(output_dir=str(self.output_dir))
        
        # Create mock screenshot data
        screenshots = []
        for i in range(3):
            # Create a simple test image
            img = Image.new('RGB', (100, 100), color=(i*50, 100, 150))
            buf = BytesIO()
            img.save(buf, format='PNG')
            screenshots.append(buf.getvalue())
        
        output_path = self.output_dir / "test.gif"
        
        result = capture.create_gif(screenshots, output_path)
        
        self.assertTrue(result)
        self.assertTrue(output_path.exists())
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True)
    def test_create_gif_no_screenshots(self):
        """Test GIF creation with no screenshots"""
        capture = XSSGifCapture(output_dir=str(self.output_dir))
        
        output_path = self.output_dir / "test.gif"
        result = capture.create_gif([], output_path)
        
        self.assertFalse(result)
        self.assertFalse(output_path.exists())
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True)
    def test_capture_with_playwright(self):
        """Test screenshot capture with Playwright"""
        # Skip test if PIL not available
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("PIL not available")
        
        # Create a mock screenshot
        img = Image.new('RGB', (100, 100), color=(0, 100, 150))
        buf = BytesIO()
        img.save(buf, format='PNG')
        mock_screenshot_data = buf.getvalue()
        
        with patch('scanner.xss_gif_capture.sync_playwright') as mock_playwright:
            # Setup mocks
            mock_page = MagicMock()
            mock_context = MagicMock()
            mock_browser = MagicMock()
            
            mock_page.screenshot.return_value = mock_screenshot_data
            mock_context.new_page.return_value = mock_page
            mock_browser.new_context.return_value = mock_context
            
            mock_playwright_context = MagicMock()
            mock_playwright_context.chromium.launch.return_value = mock_browser
            mock_playwright.return_value.__enter__.return_value = mock_playwright_context
            
            capture = XSSGifCapture(output_dir=str(self.output_dir))
            
            url = "http://example.com/test"
            screenshots = capture.capture_with_playwright(url, duration=0.5)
            
            self.assertGreater(len(screenshots), 0)
            mock_page.goto.assert_called_once()
            mock_browser.close.assert_called_once()
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', False)
    @patch('scanner.xss_gif_capture.HAS_SELENIUM', True)
    def test_capture_with_selenium(self):
        """Test screenshot capture with Selenium"""
        # Skip test if PIL not available
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("PIL not available")
        
        # Create a mock screenshot
        img = Image.new('RGB', (100, 100), color=(0, 100, 150))
        buf = BytesIO()
        img.save(buf, format='PNG')
        mock_screenshot_data = buf.getvalue()
        
        with patch('scanner.xss_gif_capture.webdriver') as mock_webdriver:
            # Setup mocks
            mock_driver = MagicMock()
            mock_driver.get_screenshot_as_png.return_value = mock_screenshot_data
            mock_webdriver.Chrome.return_value = mock_driver
            
            capture = XSSGifCapture(output_dir=str(self.output_dir))
            
            url = "http://example.com/test"
            screenshots = capture.capture_with_selenium(url, duration=0.5)
            
            self.assertGreater(len(screenshots), 0)
            mock_driver.get.assert_called_once()
            mock_driver.quit.assert_called_once()
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True)
    def test_capture_xss_proof_success(self):
        """Test complete XSS proof capture workflow"""
        # Skip test if PIL not available
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("PIL not available")
        
        # Setup mocks
        img = Image.new('RGB', (100, 100), color=(0, 100, 150))
        buf = BytesIO()
        img.save(buf, format='PNG')
        mock_screenshot = buf.getvalue()
        
        with patch.object(XSSGifCapture, 'capture_with_playwright', return_value=[mock_screenshot, mock_screenshot]), \
             patch.object(XSSGifCapture, 'create_gif', return_value=True):
            
            capture = XSSGifCapture(output_dir=str(self.output_dir))
            
            url = "http://example.com/test"
            payload = "<script>alert(1)</script>"
            
            result = capture.capture_xss_proof(url, payload, duration=2.0)
            
            self.assertIsNotNone(result)
            self.assertTrue(result.startswith('/media/xss_gif_proofs/'))
            self.assertTrue(result.endswith('.gif'))
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True)
    def test_capture_xss_proof_invalid_url(self):
        """Test XSS proof capture with invalid URL"""
        capture = XSSGifCapture(output_dir=str(self.output_dir))
        
        invalid_url = "file:///etc/passwd"
        payload = "<script>alert(1)</script>"
        
        result = capture.capture_xss_proof(invalid_url, payload)
        
        self.assertIsNone(result)
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True)
    def test_cleanup_old_files(self):
        """Test cleanup of old GIF files"""
        capture = XSSGifCapture(output_dir=str(self.output_dir))
        
        # Create some test files
        old_file = self.output_dir / "old_file.gif"
        new_file = self.output_dir / "new_file.gif"
        
        old_file.write_text("old")
        new_file.write_text("new")
        
        # Set old file's mtime to 10 days ago
        old_time = time.time() - (10 * 24 * 60 * 60)
        os.utime(old_file, (old_time, old_time))
        
        # Run cleanup (keep files newer than 7 days)
        capture.cleanup_old_files(max_age_days=7)
        
        # Old file should be deleted, new file should remain
        self.assertFalse(old_file.exists())
        self.assertTrue(new_file.exists())
    
    @patch('scanner.xss_gif_capture.HAS_PIL', True)
    @patch('scanner.xss_gif_capture.HAS_PLAYWRIGHT', True)
    def test_get_xss_gif_capture_factory(self):
        """Test factory function"""
        capture = get_xss_gif_capture(output_dir=str(self.output_dir))
        
        self.assertIsNotNone(capture)
        self.assertIsInstance(capture, XSSGifCapture)
    
    @patch('scanner.xss_gif_capture.HAS_PIL', False)
    def test_get_xss_gif_capture_factory_no_deps(self):
        """Test factory function with missing dependencies"""
        capture = get_xss_gif_capture(output_dir=str(self.output_dir))
        
        self.assertIsNone(capture)


if __name__ == '__main__':
    unittest.main()
