"""
Tests for CEF auto-setup functionality
"""

import unittest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from browser.cef_integration import auto_setup


class AutoSetupTests(unittest.TestCase):
    """Test auto_setup helper functions"""
    
    def test_check_python_version(self):
        """Test Python version checking"""
        # Should pass with current Python version (3.7+)
        self.assertTrue(auto_setup.check_python_version((3, 7)))
        
        # Should fail with unrealistic future version
        self.assertFalse(auto_setup.check_python_version((99, 0)))
    
    def test_get_os_info(self):
        """Test OS info retrieval"""
        info = auto_setup.get_os_info()
        
        self.assertIn('system', info)
        self.assertIn('platform', info)
        self.assertIsInstance(info['system'], str)
        self.assertGreater(len(info['system']), 0)
    
    def test_in_virtual_environment(self):
        """Test virtual environment detection"""
        result = auto_setup.in_virtual_environment()
        self.assertIsInstance(result, bool)
    
    def test_get_project_root(self):
        """Test project root detection"""
        root = auto_setup.get_project_root()
        
        self.assertIsInstance(root, Path)
        self.assertTrue(root.exists())
        # Should contain manage.py
        self.assertTrue((root / "manage.py").exists())
    
    def test_verify_file_exists(self):
        """Test file existence check"""
        # Test with known file
        project_root_path = auto_setup.get_project_root()
        manage_py = project_root_path / "manage.py"
        
        self.assertTrue(auto_setup.verify_file_exists(manage_py))
        
        # Test with non-existent file
        fake_file = project_root_path / "nonexistent_file_12345.txt"
        self.assertFalse(auto_setup.verify_file_exists(fake_file))
    
    def test_verify_directory_exists(self):
        """Test directory existence check"""
        project_root_path = auto_setup.get_project_root()
        
        # Test with known directory
        browser_dir = project_root_path / "browser"
        self.assertTrue(auto_setup.verify_directory_exists(browser_dir))
        
        # Test with non-existent directory
        fake_dir = project_root_path / "nonexistent_dir_12345"
        self.assertFalse(auto_setup.verify_directory_exists(fake_dir))
    
    def test_check_port_available(self):
        """Test port availability check"""
        # Port 0 should always be available (OS assigns)
        # Most high ports should be available
        result = auto_setup.check_port_available('127.0.0.1', 65000)
        self.assertIsInstance(result, bool)


class CEFSetupIntegrationTests(unittest.TestCase):
    """Integration tests for CEF setup script"""
    
    def test_imports(self):
        """Test that setup script can be imported"""
        # This tests that all imports in setup_cef_browser.py are valid
        import setup_cef_browser
        
        self.assertTrue(hasattr(setup_cef_browser, 'CEFSetup'))
        self.assertTrue(hasattr(setup_cef_browser, 'main'))
    
    def test_cef_setup_initialization(self):
        """Test CEFSetup class initialization"""
        import setup_cef_browser
        
        setup = setup_cef_browser.CEFSetup(debug=False)
        
        self.assertIsNotNone(setup.os_name)
        self.assertIsNotNone(setup.python_version)
        self.assertIsNotNone(setup.base_dir)
        self.assertIsNotNone(setup.logs_dir)
        self.assertFalse(setup.debug)
    
    def test_cef_setup_check_prerequisites(self):
        """Test prerequisites checking"""
        import setup_cef_browser
        
        setup = setup_cef_browser.CEFSetup(debug=False)
        
        # This should always pass on a working Python installation
        result = setup.check_prerequisites()
        self.assertTrue(result)
    
    def test_cef_setup_verify_cef_files(self):
        """Test CEF files verification"""
        import setup_cef_browser
        
        setup = setup_cef_browser.CEFSetup(debug=False)
        
        # Should find the CEF integration files
        result = setup.verify_cef_files()
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
