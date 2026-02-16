"""
Visual Proof Diagnostics Module

This module provides comprehensive diagnostics for visual proof capture functionality.
It checks for:
- Required Python dependencies (Playwright, Selenium, Pillow)
- Browser binaries (Chrome/Chromium for Playwright, ChromeDriver for Selenium)
- File system permissions for media directory
- Configuration issues

This helps users quickly identify and resolve issues preventing visual proof capture.
"""

import os
import sys
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class VisualProofDiagnostics:
    """
    Comprehensive diagnostics for visual proof capture system.
    """
    
    def __init__(self, media_dir: str = 'media/exploit_proofs'):
        """
        Initialize diagnostics.
        
        Args:
            media_dir: Directory where visual proof files will be stored
        """
        self.media_dir = Path(media_dir)
        self.warnings: List[Dict[str, Any]] = []
        self.dependencies_checked = False
        
    def check_all(self) -> Dict[str, Any]:
        """
        Run all diagnostic checks and return comprehensive status.
        
        Returns:
            Dictionary with diagnostic results and warnings
        """
        results = {
            'dependencies': self._check_dependencies(),
            'browsers': self._check_browsers(),
            'filesystem': self._check_filesystem_permissions(),
            'overall_status': 'ok',
            'warnings': [],
            'errors': [],
            'recommendations': []
        }
        
        # Determine overall status
        if results['dependencies']['missing_critical']:
            results['overall_status'] = 'critical'
            results['errors'].extend(results['dependencies']['missing_critical'])
        
        if results['browsers']['status'] == 'unavailable':
            if results['overall_status'] == 'ok':
                results['overall_status'] = 'critical'
            results['errors'].append(results['browsers']['message'])
        
        if not results['filesystem']['writable']:
            if results['overall_status'] == 'ok':
                results['overall_status'] = 'critical'
            results['errors'].append(results['filesystem']['error'])
        
        # Collect warnings
        if results['dependencies']['missing_optional']:
            results['warnings'].extend(results['dependencies']['missing_optional'])
        
        # Add recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        return results
    
    def _check_dependencies(self) -> Dict[str, Any]:
        """
        Check for required Python dependencies.
        
        Returns:
            Dictionary with dependency status
        """
        result = {
            'playwright': False,
            'selenium': False,
            'pillow': False,
            'missing_critical': [],
            'missing_optional': [],
            'installation_commands': []
        }
        
        # Check Playwright
        try:
            import playwright
            result['playwright'] = True
            logger.debug("Playwright is available")
        except ImportError:
            logger.warning("Playwright is not available")
            result['missing_optional'].append({
                'type': 'dependency',
                'severity': 'medium',
                'component': 'Playwright',
                'message': 'Playwright is not installed (preferred browser automation library)',
                'recommendation': 'pip install playwright && playwright install chromium'
            })
            result['installation_commands'].append('pip install playwright && playwright install chromium')
        
        # Check Selenium (fallback)
        try:
            import selenium
            result['selenium'] = True
            logger.debug("Selenium is available")
        except ImportError:
            logger.warning("Selenium is not available")
            if not result['playwright']:
                result['missing_critical'].append({
                    'type': 'dependency',
                    'severity': 'high',
                    'component': 'Browser Automation',
                    'message': 'Neither Playwright nor Selenium is installed - visual proof capture will not work',
                    'recommendation': 'pip install playwright && playwright install chromium (preferred) or pip install selenium'
                })
                result['installation_commands'].append('pip install selenium')
        
        # Check Pillow
        try:
            import PIL
            result['pillow'] = True
            logger.debug("Pillow is available")
        except ImportError:
            logger.warning("Pillow is not available")
            result['missing_critical'].append({
                'type': 'dependency',
                'severity': 'high',
                'component': 'Pillow',
                'message': 'Pillow (PIL) is not installed - required for image processing',
                'recommendation': 'pip install Pillow'
            })
            result['installation_commands'].append('pip install Pillow')
        
        return result
    
    def _check_browsers(self) -> Dict[str, Any]:
        """
        Check for available browser binaries.
        
        Returns:
            Dictionary with browser availability status
        """
        result = {
            'status': 'unavailable',
            'playwright_browser': False,
            'selenium_browser': False,
            'message': '',
            'details': []
        }
        
        # Check for Playwright browser
        try:
            import playwright
            # Try to check if chromium is installed for Playwright
            # Note: This is a simplified check; actual availability is determined at runtime
            result['playwright_browser'] = True
            result['status'] = 'available'
            result['details'].append('Playwright is installed (browser check at runtime)')
        except ImportError:
            pass
        
        # Check for Chrome/Chromium for Selenium
        chrome_paths = [
            '/usr/bin/google-chrome',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        ]
        
        for chrome_path in chrome_paths:
            if os.path.exists(chrome_path):
                result['selenium_browser'] = True
                result['status'] = 'available'
                result['details'].append(f'Chrome/Chromium found at {chrome_path}')
                break
        
        # Check using shutil.which
        if not result['selenium_browser']:
            if shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('chromium-browser'):
                result['selenium_browser'] = True
                result['status'] = 'available'
                result['details'].append('Chrome/Chromium found in PATH')
        
        if result['status'] == 'unavailable':
            result['message'] = 'No browser binary detected. Visual proof may fail at runtime.'
            result['details'].append('Install Chrome or Chromium, or run: playwright install chromium')
        
        return result
    
    def _check_filesystem_permissions(self) -> Dict[str, Any]:
        """
        Check if media directory is writable.
        
        Returns:
            Dictionary with filesystem permission status
        """
        result = {
            'writable': False,
            'directory_exists': False,
            'error': None,
            'path': str(self.media_dir.absolute())
        }
        
        try:
            # Create directory if it doesn't exist
            self.media_dir.mkdir(parents=True, exist_ok=True)
            result['directory_exists'] = True
            
            # Try to write a test file
            test_file = self.media_dir / '.write_test'
            try:
                test_file.write_text('test')
                test_file.unlink()
                result['writable'] = True
                logger.debug(f"Media directory {self.media_dir} is writable")
            except (IOError, OSError) as e:
                result['error'] = f"Directory exists but is not writable: {e}"
                logger.error(result['error'])
        except (IOError, OSError) as e:
            result['error'] = f"Cannot create media directory: {e}"
            logger.error(result['error'])
        
        return result
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate actionable recommendations based on diagnostic results.
        
        Args:
            results: Full diagnostic results
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        # Check dependencies
        if results['dependencies']['missing_critical']:
            recommendations.append(
                "Install missing dependencies: " + 
                " && ".join(results['dependencies']['installation_commands'])
            )
        
        # Check browsers
        if results['browsers']['status'] == 'unavailable':
            recommendations.append(
                "Install a browser: 'playwright install chromium' or install Google Chrome/Chromium"
            )
        
        # Check filesystem
        if not results['filesystem']['writable']:
            recommendations.append(
                f"Fix directory permissions: chmod 755 {results['filesystem']['path']} or check disk space"
            )
        
        return recommendations
    
    def get_warnings_for_scan(self) -> List[Dict[str, Any]]:
        """
        Get warnings formatted for inclusion in scan results.
        
        Returns:
            List of warning dictionaries suitable for Scan.warnings field
        """
        diagnostics = self.check_all()
        warnings = []
        
        for error in diagnostics['errors']:
            if isinstance(error, dict):
                warnings.append({
                    'category': 'visual_proof',
                    'severity': error.get('severity', 'high'),
                    'component': error.get('component', 'Visual Proof'),
                    'message': error.get('message', str(error)),
                    'recommendation': error.get('recommendation', '')
                })
            else:
                warnings.append({
                    'category': 'visual_proof',
                    'severity': 'high',
                    'component': 'Visual Proof',
                    'message': str(error),
                    'recommendation': 'Check logs for details'
                })
        
        for warning in diagnostics['warnings']:
            if isinstance(warning, dict):
                warnings.append({
                    'category': 'visual_proof',
                    'severity': warning.get('severity', 'medium'),
                    'component': warning.get('component', 'Visual Proof'),
                    'message': warning.get('message', str(warning)),
                    'recommendation': warning.get('recommendation', '')
                })
        
        return warnings


def check_visual_proof_dependencies(media_dir: str = 'media/exploit_proofs') -> Dict[str, Any]:
    """
    Quick dependency check function.
    
    Args:
        media_dir: Directory for visual proof files
        
    Returns:
        Dictionary with check results
    """
    diagnostics = VisualProofDiagnostics(media_dir)
    return diagnostics.check_all()


def get_visual_proof_warnings(media_dir: str = 'media/exploit_proofs') -> List[Dict[str, Any]]:
    """
    Get visual proof warnings for scan results.
    
    Args:
        media_dir: Directory for visual proof files
        
    Returns:
        List of warnings
    """
    diagnostics = VisualProofDiagnostics(media_dir)
    return diagnostics.get_warnings_for_scan()
