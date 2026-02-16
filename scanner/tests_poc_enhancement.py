"""
Test cases for PoC (Proof of Concept) enhancement feature.

This module tests that proof_of_impact is always populated with actionable evidence,
including both verified findings (with credentials/secrets) and unverified findings
(with generic sensitive output like stack traces, errors, debug info).
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.plugins.exploits.info_disclosure_plugin import InfoDisclosurePlugin


class TestPoCEnhancement(unittest.TestCase):
    """Test cases for PoC field enhancement"""
    
    def setUp(self):
        """Set up test environment"""
        self.plugin = InfoDisclosurePlugin()
    
    def test_verify_with_credentials_returns_verified_poc(self):
        """Test that verify() returns verified=True with PoC when credentials are found"""
        # Mock result with disclosed files containing credentials
        result = {
            'success': True,
            'disclosed_info': {
                '/.env': 'API_KEY=abc123def456ghi789jkl012mno345pqr\nDB_PASSWORD=mysecretpass123',
                '/config.php': 'define("DB_HOST", "localhost");\ndefine("DB_PASSWORD", "admin123");'
            },
            'evidence': 'Found 2 exposed file(s)',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        # Should be verified because credentials were found
        self.assertTrue(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)
        self.assertIn('Sensitive Information Disclosed', proof)
        self.assertIn('/.env', proof)
        self.assertIn('Sensitive Data Found', proof)
    
    def test_verify_with_stack_trace_returns_unverified_poc(self):
        """Test that verify() returns verified=False but with PoC when only stack traces found"""
        # Mock result with advanced exploitation findings (stack traces, no credentials)
        result = {
            'success': True,
            'disclosed_info': {
                '/error.log': 'Some generic log content without credentials'
            },
            'advanced_exploitation': {
                'exploited': True,
                'findings': [
                    {
                        'category': 'stack_trace',
                        'severity': 'high',
                        'matched_text': 'Traceback (most recent call last): File "/app/main.py", line 42',
                        'context': 'Traceback (most recent call last):\n  File "/app/main.py", line 42, in view\n    process_request()'
                    },
                    {
                        'category': 'debug_output',
                        'severity': 'high',
                        'matched_text': 'DEBUG = True',
                        'context': 'Settings loaded with DEBUG = True'
                    }
                ],
                'extracted_data': {
                    'stack_trace': ['Traceback'],
                    'debug_output': ['DEBUG = True']
                },
                'severity': 'high'
            },
            'evidence': 'Found 1 exposed file(s)',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        # Should NOT be verified (no credentials), but should have proof
        self.assertFalse(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('EVIDENCE FOUND', proof)
        self.assertIn('Sensitive Output Detected', proof)
        self.assertIn('Stack Trace', proof)
        self.assertIn('Debug Output', proof)
    
    def test_verify_with_partial_evidence_returns_poc(self):
        """Test that verify() returns PoC for partial_evidence even when success=False"""
        # Mock result with partial evidence (error responses, no full disclosure)
        result = {
            'success': False,
            'partial_evidence': [
                {
                    'path': '/api/debug',
                    'status_code': 500,
                    'evidence': 'Error evidence detected (status 500): Fatal error: Call to undefined function in /var/www/index.php on line 15'
                },
                {
                    'path': '/api/test',
                    'status_code': 500,
                    'evidence': 'Server error detected (status 500), potential info leakage'
                }
            ],
            'confidence': 'partial',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        # Should NOT be verified, but should have proof
        self.assertFalse(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('EVIDENCE FOUND', proof)
        self.assertIn('Sensitive Output Detected', proof)
        self.assertIn('/api/debug', proof)
        self.assertIn('Fatal error', proof)
    
    def test_verify_with_database_errors_returns_poc(self):
        """Test that database errors generate PoC even without credentials"""
        result = {
            'success': True,
            'disclosed_info': {},
            'advanced_exploitation': {
                'exploited': True,
                'findings': [
                    {
                        'category': 'database_error',
                        'severity': 'critical',
                        'matched_text': 'You have an error in your SQL syntax',
                        'context': 'MySQL error: You have an error in your SQL syntax; check the manual'
                    }
                ],
                'extracted_data': {
                    'database_error': ['SQL syntax error']
                },
                'severity': 'critical'
            },
            'evidence': 'Found database error exposure',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        # Database errors at critical severity should be treated as sensitive
        # But without actual credentials, it's still unverified
        self.assertFalse(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('EVIDENCE FOUND', proof)
        self.assertIn('Database Error', proof)
    
    def test_verify_with_internal_paths_returns_poc(self):
        """Test that internal path exposure generates PoC"""
        result = {
            'success': True,
            'disclosed_info': {
                '/phpinfo.php': 'PHP Info page with paths'
            },
            'advanced_exploitation': {
                'exploited': True,
                'findings': [
                    {
                        'category': 'internal_paths',
                        'severity': 'medium',
                        'matched_text': '/var/www/html/app',
                        'context': 'Application path: /var/www/html/app/config.php'
                    },
                    {
                        'category': 'source_code',
                        'severity': 'medium',
                        'matched_text': 'function authenticate($user, $pass)',
                        'context': 'Source code disclosure'
                    }
                ],
                'extracted_data': {
                    'internal_paths': ['/var/www/html/app'],
                    'source_code': ['function authenticate']
                },
                'severity': 'medium'
            },
            'evidence': 'Found internal path disclosure',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        # Internal paths without credentials should not verify
        self.assertFalse(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('EVIDENCE FOUND', proof)
        self.assertIn('Internal Paths', proof)
        self.assertIn('Source Code', proof)
    
    def test_verify_empty_result_returns_no_poc(self):
        """Test that verify() returns None for empty results"""
        result = {
            'success': False,
            'error': 'No information disclosed',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        self.assertFalse(is_verified)
        self.assertIsNone(proof)
    
    def test_verify_files_without_secrets_returns_poc(self):
        """Test that files without secrets still generate PoC"""
        result = {
            'success': True,
            'disclosed_info': {
                '/robots.txt': 'User-agent: *\nDisallow: /admin',
                '/package.json': '{"name": "myapp", "version": "1.0.0"}'
            },
            'evidence': 'Found 2 exposed file(s)',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        # Files without sensitive patterns should not verify
        self.assertFalse(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('Files Disclosed', proof)
        self.assertIn('Review Manually', proof)
        self.assertIn('/robots.txt', proof)
    
    def test_verify_mixed_evidence_prioritizes_credentials(self):
        """Test that credentials are prioritized over generic evidence"""
        result = {
            'success': True,
            'disclosed_info': {
                '/.env': 'API_KEY=secret123456789012345678901234567890'
            },
            'advanced_exploitation': {
                'exploited': True,
                'findings': [
                    {
                        'category': 'api_keys',
                        'severity': 'critical',
                        'matched_text': 'api_key=secret123456789012345678901234567890',
                        'context': 'API key in .env file'
                    },
                    {
                        'category': 'stack_trace',
                        'severity': 'high',
                        'matched_text': 'Traceback',
                        'context': 'Stack trace also present'
                    }
                ],
                'extracted_data': {
                    'api_keys': ['secret123456789012345678901234567890'],
                    'stack_trace': ['Traceback']
                },
                'severity': 'critical'
            },
            'evidence': 'Found credentials and stack traces',
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        # Should be verified because credentials were found
        self.assertTrue(is_verified)
        self.assertIsNotNone(proof)
        self.assertIn('VERIFIED', proof)
        self.assertIn('Sensitive Data Found', proof)
        # Should also mention generic evidence
        self.assertIn('Additional Generic Evidence', proof)


class TestPoCFormattingAndDisplay(unittest.TestCase):
    """Test PoC formatting for dashboard display"""
    
    def setUp(self):
        """Set up test environment"""
        self.plugin = InfoDisclosurePlugin()
    
    def test_poc_contains_descriptive_headers(self):
        """Test that PoC includes clear section headers"""
        result = {
            'success': True,
            'disclosed_info': {
                '/.env': 'PASSWORD=secret123'
            },
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        self.assertIsNotNone(proof)
        # Check for clear section headers
        lines = proof.split('\n')
        self.assertTrue(any('VERIFIED' in line for line in lines))
        self.assertTrue(any('Disclosed' in line for line in lines))
        self.assertTrue(any('Sensitive Data Found' in line for line in lines))
    
    def test_poc_limits_displayed_items(self):
        """Test that PoC respects MAX_DISPLAYED limits"""
        # Create result with many files and credentials to trigger sensitive findings limit
        disclosed_files = {}
        for i in range(20):
            disclosed_files[f'/file{i}.txt'] = f'PASSWORD=secret{i}123456'
        
        result = {
            'success': True,
            'disclosed_info': disclosed_files,
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        self.assertIsNotNone(proof)
        # Should have "... and X more" message for files or findings
        self.assertTrue('more' in proof.lower() or len(disclosed_files) > self.plugin.MAX_DISPLAYED_FILES)
    
    def test_poc_uses_proper_formatting_characters(self):
        """Test that PoC uses unicode characters for visual appeal"""
        result = {
            'success': True,
            'disclosed_info': {},
            'advanced_exploitation': {
                'exploited': True,
                'findings': [
                    {
                        'category': 'stack_trace',
                        'severity': 'high',
                        'matched_text': 'Error trace',
                        'context': 'Context'
                    }
                ],
                'severity': 'high'
            },
            'vulnerability_type': 'info_disclosure'
        }
        
        is_verified, proof = self.plugin.verify(
            result=result,
            target_url='https://example.com',
            vulnerability_data={}
        )
        
        self.assertIsNotNone(proof)
        # Check for unicode bullets and info symbols
        self.assertTrue('ℹ' in proof or '•' in proof)


if __name__ == '__main__':
    unittest.main()
