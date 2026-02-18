"""
Unit tests for Privacy Storage Analyzer

Tests privacy analysis with cookie and storage data.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_side.privacy_analyzer import (
    PrivacyStorageAnalyzer,
    PrivacyFinding,
    StorageLocation,
    RiskLevel
)


class TestPrivacyStorageAnalyzer(unittest.TestCase):
    """Test cases for PrivacyStorageAnalyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = PrivacyStorageAnalyzer()
    
    def test_initialization(self):
        """Test analyzer initialization"""
        self.assertEqual(len(self.analyzer.findings), 0)
    
    def test_analyze_cookies_with_password(self):
        """Test detection of passwords in cookies"""
        cookies = [
            {
                'name': 'user_password',
                'value': 'secret123',
                'httpOnly': False,
                'secure': False,
                'sameSite': None
            }
        ]
        
        findings = self.analyzer.analyze_cookies(cookies)
        
        # Should detect password in cookie
        password_findings = [f for f in findings if 'PASSWORD' in f.risk_type]
        self.assertGreater(len(password_findings), 0)
        
        # Should also detect missing security attributes
        httponly_findings = [f for f in findings if 'HTTPONLY' in f.risk_type]
        secure_findings = [f for f in findings if 'SECURE' in f.risk_type]
        self.assertGreater(len(httponly_findings), 0)
        self.assertGreater(len(secure_findings), 0)
    
    def test_analyze_cookies_with_token(self):
        """Test detection of tokens in cookies"""
        cookies = [
            {
                'name': 'auth_token',
                'value': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'httpOnly': True,
                'secure': True,
                'sameSite': 'Strict'
            }
        ]
        
        findings = self.analyzer.analyze_cookies(cookies)
        
        # Should detect token
        token_findings = [f for f in findings if 'TOKEN' in f.risk_type]
        self.assertGreater(len(token_findings), 0)
    
    def test_analyze_cookies_security_attributes(self):
        """Test detection of missing cookie security attributes"""
        cookies = [
            {
                'name': 'session_id',
                'value': 'abc123',
                'httpOnly': False,
                'secure': False,
                'sameSite': 'None'
            }
        ]
        
        findings = self.analyzer.analyze_cookies(cookies)
        
        # Should detect all three missing security attributes
        self.assertGreaterEqual(len(findings), 3)
    
    def test_analyze_local_storage_with_jwt(self):
        """Test detection of JWT in localStorage"""
        local_storage = {
            'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        }
        
        findings = self.analyzer.analyze_local_storage(local_storage)
        
        # Should detect JWT in localStorage
        jwt_findings = [f for f in findings if 'JWT' in f.risk_type]
        self.assertGreater(len(jwt_findings), 0)
        self.assertEqual(jwt_findings[0].risk_level, RiskLevel.HIGH.value)
    
    def test_analyze_local_storage_with_api_key(self):
        """Test detection of API key in localStorage"""
        local_storage = {
            'api_key': 'sk-1234567890abcdef'
        }
        
        findings = self.analyzer.analyze_local_storage(local_storage)
        
        # Should detect API key
        api_key_findings = [f for f in findings if 'API_KEY' in f.risk_type]
        self.assertGreater(len(api_key_findings), 0)
        self.assertEqual(api_key_findings[0].risk_level, RiskLevel.CRITICAL.value)
    
    def test_analyze_session_storage(self):
        """Test analysis of sessionStorage"""
        session_storage = {
            'user_email': 'user@example.com'
        }
        
        findings = self.analyzer.analyze_session_storage(session_storage)
        
        # Should detect email
        email_findings = [f for f in findings if 'EMAIL' in f.risk_type]
        self.assertGreater(len(email_findings), 0)
        
        # SessionStorage should have lower risk than localStorage
        # for same data type
        self.assertIn(email_findings[0].risk_level, [RiskLevel.HIGH.value, RiskLevel.MEDIUM.value])
    
    def test_analyze_cache_with_sensitive_url(self):
        """Test detection of sensitive data in cached URLs"""
        cache_entries = [
            {'url': 'https://example.com/api/user?password=secret123'},
            {'url': 'https://example.com/payment?credit_card=1234567890123456'}
        ]
        
        findings = self.analyzer.analyze_cache(cache_entries)
        
        # Should detect both password and credit card in URLs
        self.assertGreaterEqual(len(findings), 2)
    
    def test_looks_like_jwt(self):
        """Test JWT detection"""
        # Valid JWT format
        valid_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        self.assertTrue(self.analyzer._looks_like_jwt(valid_jwt))
        
        # Invalid JWT format
        invalid_jwt = 'not.a.jwt.token'
        self.assertFalse(self.analyzer._looks_like_jwt(invalid_jwt))
        
        # Not a string
        self.assertFalse(self.analyzer._looks_like_jwt(123))
    
    def test_get_risk_level(self):
        """Test risk level assignment"""
        self.assertEqual(self.analyzer._get_risk_level('password'), RiskLevel.CRITICAL.value)
        self.assertEqual(self.analyzer._get_risk_level('ssn'), RiskLevel.CRITICAL.value)
        self.assertEqual(self.analyzer._get_risk_level('credit_card'), RiskLevel.CRITICAL.value)
        self.assertEqual(self.analyzer._get_risk_level('token'), RiskLevel.HIGH.value)
        self.assertEqual(self.analyzer._get_risk_level('email'), RiskLevel.HIGH.value)
        self.assertEqual(self.analyzer._get_risk_level('personal_info'), RiskLevel.MEDIUM.value)
    
    def test_analyze_all(self):
        """Test combined analysis of all storage types"""
        storage_data = {
            'cookies': [
                {
                    'name': 'session',
                    'value': 'abc123',
                    'httpOnly': False,
                    'secure': False,
                    'sameSite': None
                }
            ],
            'localStorage': {
                'api_key': 'secret_key_123'
            },
            'sessionStorage': {
                'user_email': 'user@example.com'
            },
            'cache': [
                {'url': 'https://example.com/api?token=secret'}
            ],
            'scan_flash_lso': False
        }
        
        findings = self.analyzer.analyze_all(storage_data)
        
        # Should have findings from all storage types
        self.assertGreater(len(findings), 0)
        
        # Check that findings include all storage locations
        storage_locations = set(f.storage_location for f in findings)
        self.assertIn(StorageLocation.COOKIES.value, storage_locations)
        self.assertIn(StorageLocation.LOCAL_STORAGE.value, storage_locations)
    
    def test_report_generation(self):
        """Test report generation"""
        # Add some findings
        self.analyzer.findings = [
            PrivacyFinding(
                risk_type="SENSITIVE_DATA_IN_COOKIE_PASSWORD",
                risk_level=RiskLevel.CRITICAL.value,
                storage_location=StorageLocation.COOKIES.value,
                key="password",
                description="Test",
                recommendation="Test"
            ),
            PrivacyFinding(
                risk_type="JWT_IN_LOCALSTORAGE",
                risk_level=RiskLevel.HIGH.value,
                storage_location=StorageLocation.LOCAL_STORAGE.value,
                key="token",
                description="Test",
                recommendation="Test"
            ),
        ]
        
        report = self.analyzer.get_report()
        
        self.assertEqual(report['total_findings'], 2)
        self.assertEqual(report['by_risk_level']['CRITICAL'], 1)
        self.assertEqual(report['by_risk_level']['HIGH'], 1)
        self.assertEqual(report['by_storage_location'][StorageLocation.COOKIES.value], 1)
        self.assertEqual(report['by_storage_location'][StorageLocation.LOCAL_STORAGE.value], 1)
    
    def test_safe_storage_no_findings(self):
        """Test that safe storage produces no findings"""
        storage_data = {
            'cookies': [
                {
                    'name': 'preferences',
                    'value': 'dark_mode',
                    'httpOnly': True,
                    'secure': True,
                    'sameSite': 'Strict'
                }
            ],
            'localStorage': {
                'theme': 'dark',
                'language': 'en'
            },
            'sessionStorage': {
                'tab_state': 'active'
            },
            'cache': [],
        }
        
        findings = self.analyzer.analyze_all(storage_data)
        
        # Should have no findings for safe data
        self.assertEqual(len(findings), 0)


class TestPrivacyFinding(unittest.TestCase):
    """Test cases for PrivacyFinding dataclass"""
    
    def test_finding_creation(self):
        """Test PrivacyFinding creation"""
        finding = PrivacyFinding(
            risk_type="TEST",
            risk_level=RiskLevel.HIGH.value,
            storage_location=StorageLocation.COOKIES.value,
            key="test_key",
            description="test description",
            recommendation="test recommendation"
        )
        
        self.assertEqual(finding.risk_type, "TEST")
        self.assertEqual(finding.risk_level, RiskLevel.HIGH.value)
        self.assertEqual(finding.storage_location, StorageLocation.COOKIES.value)
    
    def test_finding_to_dict(self):
        """Test conversion to dictionary"""
        finding = PrivacyFinding(
            risk_type="TEST",
            risk_level=RiskLevel.HIGH.value,
            storage_location=StorageLocation.COOKIES.value,
            key="test",
            description="desc",
            recommendation="rec"
        )
        
        result = finding.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['risk_type'], "TEST")
        self.assertEqual(result['risk_level'], RiskLevel.HIGH.value)


if __name__ == '__main__':
    unittest.main()
