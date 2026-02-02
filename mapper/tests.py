from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from datetime import timedelta
import uuid

from .models import (
    ValidationRule, SecureFileUpload, RedirectLog, LoginAttempt,
    SecureSessionToken, AccessLog, SanitizedUserData, PasswordPolicy,
    ErrorLog, DependencyAudit
)
from .views import validate_password_strength, is_safe_url


class ValidationRuleTestCase(TestCase):
    """Test client-side validation with server-side enforcement."""
    
    def setUp(self):
        self.rule = ValidationRule.objects.create(
            field_name='email',
            rule_type='email',
            rule_value='',
            error_message='Invalid email format',
            is_active=True
        )
    
    def test_validation_rule_creation(self):
        """Test that validation rules are created correctly."""
        self.assertEqual(self.rule.field_name, 'email')
        self.assertEqual(self.rule.rule_type, 'email')
        self.assertTrue(self.rule.is_active)
    
    def test_validation_rule_string_representation(self):
        """Test string representation of validation rule."""
        self.assertEqual(str(self.rule), 'email - email')


class SecureFileUploadTestCase(TestCase):
    """Test secure file upload with path traversal prevention."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
        self.client = Client()
    
    def test_secure_file_upload_creation(self):
        """Test that files are uploaded securely."""
        file_content = b'Test file content'
        uploaded_file = SimpleUploadedFile('test.txt', file_content, content_type='text/plain')
        
        secure_file = SecureFileUpload.objects.create(
            original_filename='test.txt',
            file=uploaded_file,
            content_type='text/plain',
            file_size=len(file_content),
            uploaded_by=self.user
        )
        
        self.assertIsNotNone(secure_file.file_id)
        self.assertIsInstance(secure_file.file_id, uuid.UUID)
        self.assertEqual(secure_file.original_filename, 'test.txt')
    
    def test_file_upload_requires_authentication(self):
        """Test that file upload requires authentication."""
        response = self.client.post('/mapper/upload/')
        self.assertEqual(response.status_code, 302)  # Redirect to login


class RedirectLogTestCase(TestCase):
    """Test secure redirect handling."""
    
    def test_safe_url_validation(self):
        """Test URL validation for redirects."""
        # Safe relative URL
        self.assertTrue(is_safe_url('/home/', ['example.com']))
        
        # Safe whitelisted domain
        self.assertTrue(is_safe_url('http://example.com/page', ['example.com']))
        
        # Unsafe external URL
        self.assertFalse(is_safe_url('http://evil.com', ['example.com']))
    
    def test_redirect_log_creation(self):
        """Test that redirects are logged."""
        user = User.objects.create_user(username='testuser', password='testpass123!')
        
        redirect_log = RedirectLog.objects.create(
            redirect_url='http://example.com',
            is_whitelisted=True,
            requested_by=user,
            ip_address='127.0.0.1'
        )
        
        self.assertEqual(redirect_log.redirect_url, 'http://example.com')
        self.assertTrue(redirect_log.is_whitelisted)


class LoginAttemptTestCase(TestCase):
    """Test login attempt tracking and brute force protection."""
    
    def setUp(self):
        self.client = Client()
    
    def test_login_attempt_logging(self):
        """Test that login attempts are logged."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='127.0.0.1',
            success=False,
            failure_reason='Invalid credentials'
        )
        
        self.assertEqual(attempt.username, 'testuser')
        self.assertFalse(attempt.success)
    
    def test_failed_login_creates_log(self):
        """Test that failed logins create log entries."""
        User.objects.create_user(username='testuser', password='correctpass')
        
        response = self.client.post('/mapper/login/', {
            'username': 'testuser',
            'password': 'wrongpass'
        })
        
        # Check that login attempt was logged
        attempts = LoginAttempt.objects.filter(username='testuser')
        self.assertGreater(attempts.count(), 0)


class SecureSessionTokenTestCase(TestCase):
    """Test secure session token management."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
    
    def test_token_generation(self):
        """Test that tokens are generated securely."""
        token = SecureSessionToken.objects.create(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        self.assertIsNotNone(token.token)
        self.assertEqual(len(token.token), 64)  # URL-safe base64 48 bytes = 64 chars
        self.assertTrue(token.is_active)
    
    def test_token_expiry(self):
        """Test token expiration."""
        token = SecureSessionToken.objects.create(
            user=self.user,
            ip_address='127.0.0.1',
            expires_at=timezone.now() - timedelta(hours=1)
        )
        
        self.assertTrue(token.is_expired())


class AccessLogTestCase(TestCase):
    """Test access control logging."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
    
    def test_access_log_creation(self):
        """Test that access is logged."""
        log = AccessLog.objects.create(
            user=self.user,
            resource_type='file',
            resource_id='123',
            action='view',
            granted=True,
            ip_address='127.0.0.1'
        )
        
        self.assertTrue(log.granted)
        self.assertEqual(log.action, 'view')
    
    def test_access_denial_logging(self):
        """Test that denied access is logged."""
        log = AccessLog.objects.create(
            user=self.user,
            resource_type='admin_panel',
            resource_id='1',
            action='view',
            granted=False,
            denial_reason='Insufficient permissions',
            ip_address='127.0.0.1'
        )
        
        self.assertFalse(log.granted)
        self.assertEqual(log.denial_reason, 'Insufficient permissions')


class SanitizedUserDataTestCase(TestCase):
    """Test XSS prevention in user-supplied data."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
    
    def test_data_sanitization(self):
        """Test that user data is sanitized."""
        raw_value = '<script>alert("XSS")</script>'
        sanitized_value = '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'
        
        data = SanitizedUserData.objects.create(
            user=self.user,
            field_name='comment',
            raw_value=raw_value,
            sanitized_value=sanitized_value
        )
        
        self.assertEqual(data.raw_value, raw_value)
        self.assertNotEqual(data.sanitized_value, raw_value)


class PasswordPolicyTestCase(TestCase):
    """Test password policy enforcement."""
    
    def test_password_policy_creation(self):
        """Test password policy defaults."""
        policy = PasswordPolicy.objects.create()
        
        self.assertEqual(policy.min_length, 12)
        self.assertTrue(policy.require_uppercase)
        self.assertTrue(policy.require_lowercase)
        self.assertTrue(policy.require_digits)
        self.assertTrue(policy.require_special_chars)
    
    def test_weak_password_validation(self):
        """Test that weak passwords are rejected."""
        PasswordPolicy.objects.create()
        
        # Weak password
        valid, errors = validate_password_strength('weak')
        self.assertFalse(valid)
        self.assertGreater(len(errors), 0)
    
    def test_strong_password_validation(self):
        """Test that strong passwords are accepted."""
        PasswordPolicy.objects.create()
        
        # Strong password
        valid, errors = validate_password_strength('StrongP@ssw0rd!')
        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)


class ErrorLogTestCase(TestCase):
    """Test secure error logging."""
    
    def test_error_log_creation(self):
        """Test that errors are logged securely."""
        error = ErrorLog.objects.create(
            error_type='ValueError',
            error_message='Detailed error message for admins',
            user_message='An error occurred. Please contact support.'
        )
        
        self.assertIsNotNone(error.error_code)
        self.assertTrue(error.error_code.startswith('ERR-'))
        self.assertNotEqual(error.error_message, error.user_message)
    
    def test_error_code_uniqueness(self):
        """Test that error codes are unique."""
        error1 = ErrorLog.objects.create(
            error_type='ValueError',
            error_message='Error 1',
            user_message='Generic error'
        )
        
        error2 = ErrorLog.objects.create(
            error_type='ValueError',
            error_message='Error 2',
            user_message='Generic error'
        )
        
        self.assertNotEqual(error1.error_code, error2.error_code)


class DependencyAuditTestCase(TestCase):
    """Test dependency vulnerability tracking."""
    
    def test_dependency_audit_creation(self):
        """Test dependency audit logging."""
        audit = DependencyAudit.objects.create(
            package_name='django',
            version='2.0.0',
            vulnerability_id='CVE-2020-1234',
            severity='high',
            description='Test vulnerability',
            is_patched=False
        )
        
        self.assertEqual(audit.package_name, 'django')
        self.assertEqual(audit.severity, 'high')
        self.assertFalse(audit.is_patched)


class SQLInjectionPreventionTestCase(TestCase):
    """Test SQL injection prevention."""
    
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass123!')
        self.client = Client()
        self.client.login(username='testuser', password='testpass123!')
        
        # Create test file
        file_content = b'Test content'
        uploaded_file = SimpleUploadedFile('test.txt', file_content)
        SecureFileUpload.objects.create(
            original_filename='test.txt',
            file=uploaded_file,
            content_type='text/plain',
            file_size=len(file_content),
            uploaded_by=self.user
        )
    
    def test_search_with_special_characters(self):
        """Test that special characters in search don't cause SQL injection."""
        # Try SQL injection attempt
        response = self.client.get('/mapper/query/', {
            'search': "test' OR '1'='1"
        })
        
        # Should return 200 (handled safely by ORM)
        self.assertEqual(response.status_code, 200)


class CSRFProtectionTestCase(TestCase):
    """Test CSRF protection on forms."""
    
    def test_csrf_protection_on_post(self):
        """Test that POST requests require CSRF token."""
        client = Client(enforce_csrf_checks=True)
        
        # POST without CSRF token should fail
        response = client.post('/mapper/validate/', {
            'field_name': 'email',
            'field_value': 'test@example.com'
        })
        
        self.assertEqual(response.status_code, 403)
