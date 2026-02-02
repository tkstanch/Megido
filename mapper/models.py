from django.db import models
from django.contrib.auth.models import User
from django.core.validators import FileExtensionValidator, RegexValidator
from django.utils import timezone
import uuid
import secrets


class ValidationRule(models.Model):
    """
    Model for tracking client-side validation rules with server-side enforcement.
    Security: Ensures server-side validation is replicated.
    """
    field_name = models.CharField(max_length=255)
    rule_type = models.CharField(max_length=50, choices=[
        ('required', 'Required'),
        ('email', 'Email'),
        ('min_length', 'Minimum Length'),
        ('max_length', 'Maximum Length'),
        ('pattern', 'Pattern'),
    ])
    rule_value = models.CharField(max_length=255, blank=True)
    error_message = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['field_name', 'rule_type']
    
    def __str__(self):
        return f"{self.field_name} - {self.rule_type}"


class SecureFileUpload(models.Model):
    """
    Model for secure file uploading with path traversal prevention.
    Security: Validates file extensions, stores with secure names, prevents path traversal.
    """
    # Use UUID for filename to prevent path traversal
    file_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    original_filename = models.CharField(max_length=255)
    # Store files in a controlled directory with validated extensions
    file = models.FileField(
        upload_to='secure_uploads/',
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'txt', 'jpg', 'png'])]
    )
    content_type = models.CharField(max_length=100)
    file_size = models.IntegerField()  # in bytes
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='file_uploads')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_scanned = models.BooleanField(default=False)  # For malware scanning
    
    class Meta:
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"{self.original_filename} ({self.file_id})"


class RedirectLog(models.Model):
    """
    Model for logging and validating dynamic redirects.
    Security: Prevents open redirect vulnerabilities by whitelisting allowed domains.
    """
    redirect_url = models.URLField(max_length=2048)
    is_whitelisted = models.BooleanField(default=False)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=512, blank=True)
    
    class Meta:
        ordering = ['-requested_at']
    
    def __str__(self):
        return f"Redirect to {self.redirect_url}"


class LoginAttempt(models.Model):
    """
    Model for tracking login attempts to prevent username enumeration and brute force.
    Security: Rate limiting, prevents username enumeration, tracks failed attempts.
    """
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=255, blank=True)
    attempted_at = models.DateTimeField(auto_now_add=True)
    user_agent = models.CharField(max_length=512, blank=True)
    
    class Meta:
        ordering = ['-attempted_at']
        indexes = [
            models.Index(fields=['username', 'attempted_at']),
            models.Index(fields=['ip_address', 'attempted_at']),
        ]
    
    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{status} login for {self.username} from {self.ip_address}"


class SecureSessionToken(models.Model):
    """
    Model for secure session token management.
    Security: Uses cryptographically secure tokens, tracks expiry, prevents token prediction.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='session_tokens')
    # Use secrets module for cryptographically secure tokens
    token = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_activity = models.DateTimeField(auto_now=True)
    ip_address = models.GenericIPAddressField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        if not self.token:
            # Generate cryptographically secure token
            self.token = secrets.token_urlsafe(48)
        if not self.expires_at:
            # Set expiry to 24 hours from creation
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Session for {self.user.username} - {'Active' if self.is_active else 'Inactive'}"


class AccessLog(models.Model):
    """
    Model for logging access control decisions.
    Security: Tracks horizontal and vertical privilege escalation attempts.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='access_logs')
    resource_type = models.CharField(max_length=100)
    resource_id = models.CharField(max_length=100)
    action = models.CharField(max_length=50, choices=[
        ('view', 'View'),
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
    ])
    granted = models.BooleanField()
    denial_reason = models.CharField(max_length=255, blank=True)
    accessed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    
    class Meta:
        ordering = ['-accessed_at']
        indexes = [
            models.Index(fields=['user', 'accessed_at']),
            models.Index(fields=['granted', 'accessed_at']),
        ]
    
    def __str__(self):
        status = "Granted" if self.granted else "Denied"
        return f"{status} {self.action} on {self.resource_type}#{self.resource_id} for {self.user.username}"


class SanitizedUserData(models.Model):
    """
    Model for storing user-supplied data with XSS prevention.
    Security: Demonstrates proper data sanitization and output encoding.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_data')
    field_name = models.CharField(max_length=100)
    raw_value = models.TextField()  # Original unsanitized value
    sanitized_value = models.TextField()  # Sanitized for display
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.field_name} for {self.user.username}"


class PasswordPolicy(models.Model):
    """
    Model for enforcing password policies.
    Security: Prevents weak passwords, enforces complexity requirements.
    """
    min_length = models.IntegerField(default=12)
    require_uppercase = models.BooleanField(default=True)
    require_lowercase = models.BooleanField(default=True)
    require_digits = models.BooleanField(default=True)
    require_special_chars = models.BooleanField(default=True)
    max_age_days = models.IntegerField(default=90)  # Password expiry
    prevent_reuse_count = models.IntegerField(default=5)  # Prevent reusing last N passwords
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = "Password Policies"
    
    def __str__(self):
        return f"Password Policy (min {self.min_length} chars)"


class ErrorLog(models.Model):
    """
    Model for secure error logging without information leakage.
    Security: Logs detailed errors server-side but returns generic messages to users.
    """
    error_code = models.CharField(max_length=50, unique=True, editable=False)
    error_type = models.CharField(max_length=100)
    error_message = models.TextField()  # Detailed message for admins
    stack_trace = models.TextField(blank=True)  # Full stack trace
    user_message = models.CharField(max_length=255)  # Generic message for users
    occurred_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        ordering = ['-occurred_at']
    
    def save(self, *args, **kwargs):
        if not self.error_code:
            # Generate unique error code for reference
            self.error_code = f"ERR-{secrets.token_hex(8).upper()}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.error_code}: {self.error_type}"


class DependencyAudit(models.Model):
    """
    Model for tracking third-party dependencies and known vulnerabilities.
    Security: Audits dependencies against known vulnerabilities.
    """
    package_name = models.CharField(max_length=255)
    version = models.CharField(max_length=50)
    vulnerability_id = models.CharField(max_length=100, blank=True)
    severity = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], blank=True)
    description = models.TextField(blank=True)
    is_patched = models.BooleanField(default=False)
    discovered_at = models.DateTimeField(auto_now_add=True)
    patched_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-discovered_at']
    
    def __str__(self):
        return f"{self.package_name} {self.version} - {self.severity if self.severity else 'No vulnerabilities'}"
