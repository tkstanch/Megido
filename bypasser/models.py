from django.db import models
from django.utils import timezone


class BypasserTarget(models.Model):
    """Model to store bypasser targets for character probing and filter bypass testing"""
    url = models.URLField(max_length=2048)
    name = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    
    # HTTP method and parameter configuration
    http_method = models.CharField(max_length=10, choices=[
        ('GET', 'GET'),
        ('POST', 'POST'),
    ], default='GET')
    test_parameter = models.CharField(max_length=255, default='test', help_text="Parameter name to test")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name or self.url


class BypasserSession(models.Model):
    """Model to track bypasser testing sessions"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    target = models.ForeignKey(BypasserTarget, on_delete=models.CASCADE, related_name='sessions')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Statistics
    characters_tested = models.IntegerField(default=0)
    characters_blocked = models.IntegerField(default=0)
    characters_allowed = models.IntegerField(default=0)
    encoding_attempts = models.IntegerField(default=0)
    successful_bypasses = models.IntegerField(default=0)
    
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Bypasser Session {self.id} - {self.target} ({self.status})"


class CharacterProbe(models.Model):
    """Model to store character probing results"""
    STATUS_CHOICES = [
        ('allowed', 'Allowed'),
        ('blocked', 'Blocked'),
        ('error', 'Error'),
        ('uncertain', 'Uncertain'),
    ]
    
    session = models.ForeignKey(BypasserSession, on_delete=models.CASCADE, related_name='character_probes')
    character = models.CharField(max_length=10, help_text="Character being tested")
    character_code = models.CharField(max_length=20, help_text="Character code (e.g., U+003C)")
    character_name = models.CharField(max_length=100, help_text="Character description")
    
    # Test results
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    http_status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True, help_text="Response time in seconds")
    response_length = models.IntegerField(blank=True, null=True)
    
    # Detection indicators
    blocked_by_waf = models.BooleanField(default=False, help_text="Appears to be blocked by WAF")
    error_message = models.TextField(blank=True, null=True, help_text="Error message if blocked")
    reflection_found = models.BooleanField(default=False, help_text="Character reflected in response")
    
    tested_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['character_code']
        unique_together = ['session', 'character']
    
    def __str__(self):
        return f"{self.character} ({self.character_name}) - {self.status}"


class EncodingAttempt(models.Model):
    """Model to store encoding bypass attempts"""
    ENCODING_TYPE_CHOICES = [
        ('url_single', 'URL Encoding (Single)'),
        ('url_double', 'URL Encoding (Double)'),
        ('url_triple', 'URL Encoding (Triple)'),
        ('html_decimal', 'HTML Entity (Decimal)'),
        ('html_hex', 'HTML Entity (Hex)'),
        ('unicode', 'Unicode Escape'),
        ('base64', 'Base64'),
        ('hex', 'Hexadecimal'),
        ('mixed_case', 'Mixed Case'),
        ('concatenation', 'Character Concatenation'),
        ('null_byte', 'Null Byte Injection'),
        ('comment_insertion', 'Comment Insertion'),
        ('utf7', 'UTF-7'),
        ('utf8_overlong', 'UTF-8 Overlong Encoding'),
        ('html5_entities', 'HTML5 Named Entities'),
    ]
    
    session = models.ForeignKey(BypasserSession, on_delete=models.CASCADE, related_name='encoding_tests')
    character_probe = models.ForeignKey(CharacterProbe, on_delete=models.CASCADE, related_name='encoding_attempts')
    
    encoding_type = models.CharField(max_length=50, choices=ENCODING_TYPE_CHOICES)
    original_payload = models.CharField(max_length=500, help_text="Original character/payload")
    encoded_payload = models.CharField(max_length=1000, help_text="Encoded version")
    
    # Test results
    success = models.BooleanField(default=False, help_text="Successfully bypassed filter")
    http_status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True)
    response_length = models.IntegerField(blank=True, null=True)
    
    # Detection details
    bypass_confirmed = models.BooleanField(default=False, help_text="Bypass definitively confirmed")
    reflection_found = models.BooleanField(default=False)
    waf_triggered = models.BooleanField(default=False)
    
    notes = models.TextField(blank=True, null=True)
    tested_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-success', 'encoding_type', '-tested_at']
        indexes = [
            models.Index(fields=['session', 'success']),
            models.Index(fields=['character_probe', 'success']),
        ]
    
    def __str__(self):
        status = "✓ Success" if self.success else "✗ Failed"
        return f"{status} - {self.encoding_type}: {self.encoded_payload}"


class BypassResult(models.Model):
    """Model to store successful bypass techniques"""
    RISK_LEVEL_CHOICES = [
        ('info', 'Informational'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    session = models.ForeignKey(BypasserSession, on_delete=models.CASCADE, related_name='bypass_results')
    character_probe = models.ForeignKey(CharacterProbe, on_delete=models.CASCADE, related_name='bypass_results')
    encoding_attempt = models.ForeignKey(EncodingAttempt, on_delete=models.CASCADE, related_name='bypass_results')
    
    # Bypass details
    technique_description = models.TextField(help_text="Description of the bypass technique")
    payload_example = models.CharField(max_length=1000, help_text="Example payload that worked")
    
    # Impact assessment
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES, default='medium')
    impact_description = models.TextField(help_text="Potential security impact")
    
    # Evidence
    evidence = models.TextField(help_text="Evidence of successful bypass")
    recommendation = models.TextField(help_text="Remediation recommendation")
    
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-discovered_at']
    
    def __str__(self):
        return f"Bypass: {self.character_probe.character} via {self.encoding_attempt.encoding_type}"
