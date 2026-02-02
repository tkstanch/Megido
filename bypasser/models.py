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


class CustomBypassTechnique(models.Model):
    """Model to store user-crafted custom bypass techniques"""
    CATEGORY_CHOICES = [
        ('waf', 'WAF Bypass'),
        ('firewall', 'Firewall Bypass'),
        ('ips', 'IPS Bypass'),
        ('ids', 'IDS Bypass'),
        ('filter', 'Input Filter Bypass'),
        ('mixed', 'Mixed/Multi-Layer Bypass'),
    ]
    
    name = models.CharField(max_length=255, help_text="Name of the bypass technique")
    description = models.TextField(help_text="Detailed description of what this technique does")
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, help_text="Type of security control to bypass")
    
    # Technique template with placeholders
    # Supports: {{payload}}, {{char}}, {{url_encode}}, {{html_encode}}, etc.
    technique_template = models.TextField(
        help_text="Template with placeholders like {{payload}}, {{char}}, transformation functions"
    )
    
    # Example usage
    example_input = models.CharField(max_length=500, blank=True, null=True, help_text="Example input")
    example_output = models.CharField(max_length=1000, blank=True, null=True, help_text="Example output")
    
    # Metadata
    tags = models.CharField(max_length=500, blank=True, null=True, help_text="Comma-separated tags")
    author = models.CharField(max_length=255, blank=True, null=True, help_text="Author/creator")
    
    # Usage tracking
    times_used = models.IntegerField(default=0, help_text="Number of times this technique has been used")
    times_successful = models.IntegerField(default=0, help_text="Number of successful bypasses")
    success_rate = models.FloatField(default=0.0, help_text="Success rate percentage")
    
    # Status
    is_active = models.BooleanField(default=True, help_text="Whether this technique is active")
    is_public = models.BooleanField(default=False, help_text="Share with other users")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-times_successful', '-created_at']
        indexes = [
            models.Index(fields=['category', 'is_active']),
            models.Index(fields=['is_active', '-times_successful']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.category})"
    
    def update_success_rate(self):
        """Update the success rate based on usage statistics"""
        if self.times_used > 0:
            self.success_rate = (self.times_successful / self.times_used) * 100
        else:
            self.success_rate = 0.0
        self.save()


class CustomTechniqueExecution(models.Model):
    """Model to track execution of custom bypass techniques"""
    session = models.ForeignKey(
        BypasserSession, 
        on_delete=models.CASCADE, 
        related_name='custom_technique_executions'
    )
    technique = models.ForeignKey(
        CustomBypassTechnique, 
        on_delete=models.CASCADE, 
        related_name='executions'
    )
    
    # Input/Output
    input_payload = models.CharField(max_length=1000, help_text="Original input payload")
    output_payload = models.TextField(help_text="Transformed output payload")
    
    # Execution results
    success = models.BooleanField(default=False, help_text="Whether the bypass was successful")
    http_status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True, help_text="Response time in seconds")
    response_length = models.IntegerField(blank=True, null=True)
    
    # Detection
    bypass_confirmed = models.BooleanField(default=False, help_text="Bypass definitively confirmed")
    reflection_found = models.BooleanField(default=False, help_text="Payload reflected in response")
    waf_triggered = models.BooleanField(default=False, help_text="WAF/filter was triggered")
    
    # Additional details
    error_message = models.TextField(blank=True, null=True, help_text="Error message if execution failed")
    notes = models.TextField(blank=True, null=True, help_text="Additional notes")
    
    executed_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-executed_at']
        indexes = [
            models.Index(fields=['session', 'success']),
            models.Index(fields=['technique', 'success']),
        ]
    
    def __str__(self):
        status = "✓ Success" if self.success else "✗ Failed"
        return f"{status} - {self.technique.name}: {self.output_payload[:50]}"


class ReadyMadePayload(models.Model):
    """Model to store ready-made bypass payloads"""
    CATEGORY_CHOICES = [
        ('xss', 'XSS'),
        ('sqli', 'SQL Injection'),
        ('command_injection', 'Command Injection'),
        ('path_traversal', 'Path Traversal'),
        ('xxe', 'XXE'),
        ('ssti', 'SSTI'),
        ('ssrf', 'SSRF'),
        ('ldap', 'LDAP Injection'),
        ('nosql', 'NoSQL Injection'),
        ('general', 'General'),
    ]
    
    BYPASS_TARGET_CHOICES = [
        ('waf', 'WAF'),
        ('ips', 'IPS'),
        ('ids', 'IDS'),
        ('firewall', 'Firewall'),
        ('filter', 'Input Filter'),
        ('all', 'All'),
    ]
    
    RISK_LEVEL_CHOICES = [
        ('info', 'Informational'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    name = models.CharField(max_length=255, unique=True, help_text="Unique payload identifier")
    payload = models.TextField(help_text="The actual payload")
    description = models.TextField(help_text="What this payload does")
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, help_text="Attack type category")
    bypass_target = models.CharField(max_length=50, choices=BYPASS_TARGET_CHOICES, 
                                     help_text="What security control this bypasses")
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES, default='medium',
                                  help_text="Risk level of using this payload")
    
    # Usage tracking
    times_used = models.IntegerField(default=0, help_text="Number of times payload has been used")
    times_successful = models.IntegerField(default=0, help_text="Number of successful uses")
    success_rate = models.FloatField(default=0.0, help_text="Success rate percentage")
    
    # Metadata
    is_active = models.BooleanField(default=True, help_text="Whether payload is active")
    is_built_in = models.BooleanField(default=True, help_text="Is this a built-in payload")
    tags = models.CharField(max_length=500, blank=True, null=True, help_text="Comma-separated tags")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-times_successful', 'category', 'name']
        indexes = [
            models.Index(fields=['category', 'is_active']),
            models.Index(fields=['bypass_target', 'is_active']),
            models.Index(fields=['risk_level']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.category})"
    
    def update_success_rate(self):
        """Update the success rate based on usage statistics"""
        if self.times_used > 0:
            self.success_rate = (self.times_successful / self.times_used) * 100
        else:
            self.success_rate = 0.0
        self.save()


class PayloadExecution(models.Model):
    """Model to track execution of ready-made payloads"""
    session = models.ForeignKey(
        BypasserSession,
        on_delete=models.CASCADE,
        related_name='payload_executions'
    )
    payload = models.ForeignKey(
        ReadyMadePayload,
        on_delete=models.CASCADE,
        related_name='executions'
    )
    
    # Transformation applied (if any)
    transformations_applied = models.TextField(blank=True, null=True,
                                              help_text="Comma-separated list of transformations")
    
    # Input/Output
    original_payload = models.TextField(help_text="Original payload from library")
    transformed_payload = models.TextField(help_text="Payload after transformations")
    
    # Execution results
    success = models.BooleanField(default=False, help_text="Whether the payload worked")
    http_status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True, help_text="Response time in seconds")
    response_length = models.IntegerField(blank=True, null=True)
    
    # Detection
    bypass_confirmed = models.BooleanField(default=False, help_text="Bypass definitively confirmed")
    reflection_found = models.BooleanField(default=False, help_text="Payload reflected in response")
    waf_triggered = models.BooleanField(default=False, help_text="WAF/filter was triggered")
    
    # Additional details
    error_message = models.TextField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    
    executed_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-executed_at']
        indexes = [
            models.Index(fields=['session', 'success']),
            models.Index(fields=['payload', 'success']),
        ]
    
    def __str__(self):
        status = "✓ Success" if self.success else "✗ Failed"
        return f"{status} - {self.payload.name}: {self.transformed_payload[:50]}"
