from django.db import models
from django.utils import timezone


class SpiderTarget(models.Model):
    """Model to store spider targets for content discovery"""
    url = models.URLField(max_length=2048, unique=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    
    # Configuration options
    max_depth = models.IntegerField(default=3, help_text="Maximum crawl depth")
    follow_external_links = models.BooleanField(default=False)
    use_dirbuster = models.BooleanField(default=True)
    use_nikto = models.BooleanField(default=True)
    use_wikto = models.BooleanField(default=True)
    enable_brute_force = models.BooleanField(default=True)
    enable_inference = models.BooleanField(default=True)
    enable_parameter_discovery = models.BooleanField(default=True, help_text="Discover hidden parameters")
    
    # Stealth mode options
    enable_stealth_mode = models.BooleanField(default=True, help_text="Enable stealth features to avoid detection")
    use_random_user_agents = models.BooleanField(default=True, help_text="Rotate user agents between requests")
    stealth_delay_min = models.FloatField(default=1.0, help_text="Minimum delay between requests in seconds")
    stealth_delay_max = models.FloatField(default=3.0, help_text="Maximum delay between requests in seconds")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name or self.url


class SpiderSession(models.Model):
    """Model to track spider crawling sessions"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('paused', 'Paused'),
    ]
    
    target = models.ForeignKey(SpiderTarget, on_delete=models.CASCADE, related_name='sessions')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Statistics
    urls_discovered = models.IntegerField(default=0)
    urls_crawled = models.IntegerField(default=0)
    hidden_content_found = models.IntegerField(default=0)
    inference_results = models.IntegerField(default=0)
    parameters_discovered = models.IntegerField(default=0)
    
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Spider Session {self.id} - {self.target} ({self.status})"


class DiscoveredURL(models.Model):
    """Model to store URLs discovered during spidering"""
    DISCOVERY_METHOD_CHOICES = [
        ('crawl', 'Web Crawling'),
        ('dirbuster', 'DirBuster'),
        ('nikto', 'Nikto'),
        ('wikto', 'Wikto'),
        ('brute_force', 'Brute Force'),
        ('inference', 'Content Inference'),
    ]
    
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='discovered_urls')
    url = models.URLField(max_length=2048)
    discovery_method = models.CharField(max_length=50, choices=DISCOVERY_METHOD_CHOICES)
    depth = models.IntegerField(default=0)
    
    # Response information
    status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True, help_text="Response time in seconds")
    content_type = models.CharField(max_length=255, blank=True, null=True)
    content_length = models.IntegerField(blank=True, null=True)
    
    # Metadata
    title = models.CharField(max_length=500, blank=True, null=True)
    is_hidden = models.BooleanField(default=False, help_text="Content not linked from main site")
    is_interesting = models.BooleanField(default=False, help_text="Potentially interesting endpoint")
    
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-discovered_at']
        unique_together = ['session', 'url']
    
    def __str__(self):
        return f"{self.url} ({self.discovery_method})"


class HiddenContent(models.Model):
    """Model to store hidden/unlinked content discovered"""
    CONTENT_TYPE_CHOICES = [
        ('directory', 'Directory'),
        ('file', 'File'),
        ('api_endpoint', 'API Endpoint'),
        ('backup', 'Backup File'),
        ('config', 'Configuration File'),
        ('admin_panel', 'Admin Panel'),
        ('test_file', 'Test/Debug File'),
        ('other', 'Other'),
    ]
    
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='hidden_content')
    url = models.URLField(max_length=2048)
    content_type = models.CharField(max_length=50, choices=CONTENT_TYPE_CHOICES)
    discovery_method = models.CharField(max_length=50)
    
    status_code = models.IntegerField()
    content_sample = models.TextField(blank=True, null=True, help_text="Sample of content found")
    risk_level = models.CharField(max_length=20, choices=[
        ('info', 'Informational'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], default='info')
    
    notes = models.TextField(blank=True, null=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-discovered_at']
    
    def __str__(self):
        return f"{self.content_type} - {self.url}"


class BruteForceAttempt(models.Model):
    """Model to track brute force attempts on discovered content"""
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='brute_force_attempts')
    base_url = models.URLField(max_length=2048)
    path_tested = models.CharField(max_length=500)
    full_url = models.URLField(max_length=2048)
    
    status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True)
    content_length = models.IntegerField(blank=True, null=True)
    
    success = models.BooleanField(default=False, help_text="Path exists (200-399 status)")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['session', 'success']),
        ]
    
    def __str__(self):
        return f"{self.full_url} - {self.status_code}"


class InferredContent(models.Model):
    """Model to store content inferred from published content"""
    INFERENCE_TYPE_CHOICES = [
        ('pattern', 'Pattern-based'),
        ('naming', 'Naming Convention'),
        ('version', 'Version Discovery'),
        ('technology', 'Technology Stack'),
        ('structure', 'Site Structure'),
    ]
    
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='inferred_content')
    source_url = models.URLField(max_length=2048, help_text="URL from which inference was made")
    inferred_url = models.URLField(max_length=2048, help_text="Inferred/predicted URL")
    inference_type = models.CharField(max_length=50, choices=INFERENCE_TYPE_CHOICES)
    
    confidence = models.FloatField(help_text="Confidence score 0-1")
    reasoning = models.TextField(help_text="Why this inference was made")
    
    verified = models.BooleanField(default=False)
    exists = models.BooleanField(default=False)
    status_code = models.IntegerField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        ordering = ['-confidence', '-created_at']
    
    def __str__(self):
        return f"{self.inference_type}: {self.inferred_url}"


class ToolScanResult(models.Model):
    """Model to store results from external tools (DirBuster, Nikto, Wikto)"""
    TOOL_CHOICES = [
        ('dirbuster', 'DirBuster'),
        ('nikto', 'Nikto'),
        ('wikto', 'Wikto'),
    ]
    
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='tool_results')
    tool_name = models.CharField(max_length=50, choices=TOOL_CHOICES)
    
    # Scan details
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, default='running')
    
    # Results
    findings_count = models.IntegerField(default=0)
    raw_output = models.TextField(blank=True, null=True, help_text="Raw tool output")
    parsed_results = models.JSONField(blank=True, null=True, help_text="Parsed/structured results")
    
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-started_at']
    
    def __str__(self):
        return f"{self.tool_name} scan for session {self.session_id}"


class ParameterDiscoveryAttempt(models.Model):
    """Model to track hidden parameter discovery attempts"""
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='parameter_attempts')
    target_url = models.URLField(max_length=2048)
    parameter_name = models.CharField(max_length=255)
    parameter_value = models.CharField(max_length=255)
    
    # Request details
    http_method = models.CharField(max_length=10, choices=[
        ('GET', 'GET'),
        ('POST', 'POST'),
    ])
    parameter_location = models.CharField(max_length=20, choices=[
        ('query', 'Query String'),
        ('body', 'Request Body'),
        ('both', 'Both Query & Body'),
    ])
    
    # Response details
    status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True, help_text="Response time in seconds")
    content_length = models.IntegerField(blank=True, null=True)
    response_diff = models.BooleanField(default=False, help_text="Response differs from baseline")
    
    # Behavioral indicators
    behavior_changed = models.BooleanField(default=False, help_text="Application behavior changed")
    error_revealed = models.BooleanField(default=False, help_text="Error or debug info revealed")
    content_revealed = models.BooleanField(default=False, help_text="New content revealed")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['session', 'response_diff']),
            models.Index(fields=['session', 'behavior_changed']),
        ]
    
    def __str__(self):
        return f"{self.parameter_name}={self.parameter_value} on {self.target_url}"


class DiscoveredParameter(models.Model):
    """Model to store successfully discovered hidden parameters"""
    PARAMETER_TYPE_CHOICES = [
        ('debug', 'Debug Parameter'),
        ('test', 'Test Parameter'),
        ('admin', 'Admin Parameter'),
        ('developer', 'Developer Parameter'),
        ('feature_flag', 'Feature Flag'),
        ('other', 'Other'),
    ]
    
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='discovered_parameters')
    target_url = models.URLField(max_length=2048)
    parameter_name = models.CharField(max_length=255)
    parameter_value = models.CharField(max_length=255)
    parameter_type = models.CharField(max_length=50, choices=PARAMETER_TYPE_CHOICES)
    
    # Discovery details
    http_method = models.CharField(max_length=10)
    discovery_evidence = models.TextField(help_text="Evidence of parameter effect")
    
    # Impact assessment
    risk_level = models.CharField(max_length=20, choices=[
        ('info', 'Informational'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], default='medium')
    
    # Behavioral changes observed
    reveals_debug_info = models.BooleanField(default=False)
    reveals_source_code = models.BooleanField(default=False)
    reveals_hidden_content = models.BooleanField(default=False)
    enables_functionality = models.BooleanField(default=False)
    causes_error = models.BooleanField(default=False)
    
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-discovered_at']
        unique_together = ['session', 'target_url', 'parameter_name', 'parameter_value']
    
    def __str__(self):
        return f"{self.parameter_name}={self.parameter_value} ({self.parameter_type})"


class ParameterBruteForce(models.Model):
    """Model to track brute force attacks on discovered parameters"""
    session = models.ForeignKey(SpiderSession, on_delete=models.CASCADE, related_name='parameter_brute_force')
    discovered_parameter = models.ForeignKey(DiscoveredParameter, on_delete=models.CASCADE, related_name='brute_force_attempts')
    
    # Test details
    test_value = models.CharField(max_length=500)
    test_description = models.CharField(max_length=255, help_text="Description of what was tested")
    
    # Response details
    status_code = models.IntegerField(blank=True, null=True)
    response_time = models.FloatField(blank=True, null=True)
    content_length = models.IntegerField(blank=True, null=True)
    
    # Results
    success = models.BooleanField(default=False, help_text="Test revealed something interesting")
    finding_description = models.TextField(blank=True, null=True, help_text="What was found")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['discovered_parameter', 'success']),
        ]
    
    def __str__(self):
        return f"Brute force {self.discovered_parameter.parameter_name} with {self.test_value}"
