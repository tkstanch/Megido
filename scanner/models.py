from django.db import models
from django.core.validators import FileExtensionValidator


class ScanTarget(models.Model):
    """Model to store scan targets"""
    url = models.URLField(max_length=2048)
    name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name or self.url


class Scan(models.Model):
    """Model to store vulnerability scans"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scans')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    warnings = models.JSONField(
        default=list,
        blank=True,
        help_text='List of warnings generated during the scan (e.g., missing dependencies, configuration issues)'
    )
    
    class Meta:
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Scan {self.id} - {self.target} ({self.status})"


class Vulnerability(models.Model):
    """Model to store discovered vulnerabilities"""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    VULNERABILITY_TYPES = [
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('sqli', 'SQL Injection'),
        ('csrf', 'Cross-Site Request Forgery'),
        ('xxe', 'XML External Entity'),
        ('rce', 'Remote Code Execution'),
        ('lfi', 'Local File Inclusion'),
        ('rfi', 'Remote File Inclusion'),
        ('open_redirect', 'Open Redirect'),
        ('ssrf', 'Server-Side Request Forgery'),
        ('info_disclosure', 'Information Disclosure'),
        ('clickjacking', 'UI Redress (Clickjacking)'),
        ('js_hijacking', 'JavaScript Hijacking / JSONP Data Exposure'),
        ('idor', 'Insecure Direct Object Reference'),
        ('jwt', 'JWT Security Issue'),
        ('crlf', 'CRLF Injection'),
        ('host_header', 'Host Header Injection'),
        ('smuggling', 'HTTP Request Smuggling'),
        ('deserialization', 'Insecure Deserialization'),
        ('graphql', 'GraphQL Security Issue'),
        ('websocket', 'WebSocket Security Issue'),
        ('cache_poisoning', 'Web Cache Poisoning'),
        ('cors', 'CORS Misconfiguration'),
        ('other', 'Other'),
    ]
    
    EXPLOIT_STATUS_CHOICES = [
        ('not_attempted', 'Not Attempted'),
        ('in_progress', 'In Progress'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('no_plugin', 'No Plugin Available'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    vulnerability_type = models.CharField(max_length=50, choices=VULNERABILITY_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    url = models.URLField(max_length=2048)
    parameter = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField()
    evidence = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    # Exploit-related fields
    exploited = models.BooleanField(default=False)
    exploit_status = models.CharField(
        max_length=20,
        choices=EXPLOIT_STATUS_CHOICES,
        default='not_attempted'
    )
    exploit_result = models.TextField(blank=True, null=True)
    exploit_attempted_at = models.DateTimeField(blank=True, null=True)
    
    # Advanced features fields
    # Risk scoring
    risk_score = models.FloatField(default=0.0, help_text='Composite risk score (0-100)')
    risk_level = models.CharField(max_length=20, default='medium', help_text='Risk level: critical, high, medium, low')
    confidence_score = models.FloatField(default=0.5, help_text='Confidence in finding (0.0-1.0)')
    
    # Verification and proof of impact
    verified = models.BooleanField(default=False, help_text='Verified through successful exploitation')
    proof_of_impact = models.TextField(blank=True, null=True, help_text='Evidence of real-world impact')
    
    # Enhanced verification data (payloads and repeater requests)
    successful_payloads = models.JSONField(
        default=list,
        blank=True,
        help_text='List of payloads that successfully exploited the vulnerability'
    )
    repeater_data = models.JSONField(
        default=list,
        blank=True,
        help_text='Copy-paste ready HTTP requests for manual verification in repeater app'
    )
    
    # HTTP traffic capture for proof
    http_traffic = models.JSONField(
        default=dict,
        blank=True,
        help_text='Captured HTTP request/response traffic during exploitation'
    )
    
    # Visual proof of exploitation (screenshots/GIFs)
    visual_proof_path = models.CharField(
        max_length=512, 
        blank=True, 
        null=True, 
        help_text='Path to screenshot or GIF showing exploitation impact'
    )
    visual_proof_type = models.CharField(
        max_length=20,
        choices=[
            ('screenshot', 'Screenshot'),
            ('gif', 'Animated GIF'),
            ('video', 'Video'),
        ],
        blank=True,
        null=True,
        help_text='Type of visual proof'
    )
    visual_proof_size = models.IntegerField(
        blank=True, 
        null=True, 
        help_text='File size in bytes'
    )
    visual_proof_status = models.CharField(
        max_length=50,
        choices=[
            ('captured', 'Successfully Captured'),
            ('disabled', 'Disabled by Configuration'),
            ('failed', 'Capture Failed'),
            ('not_supported', 'Not Supported for This Vulnerability Type'),
            ('missing_dependencies', 'Missing Required Dependencies'),
            ('not_attempted', 'Not Attempted'),
        ],
        default='not_attempted',
        help_text='Status of visual proof capture attempt'
    )
    
    # False positive management
    false_positive_status = models.CharField(
        max_length=20,
        choices=[
            ('unknown', 'Unknown'),
            ('confirmed', 'Confirmed Vulnerability'),
            ('false_positive', 'False Positive'),
            ('accepted_risk', 'Accepted Risk'),
        ],
        default='unknown'
    )
    false_positive_reason = models.TextField(blank=True, null=True)
    reviewed_by = models.CharField(max_length=255, blank=True, null=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)
    
    # Compliance mapping
    compliance_violations = models.JSONField(
        default=dict,
        blank=True,
        help_text='Mapping to compliance frameworks (GDPR, PCI-DSS, OWASP, etc.)'
    )
    
    # Remediation
    remediation_priority = models.IntegerField(default=3, help_text='Priority 1-5 (1=highest)')
    remediation_effort = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
        ],
        default='medium'
    )
    
    class Meta:
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['risk_score']),
            models.Index(fields=['verified']),
            models.Index(fields=['false_positive_status']),
        ]
    
    def __str__(self):
        return f"{self.severity.upper()} - {self.get_vulnerability_type_display()} at {self.url}"


class ExploitMedia(models.Model):
    """Model to store visual proof media files (screenshots, GIFs, videos) for exploits"""
    MEDIA_TYPE_CHOICES = [
        ('screenshot', 'Screenshot'),
        ('gif', 'Animated GIF'),
        ('video', 'Video'),
    ]
    
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name='exploit_media'
    )
    
    # Media file information
    media_type = models.CharField(max_length=20, choices=MEDIA_TYPE_CHOICES)
    file_path = models.CharField(
        max_length=512,
        help_text='Relative path to the media file from media root'
    )
    file_name = models.CharField(max_length=255, help_text='Original file name')
    file_size = models.IntegerField(help_text='File size in bytes')
    mime_type = models.CharField(max_length=100, default='image/png')
    
    # Metadata
    title = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text='Descriptive title for the media'
    )
    description = models.TextField(
        blank=True,
        null=True,
        help_text='Description of what this media shows'
    )
    capture_timestamp = models.DateTimeField(auto_now_add=True)
    sequence_order = models.IntegerField(
        default=0,
        help_text='Order in which media should be displayed (0 = first)'
    )
    
    # Technical details
    duration_seconds = models.FloatField(
        blank=True,
        null=True,
        help_text='Duration for GIFs/videos'
    )
    width = models.IntegerField(blank=True, null=True, help_text='Image width in pixels')
    height = models.IntegerField(blank=True, null=True, help_text='Image height in pixels')
    frame_count = models.IntegerField(
        blank=True,
        null=True,
        help_text='Number of frames (for GIFs)'
    )
    
    # Exploit context
    exploit_step = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text='Which step of the exploit this media represents'
    )
    payload_used = models.TextField(
        blank=True,
        null=True,
        help_text='The payload that was executed for this capture'
    )
    
    class Meta:
        ordering = ['vulnerability', 'sequence_order', 'capture_timestamp']
        indexes = [
            models.Index(fields=['vulnerability', 'sequence_order']),
            models.Index(fields=['media_type']),
        ]
    
    def __str__(self):
        return f"{self.get_media_type_display()} for {self.vulnerability.vulnerability_type} - {self.file_name}"


class EngineScan(models.Model):
    """Model to store multi-engine vulnerability scans"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    target_path = models.CharField(max_length=2048, help_text='Path or URL to scan')
    target_type = models.CharField(
        max_length=20,
        choices=[
            ('path', 'File Path'),
            ('url', 'URL'),
            ('git', 'Git Repository'),
        ],
        default='path'
    )
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Execution details
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    execution_time = models.FloatField(default=0.0, help_text='Total execution time in seconds')
    
    # Engine configuration
    enabled_engines = models.JSONField(
        default=list,
        blank=True,
        help_text='List of engine IDs that were enabled for this scan'
    )
    engine_categories = models.JSONField(
        default=list,
        blank=True,
        help_text='Engine categories used (sast, dast, sca, secrets, etc.)'
    )
    parallel_execution = models.BooleanField(default=True)
    max_workers = models.IntegerField(default=4)
    
    # Results summary
    total_engines_run = models.IntegerField(default=0)
    successful_engines = models.IntegerField(default=0)
    failed_engines = models.IntegerField(default=0)
    total_findings = models.IntegerField(default=0)
    
    findings_by_severity = models.JSONField(
        default=dict,
        blank=True,
        help_text='Count of findings by severity level'
    )
    
    # Metadata
    created_by = models.CharField(max_length=255, blank=True, null=True)
    config_snapshot = models.JSONField(
        default=dict,
        blank=True,
        help_text='Configuration used for this scan'
    )
    
    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['started_at']),
            models.Index(fields=['target_type']),
        ]
    
    def __str__(self):
        return f"EngineScan {self.id} - {self.target_path} ({self.status})"


class EngineExecution(models.Model):
    """Model to store individual engine execution results"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]
    
    engine_scan = models.ForeignKey(
        EngineScan,
        on_delete=models.CASCADE,
        related_name='engine_executions'
    )
    
    engine_id = models.CharField(max_length=100, help_text='Engine identifier')
    engine_name = models.CharField(max_length=255, help_text='Human-readable engine name')
    engine_category = models.CharField(
        max_length=50,
        choices=[
            ('sast', 'SAST'),
            ('dast', 'DAST'),
            ('sca', 'SCA'),
            ('secrets', 'Secrets'),
            ('container', 'Container'),
            ('cloud', 'Cloud'),
            ('custom', 'Custom'),
        ]
    )
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Execution details
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    execution_time = models.FloatField(default=0.0, help_text='Execution time in seconds')
    
    # Results
    findings_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, null=True)
    
    # Configuration used
    engine_config = models.JSONField(
        default=dict,
        blank=True,
        help_text='Configuration used for this engine'
    )
    
    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['engine_id']),
            models.Index(fields=['status']),
            models.Index(fields=['engine_category']),
        ]
    
    def __str__(self):
        return f"{self.engine_name} - {self.status}"


class EngineFinding(models.Model):
    """Model to store findings from engine scans"""
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    engine_execution = models.ForeignKey(
        EngineExecution,
        on_delete=models.CASCADE,
        related_name='findings'
    )
    
    engine_scan = models.ForeignKey(
        EngineScan,
        on_delete=models.CASCADE,
        related_name='findings'
    )
    
    # Core identification
    engine_id = models.CharField(max_length=100)
    engine_name = models.CharField(max_length=255)
    
    # Finding details
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    confidence = models.FloatField(default=1.0, help_text='Confidence level 0.0-1.0')
    
    # Location information
    file_path = models.CharField(max_length=2048, blank=True, null=True)
    line_number = models.IntegerField(blank=True, null=True)
    url = models.URLField(max_length=2048, blank=True, null=True)
    
    # Classification
    category = models.CharField(max_length=100, blank=True, null=True)
    cwe_id = models.CharField(max_length=20, blank=True, null=True, help_text='CWE ID')
    cve_id = models.CharField(max_length=50, blank=True, null=True, help_text='CVE ID')
    owasp_category = models.CharField(max_length=100, blank=True, null=True)
    
    # Evidence and remediation
    evidence = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)
    references = models.JSONField(default=list, blank=True)
    
    # Metadata
    discovered_at = models.DateTimeField(auto_now_add=True)
    raw_output = models.JSONField(default=dict, blank=True)
    
    # Deduplication
    finding_hash = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text='Hash for deduplication'
    )
    is_duplicate = models.BooleanField(default=False)
    duplicate_of = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='duplicates'
    )
    
    # Review status
    reviewed = models.BooleanField(default=False)
    status = models.CharField(
        max_length=20,
        choices=[
            ('new', 'New'),
            ('confirmed', 'Confirmed'),
            ('false_positive', 'False Positive'),
            ('fixed', 'Fixed'),
            ('accepted', 'Accepted Risk'),
        ],
        default='new'
    )
    
    class Meta:
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['finding_hash']),
            models.Index(fields=['status']),
            models.Index(fields=['engine_id']),
            models.Index(fields=['cwe_id']),
        ]
    
    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"
    
    def generate_hash(self):
        """Generate a hash for deduplication based on key attributes"""
        import hashlib
        
        # Create a string from key attributes
        hash_string = f"{self.file_path}:{self.line_number}:{self.title}:{self.category}"
        
        # Generate SHA-256 hash
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        # Auto-generate hash if not set
        if not self.finding_hash:
            self.finding_hash = self.generate_hash()
        
        super().save(*args, **kwargs)
