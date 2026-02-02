"""
Models for the Browser Extension Decompiler app.

These models track browser extension packages, decompilation jobs,
obfuscation techniques, and analysis results.
"""
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import URLValidator
import uuid


class ExtensionPackage(models.Model):
    """
    Model for storing captured browser extension packages.
    
    Responsibilities:
    - Store metadata about captured extensions (Java applets, Flash SWF, Silverlight XAP)
    - Track download source and original bytecode
    - Maintain version history and package integrity
    
    TODO: Implement checksum validation
    TODO: Add support for detecting package type automatically
    """
    
    EXTENSION_TYPES = [
        ('java_applet', 'Java Applet (.jar/.class)'),
        ('flash', 'Flash/ActionScript (.swf)'),
        ('silverlight', 'Silverlight (.xap)'),
        ('javascript', 'JavaScript Extension'),
        ('unknown', 'Unknown Type'),
    ]
    
    STATUS_CHOICES = [
        ('downloaded', 'Downloaded'),
        ('pending_analysis', 'Pending Analysis'),
        ('analyzed', 'Analyzed'),
        ('failed', 'Failed'),
    ]
    
    package_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)
    name = models.CharField(max_length=255, help_text="Name of the extension package")
    extension_type = models.CharField(max_length=20, choices=EXTENSION_TYPES, default='unknown')
    
    # Download and source information
    download_url = models.URLField(
        max_length=2048,
        validators=[URLValidator()],
        help_text="Original URL where the extension was captured"
    )
    downloaded_at = models.DateTimeField(auto_now_add=True)
    downloaded_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='downloaded_extensions'
    )
    
    # Package data
    bytecode_file = models.FileField(
        upload_to='decompiler/bytecode/%Y/%m/%d/',
        help_text="Raw bytecode/package file"
    )
    file_size = models.BigIntegerField(help_text="Size in bytes")
    checksum_md5 = models.CharField(max_length=32, blank=True)
    checksum_sha256 = models.CharField(max_length=64, blank=True)
    
    # Metadata
    version = models.CharField(max_length=50, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='downloaded')
    notes = models.TextField(blank=True, help_text="Additional notes about this package")
    
    class Meta:
        ordering = ['-downloaded_at']
        indexes = [
            models.Index(fields=['extension_type', 'status']),
            models.Index(fields=['downloaded_at']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.extension_type})"


class DecompilationJob(models.Model):
    """
    Model for tracking decompilation jobs and their results.
    
    Responsibilities:
    - Track the decompilation workflow status
    - Store decompiled source code
    - Link to original bytecode package
    - Record decompilation tools and settings used
    
    TODO: Implement retry mechanism for failed jobs
    TODO: Add support for incremental/partial decompilation
    """
    
    JOB_STATUS = [
        ('queued', 'Queued'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    job_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)
    extension_package = models.ForeignKey(
        ExtensionPackage,
        on_delete=models.CASCADE,
        related_name='decompilation_jobs'
    )
    
    # Job tracking
    status = models.CharField(max_length=20, choices=JOB_STATUS, default='queued')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='decompilation_jobs'
    )
    
    # Decompilation settings
    decompiler_tool = models.CharField(
        max_length=50,
        help_text="Tool used for decompilation (e.g., JAD, Krakatau, JPEXS)"
    )
    decompiler_version = models.CharField(max_length=50, blank=True)
    options = models.JSONField(
        default=dict,
        blank=True,
        help_text="Decompiler options and flags"
    )
    
    # Results
    decompiled_source = models.FileField(
        upload_to='decompiler/source/%Y/%m/%d/',
        null=True,
        blank=True,
        help_text="Archive of decompiled source code"
    )
    log_output = models.TextField(blank=True, help_text="Decompilation log output")
    error_message = models.TextField(blank=True, help_text="Error message if failed")
    
    # Analysis metrics
    num_classes_found = models.IntegerField(default=0, help_text="Number of classes/modules found")
    num_methods_found = models.IntegerField(default=0, help_text="Number of methods/functions found")
    obfuscation_detected = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['extension_package', 'status']),
        ]
    
    def __str__(self):
        return f"Decompilation {self.job_id} - {self.status}"


class ObfuscationTechnique(models.Model):
    """
    Model for tracking detected obfuscation techniques in extensions.
    
    Responsibilities:
    - Catalog common obfuscation techniques
    - Track detection patterns and signatures
    - Link to deobfuscation strategies
    
    TODO: Implement pattern matching engine
    TODO: Add machine learning-based detection
    """
    
    OBFUSCATION_TYPES = [
        ('name_mangling', 'Name Mangling/Renaming'),
        ('string_encryption', 'String Encryption'),
        ('control_flow', 'Control Flow Obfuscation'),
        ('dead_code', 'Dead Code Injection'),
        ('opaque_predicates', 'Opaque Predicates'),
        ('packing', 'Code Packing/Compression'),
        ('reflection', 'Reflection-based Obfuscation'),
        ('other', 'Other/Unknown'),
    ]
    
    technique_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)
    name = models.CharField(max_length=100, help_text="Name of the obfuscation technique")
    obfuscation_type = models.CharField(max_length=30, choices=OBFUSCATION_TYPES)
    
    description = models.TextField(help_text="Description of the technique")
    detection_pattern = models.TextField(
        blank=True,
        help_text="Regex or signature for detecting this technique"
    )
    deobfuscation_strategy = models.TextField(
        blank=True,
        help_text="Strategy or algorithm for defeating this technique"
    )
    
    # Tool information
    common_tools = models.CharField(
        max_length=255,
        blank=True,
        help_text="Known obfuscation tools that use this technique"
    )
    
    # Metadata
    severity = models.IntegerField(
        default=5,
        help_text="Difficulty level (1-10) of deobfuscating this technique"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-severity', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.obfuscation_type})"


class DetectedObfuscation(models.Model):
    """
    Model for linking decompilation jobs to detected obfuscation techniques.
    
    Responsibilities:
    - Track which obfuscation techniques were found in which jobs
    - Store confidence scores and evidence
    - Enable analysis of obfuscation patterns
    
    TODO: Implement confidence scoring algorithm
    TODO: Add automatic deobfuscation triggering
    """
    
    detection_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)
    decompilation_job = models.ForeignKey(
        DecompilationJob,
        on_delete=models.CASCADE,
        related_name='detected_obfuscations'
    )
    obfuscation_technique = models.ForeignKey(
        ObfuscationTechnique,
        on_delete=models.CASCADE,
        related_name='detections'
    )
    
    # Detection details
    confidence_score = models.FloatField(
        help_text="Confidence score (0.0-1.0) that this technique is present"
    )
    evidence = models.TextField(
        blank=True,
        help_text="Code snippets or patterns that triggered detection"
    )
    location = models.CharField(
        max_length=512,
        blank=True,
        help_text="File/class/method where technique was detected"
    )
    
    detected_at = models.DateTimeField(auto_now_add=True)
    deobfuscated = models.BooleanField(default=False, help_text="Whether deobfuscation was attempted")
    deobfuscation_success = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-confidence_score', '-detected_at']
        unique_together = ['decompilation_job', 'obfuscation_technique', 'location']
    
    def __str__(self):
        return f"{self.obfuscation_technique.name} in {self.decompilation_job.job_id}"


class ExtensionAnalysis(models.Model):
    """
    Model for storing analysis results of decompiled extensions.
    
    Responsibilities:
    - Store findings from source code analysis
    - Track API calls, network requests, and data flows
    - Identify security vulnerabilities and privacy concerns
    - Enable programmatic interaction with target web apps
    
    TODO: Implement automated vulnerability scanning
    TODO: Add support for dynamic analysis integration
    """
    
    RISK_LEVELS = [
        ('low', 'Low Risk'),
        ('medium', 'Medium Risk'),
        ('high', 'High Risk'),
        ('critical', 'Critical Risk'),
    ]
    
    analysis_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)
    decompilation_job = models.OneToOneField(
        DecompilationJob,
        on_delete=models.CASCADE,
        related_name='analysis'
    )
    
    # Analysis metadata
    analyzed_at = models.DateTimeField(auto_now_add=True)
    analyzed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='analyses'
    )
    
    # Findings
    api_endpoints = models.JSONField(
        default=list,
        blank=True,
        help_text="List of API endpoints the extension communicates with"
    )
    network_requests = models.JSONField(
        default=list,
        blank=True,
        help_text="Captured or identified network requests"
    )
    data_flows = models.JSONField(
        default=list,
        blank=True,
        help_text="Data flow analysis results"
    )
    
    # Security findings
    vulnerabilities = models.JSONField(
        default=list,
        blank=True,
        help_text="List of identified security vulnerabilities"
    )
    privacy_concerns = models.JSONField(
        default=list,
        blank=True,
        help_text="Privacy issues (data collection, tracking, etc.)"
    )
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS, default='low')
    
    # Manipulation capabilities
    javascript_hooks = models.JSONField(
        default=list,
        blank=True,
        help_text="Identified JavaScript injection points for manipulation"
    )
    dom_elements = models.JSONField(
        default=list,
        blank=True,
        help_text="DOM elements the extension interacts with"
    )
    
    # Summary
    summary = models.TextField(blank=True, help_text="Human-readable analysis summary")
    recommendations = models.TextField(blank=True, help_text="Security recommendations")
    
    class Meta:
        ordering = ['-analyzed_at']
        verbose_name_plural = 'Extension Analyses'
    
    def __str__(self):
        return f"Analysis of {self.decompilation_job.extension_package.name}"


class TrafficInterception(models.Model):
    """
    Model for capturing intercepted browser extension traffic.
    
    Responsibilities:
    - Store intercepted HTTP/HTTPS traffic from extensions
    - Capture serialized data (Java serialization, AMF, etc.)
    - Link traffic to specific extension packages
    - Enable traffic replay and manipulation
    
    TODO: Implement protocol-specific parsers (AMF, Java serialization, etc.)
    TODO: Add support for WebSocket traffic
    """
    
    PROTOCOL_TYPES = [
        ('http', 'HTTP'),
        ('https', 'HTTPS'),
        ('websocket', 'WebSocket'),
        ('amf', 'Action Message Format (AMF)'),
        ('java_serialization', 'Java Serialization'),
        ('custom', 'Custom Protocol'),
    ]
    
    interception_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, primary_key=True)
    extension_package = models.ForeignKey(
        ExtensionPackage,
        on_delete=models.CASCADE,
        related_name='intercepted_traffic',
        null=True,
        blank=True
    )
    
    # Traffic metadata
    timestamp = models.DateTimeField(auto_now_add=True)
    protocol = models.CharField(max_length=30, choices=PROTOCOL_TYPES)
    
    # Request information
    request_url = models.URLField(max_length=2048)
    request_method = models.CharField(max_length=10, default='GET')
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.BinaryField(blank=True, help_text="Raw request body")
    
    # Response information
    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.BinaryField(blank=True, help_text="Raw response body")
    
    # Analysis
    is_serialized = models.BooleanField(default=False)
    serialization_format = models.CharField(max_length=50, blank=True)
    deserialized_data = models.JSONField(
        default=dict,
        blank=True,
        help_text="Deserialized/parsed data"
    )
    
    # Context
    user_agent = models.CharField(max_length=512, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['extension_package', 'timestamp']),
            models.Index(fields=['protocol', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.protocol.upper()} {self.request_method} {self.request_url[:50]}"
