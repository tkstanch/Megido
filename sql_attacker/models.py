from django.db import models
from django.utils import timezone
import json


class SQLInjectionTask(models.Model):
    """
    Model to track SQL injection attack tasks.
    Stores target information, attack configuration, and execution status.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('awaiting_confirmation', 'Awaiting Confirmation'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    METHOD_CHOICES = [
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('DELETE', 'DELETE'),
        ('PATCH', 'PATCH'),
    ]
    
    # Target information
    target_url = models.URLField(max_length=2048, db_index=True, 
                                 help_text="Target URL to test for SQL injection")
    http_method = models.CharField(max_length=10, choices=METHOD_CHOICES, default='GET',
                                   help_text="HTTP method to use")
    
    # Parameters
    get_params = models.JSONField(blank=True, null=True, 
                                   help_text="GET parameters as JSON object")
    post_params = models.JSONField(blank=True, null=True,
                                    help_text="POST parameters as JSON object")
    cookies = models.JSONField(blank=True, null=True,
                               help_text="Cookies as JSON object")
    headers = models.JSONField(blank=True, null=True,
                               help_text="Custom headers as JSON object")
    
    # Attack configuration
    enable_error_based = models.BooleanField(default=True,
                                             help_text="Enable error-based SQL injection detection")
    enable_time_based = models.BooleanField(default=True,
                                            help_text="Enable time-based (blind) SQL injection detection")
    enable_exploitation = models.BooleanField(default=True,
                                              help_text="Attempt exploitation if vulnerability found")
    
    # Stealth configuration
    use_random_delays = models.BooleanField(default=False,
                                           help_text="Use random delays between requests")
    min_delay = models.FloatField(default=0.5, help_text="Minimum delay in seconds")
    max_delay = models.FloatField(default=2.0, help_text="Maximum delay in seconds")
    randomize_user_agent = models.BooleanField(default=True,
                                               help_text="Use randomized User-Agent headers")
    use_payload_obfuscation = models.BooleanField(default=False,
                                                   help_text="Obfuscate payloads to evade WAF")
    
    # Enhanced stealth configuration (NEW)
    max_requests_per_minute = models.IntegerField(default=20,
                                                   help_text="Maximum requests per minute (rate limiting)")
    enable_jitter = models.BooleanField(default=True,
                                       help_text="Add random jitter to timing delays")
    randomize_headers = models.BooleanField(default=True,
                                           help_text="Randomize HTTP headers (Referer, Accept-Language, etc.)")
    max_retries = models.IntegerField(default=3,
                                     help_text="Maximum retry attempts for failed requests")
    
    # Interactive mode configuration (NEW)
    require_confirmation = models.BooleanField(default=False,
                                              help_text="Require manual confirmation after parameter discovery")
    awaiting_confirmation = models.BooleanField(default=False,
                                               help_text="Task is waiting for confirmation to proceed")
    selected_params = models.JSONField(blank=True, null=True,
                                      help_text="Manually selected parameters to test")
    
    # OOB (Out-of-Band) configuration – enabled by default; requires an
    # attacker-controlled listener to receive DNS/HTTP callbacks.
    enable_oob = models.BooleanField(
        default=True,
        help_text="Enable OOB payload generation (requires oob_attacker_host to attempt callbacks)",
    )
    oob_attacker_host = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text="Attacker-controlled hostname/IP for OOB callbacks (e.g. burpcollaborator.net subdomain)",
    )
    oob_max_payloads = models.IntegerField(
        default=5,
        help_text="Maximum number of OOB payloads to attempt per task (rate-limiting cap)",
    )
    oob_max_retries = models.IntegerField(
        default=2,
        help_text="Maximum retry attempts per OOB payload",
    )
    oob_exfil_expression = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text=(
            "SQL expression to exfiltrate via OOB (e.g. @@version, user). "
            "Leave blank to use the safe per-DB default (user/version)."
        ),
    )

    # Manipulator integration
    use_manipulator = models.BooleanField(
        default=False,
        help_text="Use Manipulator app tricks and encodings to enhance SQL injection payloads"
    )
    manipulator_encodings = models.JSONField(
        blank=True, null=True,
        help_text="Selected encoding techniques from Manipulator app"
    )
    manipulator_trick_ids = models.JSONField(
        blank=True, null=True,
        help_text="Selected manipulation trick IDs from Manipulator app"
    )

    # Celery integration
    celery_task_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Celery task ID for the background worker job",
    )
    current_stage = models.CharField(
        max_length=50,
        blank=True,
        default='',
        help_text="Current pipeline stage name for real-time progress reporting",
    )

    # Status and tracking
    status = models.CharField(max_length=21, choices=STATUS_CHOICES, default='pending', 
                             db_index=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    
    # Parameter discovery
    discovered_params = models.JSONField(blank=True, null=True,
                                        help_text="Parameters discovered during attack")
    auto_discover_params = models.BooleanField(default=True,
                                              help_text="Automatically discover parameters from target page")
    
    # Results summary
    vulnerabilities_found = models.IntegerField(default=0,
                                               help_text="Number of vulnerabilities found")
    error_message = models.TextField(blank=True, 
                                     help_text="Error message if task failed")
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'SQL Injection Task'
        verbose_name_plural = 'SQL Injection Tasks'
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['target_url', 'status']),
        ]
    
    def __str__(self):
        return f"SQLi Task {self.id} - {self.target_url[:50]} ({self.status})"
    
    def get_params_dict(self):
        """Get GET parameters as dict"""
        return self.get_params if self.get_params else {}
    
    def get_post_dict(self):
        """Get POST parameters as dict"""
        return self.post_params if self.post_params else {}
    
    def get_cookies_dict(self):
        """Get cookies as dict"""
        return self.cookies if self.cookies else {}
    
    def get_headers_dict(self):
        """Get headers as dict"""
        return self.headers if self.headers else {}


class SQLInjectionResult(models.Model):
    """
    Model to store SQL injection detection and exploitation results.
    Each result represents a specific vulnerable parameter or finding.
    
    Enhanced to support multi-context injection attacks (SQL, LDAP, XPath, etc.).
    """
    INJECTION_TYPE_CHOICES = [
        ('error_based', 'Error-based'),
        ('time_based', 'Time-based (Blind)'),
        ('union_based', 'UNION-based'),
        ('boolean_based', 'Boolean-based'),
        ('stacked_queries', 'Stacked Queries'),
    ]
    
    # Multi-context injection support
    INJECTION_CONTEXT_CHOICES = [
        ('sql', 'SQL'),
        ('ldap', 'LDAP'),
        ('xpath', 'XPath'),
        ('message_queue', 'Message Queue'),
        ('custom_query', 'Custom Query Language'),
    ]
    
    task = models.ForeignKey(SQLInjectionTask, on_delete=models.CASCADE,
                            related_name='results',
                            help_text="The attack task this result belongs to")
    
    # Vulnerability details
    injection_type = models.CharField(max_length=50, choices=INJECTION_TYPE_CHOICES,
                                     db_index=True,
                                     help_text="Type of SQL injection detected")
    vulnerable_parameter = models.CharField(max_length=255,
                                           help_text="Name of the vulnerable parameter")
    parameter_type = models.CharField(max_length=20, 
                                     help_text="Type: GET, POST, COOKIE, HEADER")
    
    # Detection details
    test_payload = models.TextField(help_text="Payload used to detect the vulnerability")
    detection_evidence = models.TextField(help_text="Evidence that confirms the vulnerability")
    
    # Request/Response details
    request_data = models.JSONField(blank=True, null=True,
                                   help_text="Full request details as JSON")
    response_data = models.JSONField(blank=True, null=True,
                                    help_text="Response details as JSON")
    
    # Exploitation results
    is_exploitable = models.BooleanField(default=False,
                                        help_text="Whether exploitation was successful")
    database_type = models.CharField(max_length=50, blank=True,
                                    help_text="Detected database type (MySQL, PostgreSQL, etc.)")
    database_version = models.CharField(max_length=100, blank=True,
                                       help_text="Database version if extracted")
    current_database = models.CharField(max_length=100, blank=True,
                                       help_text="Current database name if extracted")
    current_user = models.CharField(max_length=100, blank=True,
                                   help_text="Database user if extracted")
    
    # Extracted data
    extracted_tables = models.JSONField(blank=True, null=True,
                                       help_text="List of extracted table names")
    extracted_data = models.JSONField(blank=True, null=True,
                                     help_text="Sample extracted data")
    
    # Parameter discovery metadata
    parameter_source = models.CharField(max_length=20, default='manual',
                                       help_text="Source: manual, form, hidden, link, url, js")
    
    # Advanced detection metrics (NEW)
    confidence_score = models.FloatField(default=0.7,
                                        help_text="Confidence score (0.0-1.0) for detection accuracy")
    risk_score = models.IntegerField(default=50,
                                    help_text="Risk score (0-100) indicating severity and exploitability")
    impact_analysis = models.JSONField(blank=True, null=True,
                                      help_text="Detailed impact demonstration results")
    proof_of_concept = models.JSONField(blank=True, null=True,
                                       help_text="Proof-of-concept queries and findings")
    
    # Multi-context injection fields
    injection_context = models.CharField(
        max_length=50, 
        choices=INJECTION_CONTEXT_CHOICES,
        default='sql',
        db_index=True,
        help_text="Injection context type (SQL, LDAP, XPath, etc.)"
    )
    
    # Visual proof fields (mirroring vulnerability scanner pattern)
    verified = models.BooleanField(
        default=False,
        help_text="Verified through successful exploitation"
    )
    proof_of_impact = models.TextField(
        blank=True, 
        null=True,
        help_text="Evidence of real-world impact"
    )
    visual_proof_path = models.CharField(
        max_length=512, 
        blank=True, 
        null=True, 
        help_text="Path to screenshot or GIF showing exploitation impact"
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
        help_text="Type of visual proof"
    )
    visual_proof_size = models.IntegerField(
        blank=True, 
        null=True, 
        help_text="File size in bytes"
    )
    
    # Visual Evidence Fields
    screenshots = models.JSONField(blank=True, null=True, help_text="Array of screenshot paths")
    video_evidence = models.FileField(upload_to='sql_attacker/videos/%Y/%m/%d/', blank=True, null=True)
    gif_evidence = models.FileField(upload_to='sql_attacker/gifs/%Y/%m/%d/', blank=True, null=True)
    evidence_timeline = models.JSONField(blank=True, null=True, help_text="Timeline of attack steps")

    # Enhanced POC Data
    all_injection_points = models.JSONField(blank=True, null=True, help_text="All discovered injection points")
    successful_payloads = models.JSONField(blank=True, null=True, help_text="All successful payloads by type")
    extracted_sensitive_data = models.JSONField(blank=True, null=True, help_text="Categorized extracted data")

    # Standardised finding schema (evidence packet, location, reproducibility)
    injection_location = models.CharField(
        max_length=20,
        blank=True,
        default='',
        help_text="Where the injection point was found: GET, POST, header, cookie, json",
    )
    evidence_packet = models.JSONField(
        blank=True,
        null=True,
        help_text=(
            "Structured evidence: normalized diff summary, matched patterns, "
            "classifier outcome, timing delta"
        ),
    )
    confidence_rationale = models.TextField(
        blank=True,
        default='',
        help_text="Human-readable explanation of how the confidence score was reached",
    )
    reproduction_steps = models.TextField(
        blank=True,
        default='',
        help_text="Safe, step-by-step instructions to reproduce the finding",
    )

    # Manipulator integration tracking
    manipulator_tricks_used = models.JSONField(
        blank=True, null=True,
        help_text="Manipulation tricks applied from Manipulator app"
    )
    manipulator_encodings_used = models.JSONField(
        blank=True, null=True,
        help_text="Encoding techniques applied from Manipulator app"
    )

    # OOB findings – payloads generated for this result, stored for dashboard display
    oob_findings = models.JSONField(
        blank=True,
        null=True,
        help_text=(
            "OOB payloads generated for this finding. Each entry contains technique, "
            "payload (redacted to first 200 chars), listener_type, and requires_privileges."
        ),
    )

    # Union-based SQL injection PoC HTML evidence
    union_poc_html = models.TextField(
        blank=True,
        null=True,
        help_text=(
            "HTML evidence table generated by the union-based SQL injection PoC module. "
            "Proof-of-concept only – non-destructive (SELECT/UNION payloads only)."
        ),
    )

    # Metadata
    detected_at = models.DateTimeField(default=timezone.now, db_index=True)
    severity = models.CharField(max_length=20, default='critical',
                               help_text="Severity: critical, high, medium, low")
    
    class Meta:
        ordering = ['-detected_at']
        verbose_name = 'Injection Attack Result'
        verbose_name_plural = 'Injection Attack Results'
        indexes = [
            models.Index(fields=['task', 'injection_type']),
            models.Index(fields=['severity', 'detected_at']),
            models.Index(fields=['injection_context', 'detected_at']),
        ]
    
    def __str__(self):
        context_display = self.get_injection_context_display() if self.injection_context != 'sql' else self.get_injection_type_display()
        return (f"{context_display} in {self.vulnerable_parameter} "
                f"({self.task.target_url[:30]}...)")


class BugReport(models.Model):
    """
    Bugzilla-style bug tracking record for a SQL injection finding.

    Each BugReport wraps one SQLInjectionResult and carries its own triage
    lifecycle (status, priority, assignee, FP analysis, bounty tracking).
    """

    STATUS_CHOICES = [
        ('new', 'New'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('duplicate', 'Duplicate'),
        ('wont_fix', "Won't Fix"),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('verified', 'Verified'),
    ]

    PRIORITY_CHOICES = [
        ('P1_critical', 'P1 – Critical'),
        ('P2_high', 'P2 – High'),
        ('P3_medium', 'P3 – Medium'),
        ('P4_low', 'P4 – Low'),
        ('P5_info', 'P5 – Informational'),
    ]

    BOUNTY_STATUS_CHOICES = [
        ('not_submitted', 'Not Submitted'),
        ('submitted', 'Submitted'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('paid', 'Paid'),
    ]

    result = models.ForeignKey(
        SQLInjectionResult,
        on_delete=models.CASCADE,
        related_name='bug_reports',
        help_text="The injection finding this bug report tracks",
    )
    bug_id = models.CharField(
        max_length=30,
        unique=True,
        db_index=True,
        help_text="Auto-generated unique identifier (e.g. SQLI-2026-001)",
    )
    title = models.CharField(
        max_length=255,
        help_text="Auto-generated descriptive bug title",
    )

    # Triage fields
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='new',
        db_index=True,
    )
    priority = models.CharField(
        max_length=15,
        choices=PRIORITY_CHOICES,
        default='P3_medium',
        db_index=True,
    )
    assignee = models.CharField(max_length=100, blank=True, default='')
    triage_notes = models.TextField(blank=True, default='')
    false_positive_reason = models.TextField(
        blank=True,
        default='',
        help_text="Justification when status=false_positive",
    )
    false_positive_indicators = models.JSONField(
        blank=True,
        null=True,
        help_text="Automated FP detection signals from FalsePositiveReducer",
    )
    verified_by = models.CharField(max_length=100, blank=True, default='')
    verified_at = models.DateTimeField(blank=True, null=True)
    resolution = models.TextField(blank=True, default='')

    # Bounty tracking
    bounty_status = models.CharField(
        max_length=15,
        choices=BOUNTY_STATUS_CHOICES,
        default='not_submitted',
        db_index=True,
    )
    bounty_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        blank=True,
        null=True,
        help_text="Bounty amount awarded (USD)",
    )
    bounty_platform = models.CharField(
        max_length=50,
        blank=True,
        default='',
        help_text="e.g. HackerOne, Bugcrowd, Intigriti",
    )
    bounty_submission_url = models.URLField(max_length=1024, blank=True, default='')

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Bug Report'
        verbose_name_plural = 'Bug Reports'
        indexes = [
            models.Index(fields=['status', 'priority']),
            models.Index(fields=['bounty_status', 'created_at']),
        ]

    def __str__(self):
        return f"{self.bug_id} – {self.title[:60]}"

    @property
    def fp_score(self):
        """Return the numeric FP score stored in false_positive_indicators, or 0."""
        indicators = self.false_positive_indicators or {}
        return indicators.get('fp_score', 0.0)

    @property
    def is_likely_false_positive(self):
        return self.fp_score > 0.85


class BountyImpactReport(models.Model):
    """
    Detailed bounty-submission-ready impact report linked to a BugReport.
    """

    PLATFORM_CHOICES = [
        ('hackerone', 'HackerOne'),
        ('bugcrowd', 'Bugcrowd'),
        ('intigriti', 'Intigriti'),
        ('custom', 'Custom / Other'),
    ]

    bug_report = models.OneToOneField(
        BugReport,
        on_delete=models.CASCADE,
        related_name='impact_report',
        help_text="The BugReport this impact report supplements",
    )

    # CVSS & Classification
    cvss_score = models.FloatField(
        default=0.0,
        help_text="Auto-calculated CVSS v3.1 base score",
    )
    cvss_vector = models.CharField(
        max_length=100,
        blank=True,
        default='',
        help_text="CVSS v3.1 vector string",
    )
    cwe_id = models.CharField(
        max_length=20,
        blank=True,
        default='CWE-89',
        help_text="CWE identifier (e.g. CWE-89 for SQL Injection)",
    )

    # Report sections
    impact_summary = models.TextField(blank=True, default='')
    technical_details = models.TextField(blank=True, default='')
    reproduction_steps = models.TextField(blank=True, default='')
    business_impact = models.TextField(blank=True, default='')
    remediation = models.TextField(blank=True, default='')
    ready_to_submit_report = models.TextField(
        blank=True,
        default='',
        help_text="Complete formatted bounty submission text",
    )

    # Bounty estimation
    estimated_bounty_range = models.CharField(
        max_length=50,
        blank=True,
        default='',
        help_text="e.g. $500-$2000",
    )
    submission_platform_template = models.CharField(
        max_length=20,
        choices=PLATFORM_CHOICES,
        default='hackerone',
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Bounty Impact Report'
        verbose_name_plural = 'Bounty Impact Reports'

    def __str__(self):
        return f"Impact Report for {self.bug_report.bug_id}"
