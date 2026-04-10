from django.db import models


VULNERABILITY_TYPE_CHOICES = [
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
    ('email_rce', 'Email Field RCE'),
    ('ai_llm', 'AI/LLM Vulnerability'),
    ('dos', 'Denial of Service (DoS)'),
    ('security_misconfig', 'Security Misconfiguration'),
    ('sensitive_data', 'Sensitive Data Exposure'),
    ('weak_password', 'Weak Password Policy'),
    ('bac', 'Broken Access Control'),
    ('username_enum', 'Username/Email Enumeration'),
    ('captcha_bypass', 'Captcha Bypass'),
    ('unsafe_upload', 'Unsafe File Upload'),
    ('subdomain_takeover', 'Subdomain Takeover'),
    ('exif_data', 'EXIF Geolocation Data Exposure'),
    ('api_key_exposure', 'Private API Key Exposure'),
    ('other', 'Other'),
]


class ScanTarget(models.Model):
    name = models.CharField(max_length=255, blank=True, null=True)
    url = models.URLField(max_length=2048)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name or self.url


class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='scans')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    warnings = models.JSONField(default=list, blank=True)
    error_message = models.TextField(null=True, blank=True)
    enable_dos_testing = models.BooleanField(default=False)
    enable_sqli_testing = models.BooleanField(default=True)
    program_scope = models.ForeignKey(
        'ProgramScope',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scans',
    )

    def __str__(self):
        return f"Scan {self.id} for {self.target}"


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    EXPLOIT_STATUS_CHOICES = [
        ('not_attempted', 'Not Attempted'),
        ('in_progress', 'In Progress'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('no_plugin', 'No Plugin Available'),
    ]

    FALSE_POSITIVE_CHOICES = [
        ('not_reviewed', 'Not Reviewed'),
        ('confirmed', 'Confirmed Vulnerability'),
        ('false_positive', 'False Positive'),
        ('needs_review', 'Needs Review'),
    ]

    vulnerability_type = models.CharField(
        max_length=50, choices=VULNERABILITY_TYPE_CHOICES
    )
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    url = models.URLField(max_length=2048)
    parameter = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField()
    evidence = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    discovered_at = models.DateTimeField(auto_now_add=True)
    exploited = models.BooleanField(default=False)
    exploit_status = models.CharField(
        max_length=20, choices=EXPLOIT_STATUS_CHOICES, default='not_attempted'
    )
    exploit_result = models.TextField(blank=True, null=True)
    exploit_attempted_at = models.DateTimeField(blank=True, null=True)

    # Advanced features (migration 0003)
    risk_score = models.FloatField(default=0.0, help_text='Composite risk score (0-100)')
    risk_level = models.CharField(max_length=20, default='medium', help_text='Risk level: critical, high, medium, low')
    confidence_score = models.FloatField(default=0.5, help_text='Confidence in finding (0.0-1.0)')
    verified = models.BooleanField(default=False, help_text='Verified through successful exploitation')
    proof_of_impact = models.TextField(blank=True, null=True, help_text='Evidence of real-world impact')
    false_positive_status = models.CharField(
        max_length=20,
        choices=FALSE_POSITIVE_CHOICES,
        default='not_reviewed',
    )
    false_positive_reason = models.TextField(blank=True, null=True)
    reviewed_by = models.CharField(max_length=255, blank=True, null=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)
    compliance_violations = models.JSONField(default=dict, blank=True, help_text='Mapping to compliance frameworks')
    remediation_priority = models.IntegerField(default=3, help_text='Priority 1-5 (1=highest)')
    remediation_effort = models.CharField(max_length=20, default='medium', blank=True, null=True)

    # Visual proof fields (migration 0006)
    visual_proof_path = models.CharField(max_length=512, blank=True, null=True)
    visual_proof_type = models.CharField(max_length=50, blank=True, null=True)
    visual_proof_size = models.IntegerField(default=0)

    # Payload / repeater fields (migration 0008)
    successful_payloads = models.JSONField(
        default=list, blank=True,
        help_text='List of payloads that successfully exploited the vulnerability',
    )
    repeater_data = models.JSONField(
        default=list, blank=True,
        help_text='Copy-paste ready HTTP requests for manual verification in repeater app',
    )

    # HTTP traffic field (migration 0009)
    http_traffic = models.JSONField(
        default=dict, blank=True,
        help_text='Captured HTTP request/response traffic during exploitation',
    )

    # Visual proof status (migration 0010)
    visual_proof_status = models.CharField(max_length=50, blank=True, null=True)

    # Bounty report field (migration 0012)
    bounty_report = models.JSONField(default=dict, blank=True, null=True)

    # PoC fields (migration 0013)
    poc_html_report_path = models.CharField(
        max_length=512, blank=True, null=True,
        help_text='Path to the generated self-contained HTML PoC report',
    )
    poc_step_count = models.IntegerField(
        default=0, help_text='Number of completed PoC exploitation steps',
    )
    poc_steps_json = models.TextField(
        blank=True, null=True,
        help_text='JSON array of step-by-step proof-of-concept exploitation data',
    )

    def __str__(self):
        return f"Vulnerability in {self.url}"

    class Meta:
        indexes = [
            models.Index(fields=['risk_score'], name='scanner_vul_risk_sc_b879c5_idx'),
            models.Index(fields=['verified'], name='scanner_vul_verifie_aab60f_idx'),
            models.Index(fields=['false_positive_status'], name='scanner_vul_false_p_3e73b7_idx'),
        ]


class ExploitMedia(models.Model):
    media_type = models.CharField(max_length=50)
    title = models.CharField(max_length=255)
    description = models.TextField()
    file_path = models.FileField(upload_to='exploit_media/')
    file_name = models.CharField(max_length=255)
    file_size = models.FloatField()
    sequence_order = models.IntegerField()
    exploit_step = models.CharField(max_length=50, null=True, blank=True)
    payload_used = models.CharField(max_length=255, null=True, blank=True)
    capture_timestamp = models.DateTimeField(auto_now_add=True)
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE, related_name='exploit_media'
    )

    def __str__(self):
        return self.title

    class Meta:
        indexes = [
            models.Index(fields=['vulnerability', 'sequence_order'], name='scanner_exp_vulnera_1eff1f_idx'),
            models.Index(fields=['media_type'], name='scanner_exp_media_t_2ddbb3_idx'),
        ]


# ---------------------------------------------------------------------------
# Engine models (migration 0004)
# ---------------------------------------------------------------------------

class EngineScan(models.Model):
    TARGET_TYPE_CHOICES = [
        ('path', 'File Path'),
        ('url', 'URL'),
        ('git', 'Git Repository'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    target_path = models.CharField(max_length=2048, help_text='Path or URL to scan')
    target_type = models.CharField(max_length=20, choices=TARGET_TYPE_CHOICES, default='path')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    execution_time = models.FloatField(default=0.0, help_text='Total execution time in seconds')
    enabled_engines = models.JSONField(default=list, blank=True, help_text='List of engine IDs enabled for this scan')
    engine_categories = models.JSONField(default=list, blank=True, help_text='Engine categories used')
    parallel_execution = models.BooleanField(default=True)
    max_workers = models.IntegerField(default=4)
    total_engines_run = models.IntegerField(default=0)
    successful_engines = models.IntegerField(default=0)
    failed_engines = models.IntegerField(default=0)
    total_findings = models.IntegerField(default=0)
    findings_by_severity = models.JSONField(default=dict, blank=True, help_text='Count of findings by severity')
    created_by = models.CharField(max_length=255, blank=True, null=True)
    config_snapshot = models.JSONField(default=dict, blank=True, help_text='Configuration used for this scan')

    class Meta:
        ordering = ['-started_at']
        indexes = [
            models.Index(fields=['status'], name='scanner_eng_status_6b1bf6_idx'),
            models.Index(fields=['started_at'], name='scanner_eng_started_6208ec_idx'),
            models.Index(fields=['target_type'], name='scanner_eng_target__d75a1d_idx'),
        ]

    def __str__(self):
        return f"EngineScan {self.id} [{self.status}] {self.target_path}"


class EngineExecution(models.Model):
    CATEGORY_CHOICES = [
        ('sast', 'SAST'),
        ('dast', 'DAST'),
        ('sca', 'SCA'),
        ('secrets', 'Secrets'),
        ('container', 'Container'),
        ('cloud', 'Cloud'),
        ('custom', 'Custom'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]

    engine_scan = models.ForeignKey(EngineScan, on_delete=models.CASCADE, related_name='engine_executions')
    engine_id = models.CharField(max_length=100, help_text='Engine identifier')
    engine_name = models.CharField(max_length=255, help_text='Human-readable engine name')
    engine_category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    execution_time = models.FloatField(default=0.0, help_text='Execution time in seconds')
    findings_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, null=True)
    engine_config = models.JSONField(default=dict, blank=True, help_text='Configuration used for this engine')

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f"EngineExecution {self.id} [{self.engine_name}]"


class EngineFinding(models.Model):
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    STATUS_CHOICES = [
        ('new', 'New'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('fixed', 'Fixed'),
        ('accepted', 'Accepted Risk'),
    ]

    engine_scan = models.ForeignKey(EngineScan, on_delete=models.CASCADE, related_name='findings')
    engine_execution = models.ForeignKey(EngineExecution, on_delete=models.CASCADE, related_name='findings')
    engine_id = models.CharField(max_length=100)
    engine_name = models.CharField(max_length=255)
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    confidence = models.FloatField(default=1.0, help_text='Confidence level 0.0-1.0')
    file_path = models.CharField(max_length=2048, blank=True, null=True)
    line_number = models.IntegerField(blank=True, null=True)
    url = models.URLField(max_length=2048, blank=True, null=True)
    category = models.CharField(max_length=100, blank=True, null=True)
    cwe_id = models.CharField(max_length=20, blank=True, null=True, help_text='CWE ID')
    cve_id = models.CharField(max_length=50, blank=True, null=True, help_text='CVE ID')
    owasp_category = models.CharField(max_length=100, blank=True, null=True)
    evidence = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)
    references = models.JSONField(default=list, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    raw_output = models.JSONField(default=dict, blank=True)
    finding_hash = models.CharField(max_length=64, blank=True, null=True, help_text='Hash for deduplication')
    is_duplicate = models.BooleanField(default=False)
    duplicate_of = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True, related_name='duplicates'
    )
    reviewed = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')

    class Meta:
        indexes = [
            models.Index(fields=['severity'], name='scanner_eng_severit_a5cf71_idx'),
        ]

    def __str__(self):
        return f"EngineFinding {self.id} [{self.severity}] {self.title}"


# ---------------------------------------------------------------------------
# Heat Map models (migration 0016)
# ---------------------------------------------------------------------------

class ProgramScope(models.Model):
    """Stores bug bounty program or engagement scope rules."""

    name = models.CharField(max_length=255, help_text='Name of the bug bounty program or engagement')
    in_scope_domains = models.JSONField(
        default=list,
        blank=True,
        help_text='Domains/URLs allowed to be scanned (supports wildcards like *.example.com)',
    )
    out_of_scope_domains = models.JSONField(
        default=list,
        blank=True,
        help_text='Domains/URLs that must NOT be scanned',
    )
    allowed_vulnerability_types = models.JSONField(
        default=list,
        blank=True,
        help_text='Vulnerability types allowed to test; empty means all allowed',
    )
    disallowed_vulnerability_types = models.JSONField(
        default=list,
        blank=True,
        help_text='Vulnerability types explicitly prohibited',
    )
    max_requests_per_second = models.FloatField(
        null=True,
        blank=True,
        help_text='Rate limit: maximum requests per second (optional)',
    )
    testing_window_start = models.TimeField(
        null=True,
        blank=True,
        help_text='Start of allowed testing window (optional)',
    )
    testing_window_end = models.TimeField(
        null=True,
        blank=True,
        help_text='End of allowed testing window (optional)',
    )
    notes = models.TextField(
        blank=True,
        default='',
        help_text='Free-form program rules or special instructions',
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class HeatMapScan(models.Model):
    """Stores the result of a heat map analysis for a target URL."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    target_url = models.URLField(max_length=2048)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    total_hotspots = models.IntegerField(default=0)
    summary = models.JSONField(default=dict, blank=True)
    risk_scores = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True, null=True)
    program_scope = models.ForeignKey(
        ProgramScope,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='heat_map_scans',
    )

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f"HeatMapScan {self.id} [{self.status}] {self.target_url}"


class HeatMapHotspot(models.Model):
    """A single hot spot discovered during a heat map analysis."""

    PRIORITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    heat_map_scan = models.ForeignKey(HeatMapScan, on_delete=models.CASCADE, related_name='hotspots')
    category = models.CharField(max_length=100)
    category_label = models.CharField(max_length=255, blank=True, null=True)
    url = models.URLField(max_length=2048)
    parameter = models.CharField(max_length=255, blank=True, null=True)
    risk_score = models.IntegerField(default=5)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='Medium')
    vulnerabilities = models.JSONField(default=list, blank=True)
    payloads = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True, null=True)
    evidence = models.TextField(blank=True, null=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-risk_score', 'priority']
        indexes = [
            models.Index(fields=['priority'], name='scanner_hm_priority_idx'),
            models.Index(fields=['risk_score'], name='scanner_hm_risk_idx'),
        ]

    def __str__(self):
        return f"HeatMapHotspot {self.id} [{self.priority}] {self.category} @ {self.url}"
