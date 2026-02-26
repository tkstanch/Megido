from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


class Scan(models.Model):
    """Model to store scan history and results"""
    target = models.CharField(max_length=500, help_text="Target domain or URL")
    scan_date = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='discover_scans')
    
    # Results stored as JSON text fields
    wayback_urls = models.TextField(blank=True, help_text="JSON array of Wayback Machine URLs")
    shodan_data = models.TextField(blank=True, help_text="JSON data from Shodan API")
    hunter_data = models.TextField(blank=True, help_text="JSON data from Hunter.io API")
    dork_queries = models.TextField(blank=True, help_text="JSON array of Google Dorks")
    dork_results = models.TextField(blank=True, help_text="JSON data with Google Dorks search results")
    
    # Summary fields
    total_urls = models.IntegerField(default=0)
    total_emails = models.IntegerField(default=0)
    
    # Sensitive scan fields
    sensitive_scan_completed = models.BooleanField(default=False)
    sensitive_scan_date = models.DateTimeField(null=True, blank=True)
    total_findings = models.IntegerField(default=0)
    high_risk_findings = models.IntegerField(default=0)
    
    # Metadata
    scan_duration_seconds = models.IntegerField(default=0, help_text="Duration of the scan")
    
    class Meta:
        ordering = ['-scan_date']
        verbose_name = 'OSINT Scan'
        verbose_name_plural = 'OSINT Scans'
        indexes = [
            models.Index(fields=['-scan_date']),
            models.Index(fields=['target']),
            models.Index(fields=['user', '-scan_date']),
        ]
    
    def __str__(self):
        return f"{self.target} - {self.scan_date.strftime('%Y-%m-%d %H:%M')}"


class SensitiveFinding(models.Model):
    """Model to store sensitive information findings"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='sensitive_findings')
    url = models.URLField(max_length=2000)
    finding_type = models.CharField(max_length=100)
    value = models.TextField(help_text="The actual sensitive data found")
    context = models.TextField(help_text="Surrounding text for context")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    position = models.IntegerField(null=True, blank=True, help_text="Position in content")
    discovered_at = models.DateTimeField(auto_now_add=True)
    verified = models.BooleanField(default=False)
    false_positive = models.BooleanField(default=False)
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['scan', 'severity']),
            models.Index(fields=['finding_type']),
            models.Index(fields=['-discovered_at']),
        ]
        verbose_name = 'Sensitive Finding'
        verbose_name_plural = 'Sensitive Findings'
    
    def __str__(self):
        return f"{self.finding_type} - {self.severity} - {self.url[:50]}"


class UserActivity(models.Model):
    """Track user activities for analytics"""
    ACTION_CHOICES = [
        ('scan_start', 'Scan Started'),
        ('scan_view', 'Scan Viewed'),
        ('finding_verify', 'Finding Verified'),
        ('finding_false_positive', 'Finding Marked False Positive'),
        ('export_data', 'Data Exported'),
        ('dashboard_view', 'Dashboard Viewed'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='activities')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    target = models.CharField(max_length=500, blank=True)
    scan = models.ForeignKey(Scan, on_delete=models.SET_NULL, null=True, blank=True, related_name='activities')
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    metadata = models.TextField(blank=True, help_text="Additional JSON metadata")
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'User Activity'
        verbose_name_plural = 'User Activities'
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action']),
        ]
    
    def __str__(self):
        user_str = self.user.username if self.user else 'Anonymous'
        return f"{user_str} - {self.get_action_display()} - {self.timestamp}"


class ScanRecommendation(models.Model):
    """AI/ML-powered recommendations for scans"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recommendations')
    recommended_target = models.CharField(max_length=500)
    reason = models.TextField(help_text="Why this target is recommended")
    confidence_score = models.FloatField(default=0.0, help_text="ML confidence score 0-1")
    based_on_scan = models.ForeignKey(Scan, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-confidence_score', '-created_at']
        verbose_name = 'Scan Recommendation'
        verbose_name_plural = 'Scan Recommendations'
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['-confidence_score']),
        ]
    
    def __str__(self):
        return f"Recommend {self.recommended_target} to {self.user.username} (score: {self.confidence_score})"


class Dashboard(models.Model):
    """User-customizable dashboards"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='dashboards')
    name = models.CharField(max_length=200)
    is_default = models.BooleanField(default=False)
    layout_config = models.TextField(help_text="JSON configuration for dashboard layout")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['user', 'name']
        verbose_name = 'Dashboard'
        verbose_name_plural = 'Dashboards'
    
    def __str__(self):
        return f"{self.user.username} - {self.name}"



# ---------------------------------------------------------------------------
# New models added to support the expanded OSINT engine architecture
# ---------------------------------------------------------------------------

class Subdomain(models.Model):
    """Discovered subdomain with associated metadata."""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='subdomains')
    subdomain = models.CharField(max_length=500)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    page_title = models.CharField(max_length=500, blank=True)
    technology_stack = models.TextField(blank=True, help_text='JSON list of detected technologies')
    screenshot_path = models.CharField(max_length=1000, blank=True)
    ssl_info = models.TextField(blank=True, help_text='JSON SSL/TLS info')
    source = models.CharField(max_length=100, blank=True, help_text='Discovery source, e.g. crt.sh')
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['subdomain']
        unique_together = ('scan', 'subdomain')
        verbose_name = 'Subdomain'
        verbose_name_plural = 'Subdomains'
        indexes = [
            models.Index(fields=['scan', 'subdomain']),
        ]

    def __str__(self):
        return self.subdomain


class DNSRecord(models.Model):
    """Individual DNS record discovered during a scan."""
    RECORD_TYPE_CHOICES = [
        ('A', 'A'), ('AAAA', 'AAAA'), ('MX', 'MX'), ('NS', 'NS'),
        ('TXT', 'TXT'), ('SOA', 'SOA'), ('SRV', 'SRV'), ('CNAME', 'CNAME'),
        ('PTR', 'PTR'), ('CAA', 'CAA'), ('OTHER', 'Other'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='dns_records')
    record_type = models.CharField(max_length=10, choices=RECORD_TYPE_CHOICES)
    name = models.CharField(max_length=500)
    value = models.TextField()
    ttl = models.IntegerField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['record_type', 'name']
        verbose_name = 'DNS Record'
        verbose_name_plural = 'DNS Records'
        indexes = [
            models.Index(fields=['scan', 'record_type']),
        ]

    def __str__(self):
        return f'{self.record_type} {self.name} → {self.value[:80]}'


class Certificate(models.Model):
    """SSL/TLS certificate discovered for a target."""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='certificates')
    subject = models.TextField(blank=True)
    issuer = models.TextField(blank=True)
    sans = models.TextField(blank=True, help_text='JSON list of Subject Alternative Names')
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    is_expired = models.BooleanField(default=False)
    is_self_signed = models.BooleanField(default=False)
    serial_number = models.CharField(max_length=200, blank=True)
    chain_info = models.TextField(blank=True, help_text='JSON certificate chain details')
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-not_after']
        verbose_name = 'Certificate'
        verbose_name_plural = 'Certificates'
        indexes = [
            models.Index(fields=['scan', 'is_expired']),
        ]

    def __str__(self):
        return f'{self.subject[:80]} (expires {self.not_after})'


class Technology(models.Model):
    """Technology detected on a target."""
    CATEGORY_CHOICES = [
        ('CMS', 'CMS'), ('Framework', 'Framework'), ('Server', 'Server'),
        ('CDN', 'CDN'), ('WAF', 'WAF'), ('Analytics', 'Analytics'),
        ('JS Framework', 'JS Framework'), ('Language', 'Language'),
        ('Database', 'Database'), ('Other', 'Other'),
    ]
    CONFIDENCE_CHOICES = [
        ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='technologies')
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=100, blank=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='Other')
    confidence = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES, default='medium')
    url = models.URLField(max_length=2000, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['category', 'name']
        unique_together = ('scan', 'name', 'url')
        verbose_name = 'Technology'
        verbose_name_plural = 'Technologies'
        indexes = [
            models.Index(fields=['scan', 'category']),
        ]

    def __str__(self):
        return f'{self.name} ({self.category})'


class EmailAddress(models.Model):
    """Email address discovered during OSINT collection."""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='email_addresses')
    email = models.EmailField(max_length=500)
    first_name = models.CharField(max_length=200, blank=True)
    last_name = models.CharField(max_length=200, blank=True)
    position = models.CharField(max_length=200, blank=True)
    source = models.CharField(max_length=100, blank=True)
    verified = models.BooleanField(default=False)
    breach_count = models.IntegerField(default=0)
    breach_info = models.TextField(blank=True, help_text='JSON breach details')
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['email']
        unique_together = ('scan', 'email')
        verbose_name = 'Email Address'
        verbose_name_plural = 'Email Addresses'
        indexes = [
            models.Index(fields=['scan', 'email']),
        ]

    def __str__(self):
        return self.email


class SocialProfile(models.Model):
    """Social media profile linked to a scan target."""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='social_profiles')
    platform = models.CharField(max_length=100)
    username = models.CharField(max_length=200)
    url = models.URLField(max_length=2000)
    display_name = models.CharField(max_length=500, blank=True)
    bio = models.TextField(blank=True)
    followers = models.IntegerField(null=True, blank=True)
    verified_exists = models.BooleanField(default=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['platform', 'username']
        unique_together = ('scan', 'platform', 'username')
        verbose_name = 'Social Profile'
        verbose_name_plural = 'Social Profiles'
        indexes = [
            models.Index(fields=['scan', 'platform']),
        ]

    def __str__(self):
        return f'{self.platform}: {self.username}'


class CloudResource(models.Model):
    """Cloud storage resource discovered during enumeration."""
    RESOURCE_TYPE_CHOICES = [
        ('s3_bucket', 'AWS S3 Bucket'),
        ('azure_blob', 'Azure Blob Storage'),
        ('gcp_bucket', 'GCP Storage Bucket'),
        ('firebase_db', 'Firebase Database'),
        ('elasticsearch', 'Elasticsearch Instance'),
        ('other', 'Other'),
    ]
    ACCESS_CHOICES = [
        ('open', 'Publicly Open'),
        ('exists_private', 'Exists (Private)'),
        ('exists_auth_required', 'Exists (Auth Required)'),
        ('other', 'Other'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='cloud_resources')
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPE_CHOICES)
    name = models.CharField(max_length=500)
    url = models.URLField(max_length=2000)
    access_level = models.CharField(max_length=50, choices=ACCESS_CHOICES, default='other')
    metadata = models.TextField(blank=True, help_text='JSON additional metadata')
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        verbose_name = 'Cloud Resource'
        verbose_name_plural = 'Cloud Resources'
        indexes = [
            models.Index(fields=['scan', 'resource_type']),
            models.Index(fields=['access_level']),
        ]

    def __str__(self):
        return f'{self.get_resource_type_display()}: {self.name}'


class PortService(models.Model):
    """Open port and service discovered on a target host."""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='port_services')
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    service_name = models.CharField(max_length=100, blank=True)
    service_version = models.CharField(max_length=200, blank=True)
    banner = models.TextField(blank=True)
    source = models.CharField(max_length=100, blank=True, help_text='e.g. shodan, masscan')
    cves = models.TextField(blank=True, help_text='JSON list of CVE identifiers')
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['ip_address', 'port']
        unique_together = ('scan', 'ip_address', 'port', 'protocol')
        verbose_name = 'Port / Service'
        verbose_name_plural = 'Ports / Services'
        indexes = [
            models.Index(fields=['scan', 'ip_address']),
            models.Index(fields=['port']),
        ]

    def __str__(self):
        return f'{self.ip_address}:{self.port}/{self.protocol} ({self.service_name})'


class ThreatIntelIndicator(models.Model):
    """Threat intelligence indicator linked to a scan target."""
    INDICATOR_TYPE_CHOICES = [
        ('domain', 'Domain'), ('ip', 'IP Address'), ('url', 'URL'),
        ('hash', 'File Hash'), ('email', 'Email'), ('other', 'Other'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='threat_intel')
    indicator_type = models.CharField(max_length=20, choices=INDICATOR_TYPE_CHOICES)
    value = models.CharField(max_length=1000)
    source = models.CharField(max_length=100)
    threat_score = models.IntegerField(default=0, help_text='0-100 threat confidence')
    malicious_votes = models.IntegerField(default=0)
    tags = models.TextField(blank=True, help_text='JSON list of threat tags')
    raw_data = models.TextField(blank=True, help_text='JSON raw API response')
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-threat_score']
        verbose_name = 'Threat Intel Indicator'
        verbose_name_plural = 'Threat Intel Indicators'
        indexes = [
            models.Index(fields=['scan', 'indicator_type']),
            models.Index(fields=['-threat_score']),
        ]

    def __str__(self):
        return f'{self.indicator_type}: {self.value[:80]} (score: {self.threat_score})'


class ScanModule(models.Model):
    """Tracks which OSINT module ran for a scan, its status and timing."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='modules')
    module_name = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(default=0.0)
    items_found = models.IntegerField(default=0)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['scan', 'module_name']
        unique_together = ('scan', 'module_name')
        verbose_name = 'Scan Module'
        verbose_name_plural = 'Scan Modules'
        indexes = [
            models.Index(fields=['scan', 'status']),
        ]

    def __str__(self):
        return f'{self.scan_id}/{self.module_name} [{self.status}]'


class CorrelationLink(models.Model):
    """Represents a relationship between two discovered entities."""
    LINK_TYPE_CHOICES = [
        ('domain_ip', 'Domain → IP'),
        ('email_domain', 'Email → Domain'),
        ('subdomain_ip', 'Subdomain → IP'),
        ('cert_subdomain', 'Certificate → Subdomain'),
        ('ip_cloud', 'IP → Cloud Resource'),
        ('email_social', 'Email → Social Profile'),
        ('other', 'Other'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='correlation_links')
    link_type = models.CharField(max_length=30, choices=LINK_TYPE_CHOICES)
    source_entity = models.CharField(max_length=500)
    source_type = models.CharField(max_length=100)
    target_entity = models.CharField(max_length=500)
    target_type = models.CharField(max_length=100)
    metadata = models.TextField(blank=True, help_text='JSON additional link metadata')
    confidence = models.FloatField(default=1.0, help_text='Confidence score 0.0-1.0')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['link_type', 'source_entity']
        verbose_name = 'Correlation Link'
        verbose_name_plural = 'Correlation Links'
        indexes = [
            models.Index(fields=['scan', 'link_type']),
            models.Index(fields=['source_entity']),
        ]

    def __str__(self):
        return f'{self.source_entity} → {self.target_entity} ({self.link_type})'


class ReconReport(models.Model):
    """Auto-generated reconnaissance report for a scan."""
    FORMAT_CHOICES = [
        ('html', 'HTML'), ('pdf', 'PDF'), ('json', 'JSON'),
        ('csv', 'CSV'), ('markdown', 'Markdown'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='recon_reports')
    title = models.CharField(max_length=500)
    executive_summary = models.TextField(blank=True)
    risk_score = models.IntegerField(default=0, help_text='Overall risk score 0-100')
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES, default='html')
    file_path = models.CharField(max_length=1000, blank=True)
    content = models.TextField(blank=True, help_text='Report content or JSON data')
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-generated_at']
        verbose_name = 'Recon Report'
        verbose_name_plural = 'Recon Reports'
        indexes = [
            models.Index(fields=['scan', 'format']),
        ]

    def __str__(self):
        return f'{self.title} ({self.format}) — {self.generated_at.strftime("%Y-%m-%d %H:%M")}'
