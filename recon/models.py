"""
Models for the Recon app - Web Hacking Reconnaissance.

Provides structured storage for all reconnaissance data including
WHOIS results, subdomain discoveries, port scans, directory brute-force,
cloud bucket findings, GitHub recon, and technology fingerprints.
"""
from django.db import models
from django.contrib.auth.models import User


class ReconProject(models.Model):
    """Top-level project / scope definition for a reconnaissance engagement."""

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='recon_projects',
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Recon Project'
        verbose_name_plural = 'Recon Projects'

    def __str__(self):
        return self.name


class ScopeTarget(models.Model):
    """Individual scope entries (domains, IPs, ranges) for a project."""

    TARGET_TYPE_CHOICES = [
        ('domain', 'Domain'),
        ('subdomain', 'Subdomain'),
        ('ip', 'IP Address'),
        ('ip_range', 'IP Range'),
        ('wildcard', 'Wildcard'),
    ]

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='targets'
    )
    target = models.CharField(max_length=500)
    target_type = models.CharField(max_length=20, choices=TARGET_TYPE_CHOICES)
    is_in_scope = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['project', 'target']
        verbose_name = 'Scope Target'
        verbose_name_plural = 'Scope Targets'

    def __str__(self):
        return f"{self.target} ({self.target_type})"


class WhoisResult(models.Model):
    """WHOIS lookup results for a domain."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='whois_results'
    )
    domain = models.CharField(max_length=500)
    raw_data = models.TextField(blank=True)
    registrar = models.CharField(max_length=200, blank=True)
    registrant_name = models.CharField(max_length=200, blank=True)
    registrant_email = models.CharField(max_length=200, blank=True)
    registrant_org = models.CharField(max_length=200, blank=True)
    registrant_phone = models.CharField(max_length=50, blank=True)
    registrant_address = models.TextField(blank=True)
    creation_date = models.CharField(max_length=100, blank=True)
    expiration_date = models.CharField(max_length=100, blank=True)
    # JSON list of name servers
    name_servers = models.TextField(blank=True)
    status = models.TextField(blank=True)
    queried_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-queried_at']
        verbose_name = 'WHOIS Result'
        verbose_name_plural = 'WHOIS Results'

    def __str__(self):
        return f"WHOIS {self.domain}"


class IPDiscovery(models.Model):
    """IP addresses, reverse lookups, and ASN data."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='ip_discoveries'
    )
    domain = models.CharField(max_length=500, blank=True)
    ip_address = models.GenericIPAddressField()
    # JSON list of domains sharing the same IP
    reverse_domains = models.TextField(blank=True)
    asn_number = models.CharField(max_length=20, blank=True)
    asn_org = models.CharField(max_length=200, blank=True)
    asn_country = models.CharField(max_length=10, blank=True)
    ip_range = models.CharField(max_length=100, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        verbose_name = 'IP Discovery'
        verbose_name_plural = 'IP Discoveries'

    def __str__(self):
        return f"{self.ip_address} ({self.domain})"


class CertificateDiscovery(models.Model):
    """SSL certificate findings from crt.sh and other sources."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='certificates'
    )
    domain = models.CharField(max_length=500)
    issuer = models.CharField(max_length=500, blank=True)
    subject = models.CharField(max_length=500, blank=True)
    not_before = models.CharField(max_length=100, blank=True)
    not_after = models.CharField(max_length=100, blank=True)
    # JSON list of Subject Alternative Names
    san_domains = models.TextField(blank=True)
    source = models.CharField(max_length=50, default='crt.sh')
    cert_id = models.CharField(max_length=100, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        verbose_name = 'Certificate Discovery'
        verbose_name_plural = 'Certificate Discoveries'

    def __str__(self):
        return f"Cert {self.domain}"


class SubdomainResult(models.Model):
    """Discovered subdomains with status and metadata."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='subdomains'
    )
    subdomain = models.CharField(max_length=500)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    is_alive = models.BooleanField(default=False)
    # How it was discovered (brute-force, crt.sh, dns, etc.)
    source = models.CharField(max_length=100, blank=True)
    title = models.CharField(max_length=500, blank=True)
    technologies = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_checked = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-discovered_at']
        unique_together = ['project', 'subdomain']
        verbose_name = 'Subdomain Result'
        verbose_name_plural = 'Subdomain Results'

    def __str__(self):
        return self.subdomain


class ServicePort(models.Model):
    """Discovered services and open ports."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='services'
    )
    host = models.CharField(max_length=500)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    service_name = models.CharField(max_length=100, blank=True)
    service_version = models.CharField(max_length=200, blank=True)
    banner = models.TextField(blank=True)
    is_open = models.BooleanField(default=True)
    # nmap, masscan, shodan, censys
    source = models.CharField(max_length=50, default='nmap')
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        unique_together = ['project', 'host', 'port', 'protocol']
        verbose_name = 'Service Port'
        verbose_name_plural = 'Service Ports'

    def __str__(self):
        return f"{self.host}:{self.port}/{self.protocol}"


class DirectoryFinding(models.Model):
    """Directory brute-force results."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='directories'
    )
    target_url = models.URLField(max_length=2000)
    path = models.CharField(max_length=500)
    full_url = models.URLField(max_length=2000, blank=True)
    status_code = models.IntegerField()
    content_length = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=200, blank=True)
    redirect_url = models.URLField(max_length=2000, blank=True)
    is_interesting = models.BooleanField(default=False)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        verbose_name = 'Directory Finding'
        verbose_name_plural = 'Directory Findings'

    def __str__(self):
        return f"{self.status_code} {self.full_url or self.path}"


class BucketFinding(models.Model):
    """S3 and cloud storage bucket findings."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='buckets'
    )
    bucket_name = models.CharField(max_length=500)
    bucket_url = models.URLField(max_length=2000, blank=True)
    # aws, azure, gcp
    provider = models.CharField(max_length=50, default='aws')
    is_public = models.BooleanField(null=True, blank=True)
    is_listable = models.BooleanField(default=False)
    is_writable = models.BooleanField(default=False)
    # Keywords used to discover this bucket
    keywords = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        unique_together = ['project', 'bucket_name', 'provider']
        verbose_name = 'Bucket Finding'
        verbose_name_plural = 'Bucket Findings'

    def __str__(self):
        return f"{self.provider}:{self.bucket_name}"


class GitHubFinding(models.Model):
    """GitHub reconnaissance results."""

    FINDING_TYPE_CHOICES = [
        ('repo', 'Repository'),
        ('secret', 'Secret'),
        ('contributor', 'Contributor'),
        ('leak', 'Data Leak'),
        ('issue', 'Issue'),
        ('commit', 'Commit'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='github_findings'
    )
    finding_type = models.CharField(max_length=20, choices=FINDING_TYPE_CHOICES)
    repository = models.CharField(max_length=500, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    content = models.TextField(blank=True)
    url = models.URLField(max_length=2000, blank=True)
    severity = models.CharField(
        max_length=20, choices=SEVERITY_CHOICES, default='info'
    )
    is_verified = models.BooleanField(default=False)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        verbose_name = 'GitHub Finding'
        verbose_name_plural = 'GitHub Findings'

    def __str__(self):
        return f"{self.finding_type} - {self.repository}"


class TechFingerprint(models.Model):
    """Technology stack fingerprints."""

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='tech_fingerprints'
    )
    target_url = models.URLField(max_length=2000)
    technology = models.CharField(max_length=200)
    version = models.CharField(max_length=100, blank=True)
    # cms, framework, language, server, etc.
    category = models.CharField(max_length=100, blank=True)
    evidence = models.TextField(blank=True)
    cve_count = models.IntegerField(default=0)
    # Confidence 0-100 %
    confidence = models.IntegerField(default=100)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        verbose_name = 'Tech Fingerprint'
        verbose_name_plural = 'Tech Fingerprints'

    def __str__(self):
        return f"{self.technology} {self.version} @ {self.target_url[:60]}"


class ReconTask(models.Model):
    """Track individual recon task status and progress."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    TASK_TYPE_CHOICES = [
        ('whois', 'WHOIS Lookup'),
        ('subdomain_enum', 'Subdomain Enumeration'),
        ('port_scan', 'Port Scan'),
        ('directory_brute', 'Directory Brute-Force'),
        ('bucket_discovery', 'Bucket Discovery'),
        ('github_recon', 'GitHub Recon'),
        ('fingerprinting', 'Fingerprinting'),
        ('full_recon', 'Full Recon'),
        ('ip_discovery', 'IP Discovery'),
        ('cert_parsing', 'Certificate Parsing'),
    ]

    project = models.ForeignKey(
        ReconProject, on_delete=models.CASCADE, related_name='tasks'
    )
    task_type = models.CharField(max_length=30, choices=TASK_TYPE_CHOICES)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='pending'
    )
    target = models.CharField(max_length=500, blank=True)
    celery_task_id = models.CharField(max_length=200, blank=True)
    # Progress 0-100
    progress = models.IntegerField(default=0)
    result_summary = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Recon Task'
        verbose_name_plural = 'Recon Tasks'

    def __str__(self):
        return f"{self.task_type} - {self.status} ({self.project})"
