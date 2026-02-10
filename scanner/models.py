from django.db import models


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
