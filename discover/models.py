from django.db import models
from django.utils import timezone


class Scan(models.Model):
    """Model to store scan history and results"""
    target = models.CharField(max_length=500, help_text="Target domain or URL")
    scan_date = models.DateTimeField(default=timezone.now)
    
    # Results stored as JSON text fields
    wayback_urls = models.TextField(blank=True, help_text="JSON array of Wayback Machine URLs")
    shodan_data = models.TextField(blank=True, help_text="JSON data from Shodan API")
    hunter_data = models.TextField(blank=True, help_text="JSON data from Hunter.io API")
    dork_queries = models.TextField(blank=True, help_text="JSON array of Google Dorks")
    
    # Summary fields
    total_urls = models.IntegerField(default=0)
    total_emails = models.IntegerField(default=0)
    
    # Sensitive scan fields
    sensitive_scan_completed = models.BooleanField(default=False)
    sensitive_scan_date = models.DateTimeField(null=True, blank=True)
    total_findings = models.IntegerField(default=0)
    high_risk_findings = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-scan_date']
        verbose_name = 'OSINT Scan'
        verbose_name_plural = 'OSINT Scans'
    
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
        ]
        verbose_name = 'Sensitive Finding'
        verbose_name_plural = 'Sensitive Findings'
    
    def __str__(self):
        return f"{self.finding_type} - {self.severity} - {self.url[:50]}"
