from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.postgres.fields import JSONField


class Scan(models.Model):
    """Model to store scan history and results"""
    target = models.CharField(max_length=500, help_text="Target domain or URL")
    scan_date = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='scans')
    
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

