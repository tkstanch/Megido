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
    
    class Meta:
        ordering = ['-scan_date']
        verbose_name = 'OSINT Scan'
        verbose_name_plural = 'OSINT Scans'
    
    def __str__(self):
        return f"{self.target} - {self.scan_date.strftime('%Y-%m-%d %H:%M')}"
