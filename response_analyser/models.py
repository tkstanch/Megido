from django.db import models
from django.utils import timezone


class Vulnerability(models.Model):
    """
    Model for storing vulnerability findings from attack routines.
    Captures HTTP requests/responses, payloads, and full HTML evidence.
    """
    ATTACK_TYPES = [
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('sqli', 'SQL Injection'),
        ('csrf', 'Cross-Site Request Forgery'),
        ('idor', 'Insecure Direct Object Reference'),
        ('lfi', 'Local File Inclusion'),
        ('rfi', 'Remote File Inclusion'),
        ('rce', 'Remote Code Execution'),
        ('xxe', 'XML External Entity'),
        ('ssrf', 'Server-Side Request Forgery'),
        ('open_redirect', 'Open Redirect'),
        ('path_traversal', 'Path Traversal'),
        ('command_injection', 'Command Injection'),
        ('other', 'Other'),
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    # Core vulnerability information
    attack_type = models.CharField(max_length=50, choices=ATTACK_TYPES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='medium', db_index=True)
    target_url = models.URLField(max_length=2048, db_index=True)
    payload = models.TextField(help_text="The payload that triggered the vulnerability")
    
    # Request details
    request_method = models.CharField(max_length=10, default='GET')
    request_headers = models.TextField(blank=True, help_text="JSON or text representation of request headers")
    request_body = models.TextField(blank=True, help_text="Request body/parameters")
    
    # Response details
    response_status_code = models.IntegerField(null=True, blank=True)
    response_headers = models.TextField(blank=True, help_text="JSON or text representation of response headers")
    response_body = models.TextField(blank=True, help_text="Response body text")
    evidence_html = models.TextField(blank=True, help_text="Full HTML response for inspection in iframe")
    
    # Metadata
    detected_at = models.DateTimeField(default=timezone.now, db_index=True)
    notes = models.TextField(blank=True, help_text="Additional notes or analysis")
    
    # Grouping and categorization
    endpoint = models.CharField(max_length=500, blank=True, db_index=True, 
                                help_text="Normalized endpoint path for grouping")
    is_confirmed = models.BooleanField(default=False, db_index=True, 
                                       help_text="Whether the vulnerability has been manually confirmed")
    false_positive = models.BooleanField(default=False, db_index=True)
    
    # Proof of Concept / Proof of Impact
    proof_of_impact = models.TextField(blank=True, null=True,
                                       help_text="Proof of Concept or evidence of impact for this vulnerability")
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['attack_type', 'target_url']),
            models.Index(fields=['attack_type', 'endpoint']),
            models.Index(fields=['severity', 'detected_at']),
        ]
        verbose_name = 'Vulnerability'
        verbose_name_plural = 'Vulnerabilities'
    
    def __str__(self):
        return f"{self.get_attack_type_display()} on {self.target_url[:50]}"
    
    def get_short_payload(self):
        """Return truncated payload for display"""
        if len(self.payload) > 100:
            return self.payload[:97] + "..."
        return self.payload
