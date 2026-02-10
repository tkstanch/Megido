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
    
    # Status and tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', 
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
    """
    INJECTION_TYPE_CHOICES = [
        ('error_based', 'Error-based'),
        ('time_based', 'Time-based (Blind)'),
        ('union_based', 'UNION-based'),
        ('boolean_based', 'Boolean-based'),
        ('stacked_queries', 'Stacked Queries'),
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
    
    # Metadata
    detected_at = models.DateTimeField(default=timezone.now, db_index=True)
    severity = models.CharField(max_length=20, default='critical',
                               help_text="Severity: critical, high, medium, low")
    
    class Meta:
        ordering = ['-detected_at']
        verbose_name = 'SQL Injection Result'
        verbose_name_plural = 'SQL Injection Results'
        indexes = [
            models.Index(fields=['task', 'injection_type']),
            models.Index(fields=['severity', 'detected_at']),
        ]
    
    def __str__(self):
        return (f"{self.get_injection_type_display()} in {self.vulnerable_parameter} "
                f"({self.task.target_url[:30]}...)")
