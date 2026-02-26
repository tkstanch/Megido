from django.db import models
from django.utils import timezone


class VulnerabilityType(models.Model):
    """
    Model to store different vulnerability types (XSS, SQLi, LFI, RCE, CSRF, etc.)
    """
    name = models.CharField(max_length=100, unique=True, db_index=True,
                           help_text="Vulnerability name (e.g., XSS, SQLi, LFI)")
    description = models.TextField(help_text="Detailed description of the vulnerability")
    category = models.CharField(max_length=50, db_index=True,
                               help_text="Category: injection, misconfiguration, etc.")
    severity = models.CharField(max_length=20, default='high',
                               choices=[('critical', 'Critical'), ('high', 'High'),
                                       ('medium', 'Medium'), ('low', 'Low')])
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Vulnerability Type'
        verbose_name_plural = 'Vulnerability Types'
    
    def __str__(self):
        return f"{self.name} - {self.get_severity_display()}"


class Payload(models.Model):
    """
    Model to store payloads for each vulnerability type
    """
    vulnerability = models.ForeignKey(VulnerabilityType, on_delete=models.CASCADE,
                                     related_name='payloads')
    name = models.CharField(max_length=200, help_text="Payload name/identifier")
    payload_text = models.TextField(help_text="The actual payload code/string")
    description = models.TextField(blank=True,
                                  help_text="What this payload does and how it works")
    
    # Payload metadata
    is_obfuscated = models.BooleanField(default=False,
                                       help_text="Whether payload is obfuscated")
    bypass_technique = models.CharField(max_length=100, blank=True,
                                       help_text="Bypass technique used (e.g., WAF bypass)")
    platform = models.CharField(max_length=100, blank=True,
                               help_text="Target platform (e.g., Windows, Linux, Web)")
    
    # User tracking
    is_custom = models.BooleanField(default=False,
                                   help_text="User-submitted vs pre-loaded")
    submitted_by = models.CharField(max_length=100, blank=True,
                                   help_text="User who submitted this payload")
    created_at = models.DateTimeField(default=timezone.now)
    success_rate = models.IntegerField(default=0,
                                      help_text="Success rate percentage (0-100)")
    
    class Meta:
        ordering = ['-created_at', 'name']
        verbose_name = 'Payload'
        verbose_name_plural = 'Payloads'
        indexes = [
            models.Index(fields=['vulnerability', 'created_at']),
            models.Index(fields=['is_custom', 'vulnerability']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.vulnerability.name})"


class EncodingTechnique(models.Model):
    """
    Model to store encoding/obfuscation techniques
    """
    name = models.CharField(max_length=100, unique=True, db_index=True,
                           help_text="Encoding name (e.g., URL Encode, Base64)")
    description = models.TextField(help_text="How this encoding works")
    encoding_type = models.CharField(max_length=50,
                                    help_text="Type: url, base64, hex, unicode, etc.")
    is_reversible = models.BooleanField(default=True,
                                       help_text="Can be decoded back to original")
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Encoding Technique'
        verbose_name_plural = 'Encoding Techniques'
    
    def __str__(self):
        return f"{self.name} ({self.encoding_type})"


class PayloadManipulation(models.Model):
    """
    Model to store payload manipulation tricks and bypass techniques
    """
    vulnerability = models.ForeignKey(VulnerabilityType, on_delete=models.CASCADE,
                                     related_name='manipulation_tricks')
    name = models.CharField(max_length=200, help_text="Trick name")
    technique = models.TextField(help_text="The manipulation technique/pattern")
    description = models.TextField(help_text="Explanation of the bypass technique")
    example = models.TextField(blank=True, help_text="Example usage")
    
    # Metadata
    effectiveness = models.CharField(max_length=20, default='medium',
                                    choices=[('high', 'High'), ('medium', 'Medium'),
                                            ('low', 'Low')])
    target_defense = models.CharField(max_length=200, blank=True,
                                     help_text="What defense this bypasses (e.g., WAF, filter)")
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-effectiveness', 'name']
        verbose_name = 'Payload Manipulation'
        verbose_name_plural = 'Payload Manipulations'
    
    def __str__(self):
        return f"{self.name} for {self.vulnerability.name}"


class CraftedPayload(models.Model):
    """
    Model to store crafted/encoded payloads with their manipulation history
    """
    base_payload = models.ForeignKey(Payload, on_delete=models.CASCADE,
                                    related_name='crafted_versions')
    crafted_text = models.TextField(help_text="Final crafted/encoded payload")
    
    # Encoding/manipulation applied
    encodings_applied = models.JSONField(default=list,
                                        help_text="List of encoding techniques applied")
    manipulations_applied = models.JSONField(default=list,
                                            help_text="List of manipulation tricks applied")
    
    # Testing metadata
    tested = models.BooleanField(default=False, help_text="Has been tested")
    successful = models.BooleanField(default=False, help_text="Test was successful")
    test_notes = models.TextField(blank=True, help_text="Notes from testing")
    test_date = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Crafted Payload'
        verbose_name_plural = 'Crafted Payloads'
    
    def __str__(self):
        return f"Crafted from {self.base_payload.name} at {self.created_at.strftime('%Y-%m-%d %H:%M')}"


class AttackCampaign(models.Model):
    name = models.CharField(max_length=200)
    target_url = models.URLField()
    target_scope = models.TextField(blank=True)
    status = models.CharField(max_length=20, default='pending',
        choices=[('pending','Pending'),('crawling','Crawling'),('injecting','Injecting'),
                 ('completed','Completed'),('paused','Paused'),('failed','Failed')])
    mode = models.CharField(max_length=20, default='auto',
        choices=[('auto','Fully Automatic'),('semi','Semi-Automatic'),('manual','Manual Payloads Only')])
    concurrency = models.IntegerField(default=10)
    follow_redirects = models.BooleanField(default=True)
    max_depth = models.IntegerField(default=5)
    include_headers = models.BooleanField(default=True)
    include_cookies = models.BooleanField(default=True)
    custom_headers = models.JSONField(default=dict)
    authentication = models.JSONField(default=dict)
    use_builtin_payloads = models.BooleanField(default=True)
    use_custom_payloads = models.BooleanField(default=True)
    custom_payload_text = models.TextField(blank=True)
    vuln_types_to_test = models.JSONField(default=list)
    manipulation_level = models.CharField(max_length=20, default='moderate',
        choices=[('minimal','Minimal'),('moderate','Moderate'),('aggressive','Aggressive'),('maximum','Maximum')])
    total_injection_points = models.IntegerField(default=0)
    total_payloads_tested = models.IntegerField(default=0)
    total_requests_sent = models.IntegerField(default=0)
    successful_exploits = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} -> {self.target_url}"


class DiscoveredInjectionPoint(models.Model):
    campaign = models.ForeignKey(AttackCampaign, on_delete=models.CASCADE, related_name='injection_points')
    url = models.URLField(max_length=2000)
    parameter_name = models.CharField(max_length=500)
    parameter_type = models.CharField(max_length=20,
        choices=[('GET','GET'),('POST','POST'),('header','Header'),('cookie','Cookie'),
                 ('json','JSON'),('xml','XML'),('file','File'),('websocket','WebSocket')])
    injection_location = models.CharField(max_length=200, blank=True)
    original_value = models.TextField(blank=True)
    form_action = models.URLField(blank=True, max_length=2000)
    form_method = models.CharField(max_length=10, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']

    def __str__(self):
        return f"{self.parameter_type}:{self.parameter_name} @ {self.url}"


class InjectionResult(models.Model):
    campaign = models.ForeignKey(AttackCampaign, on_delete=models.CASCADE, related_name='results')
    injection_point = models.ForeignKey(DiscoveredInjectionPoint, on_delete=models.CASCADE)
    payload = models.ForeignKey(Payload, on_delete=models.SET_NULL, null=True, blank=True)
    payload_text = models.TextField()
    manipulations_applied = models.JSONField(default=list)
    encodings_applied = models.JSONField(default=list)
    request_method = models.CharField(max_length=10)
    request_url = models.URLField(max_length=2000)
    request_headers = models.JSONField(default=dict)
    request_body = models.TextField(blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict)
    response_body = models.TextField(blank=True)
    response_time_ms = models.IntegerField(null=True, blank=True)
    is_successful = models.BooleanField(default=False)
    vulnerability_type = models.CharField(max_length=100, blank=True)
    detection_method = models.CharField(max_length=100, blank=True)
    confidence = models.FloatField(default=0.0)
    evidence = models.TextField(blank=True)
    poc_curl_command = models.TextField(blank=True)
    poc_python_script = models.TextField(blank=True)
    poc_report = models.TextField(blank=True)
    severity = models.CharField(max_length=20, default='info',
        choices=[('critical','Critical'),('high','High'),('medium','Medium'),('low','Low'),('info','Info')])
    tested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-tested_at']

    def __str__(self):
        return f"{'✓' if self.is_successful else '✗'} {self.vulnerability_type} @ {self.request_url}"


class PayloadSource(models.Model):
    name = models.CharField(max_length=200)
    source_type = models.CharField(max_length=20,
        choices=[('builtin','Built-in'),('user','User Provided'),('discovered','Auto-Discovered'),('imported','Imported')])
    vulnerability_type = models.ForeignKey(VulnerabilityType, on_delete=models.CASCADE)
    payloads_text = models.TextField()
    description = models.TextField(blank=True)
    effectiveness_score = models.FloatField(default=0.0)
    times_used = models.IntegerField(default=0)
    times_successful = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-effectiveness_score', '-times_successful']

    def __str__(self):
        return f"{self.name} ({self.source_type})"
