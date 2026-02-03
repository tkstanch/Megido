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
