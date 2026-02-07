from django.db import models
from django.contrib.auth.models import User


class InterceptorSettings(models.Model):
    """Global settings for the interceptor"""
    is_enabled = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Interceptor Settings'
        verbose_name_plural = 'Interceptor Settings'
    
    def __str__(self):
        return f"Interceptor: {'Enabled' if self.is_enabled else 'Disabled'}"
    
    @classmethod
    def get_settings(cls):
        """Get or create the interceptor settings singleton"""
        settings, created = cls.objects.get_or_create(id=1)
        return settings


class InterceptedRequest(models.Model):
    """Store all intercepted HTTP requests"""
    url = models.URLField(max_length=2000)
    method = models.CharField(max_length=10)
    headers = models.JSONField()
    body = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    source_app = models.CharField(max_length=50, blank=True)  # Which app triggered this
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['source_app']),
            models.Index(fields=['method']),
        ]
    
    def __str__(self):
        return f"{self.method} {self.url[:50]}"


class InterceptedResponse(models.Model):
    """Store HTTP responses"""
    request = models.OneToOneField(InterceptedRequest, on_delete=models.CASCADE, related_name='response')
    status_code = models.IntegerField()
    headers = models.JSONField()
    body = models.TextField()
    response_time = models.FloatField()  # in milliseconds
    
    class Meta:
        indexes = [
            models.Index(fields=['status_code']),
        ]
    
    def __str__(self):
        return f"Response {self.status_code} for {self.request}"


class PayloadRule(models.Model):
    """Rules for automatic payload injection"""
    INJECTION_TYPES = [
        ('header', 'HTTP Header'),
        ('body', 'Request Body'),
        ('param', 'URL Parameter'),
        ('cookie', 'Cookie'),
    ]
    
    name = models.CharField(max_length=200)
    target_url_pattern = models.CharField(max_length=500, help_text="Regex pattern to match URLs")
    injection_type = models.CharField(max_length=20, choices=INJECTION_TYPES)
    injection_point = models.CharField(max_length=100, help_text="Header name, parameter name, etc.")
    payload_content = models.TextField()
    active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    target_apps = models.JSONField(default=list, blank=True)  # Which apps can use this rule
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['active']),
        ]
    
    def __str__(self):
        return f"{self.name} ({'active' if self.active else 'inactive'})"
