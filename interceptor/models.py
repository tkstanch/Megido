from django.db import models
from proxy.models import ProxyRequest


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
    """Model to store intercepted requests for manual inspection/modification"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('modified', 'Modified'),
        ('forwarded', 'Forwarded'),
        ('dropped', 'Dropped'),
    ]
    
    proxy_request = models.ForeignKey(ProxyRequest, on_delete=models.CASCADE)
    original_url = models.URLField(max_length=2048)
    original_method = models.CharField(max_length=10)
    original_headers = models.TextField()
    original_body = models.TextField(blank=True, null=True)
    
    modified_url = models.URLField(max_length=2048, blank=True, null=True)
    modified_method = models.CharField(max_length=10, blank=True, null=True)
    modified_headers = models.TextField(blank=True, null=True)
    modified_body = models.TextField(blank=True, null=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.status} - {self.original_method} {self.original_url}"
