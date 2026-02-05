from django.db import models
from django.contrib.auth.models import User


class BrowserSession(models.Model):
    """Model to store browser sessions"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    session_name = models.CharField(max_length=200, default='Unnamed Session')
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Session {self.session_name} - {self.started_at}"


class BrowserHistory(models.Model):
    """Model to track browser navigation history"""
    session = models.ForeignKey(BrowserSession, on_delete=models.CASCADE, related_name='history')
    url = models.URLField(max_length=2048)
    title = models.CharField(max_length=500, blank=True)
    visited_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-visited_at']
        verbose_name_plural = 'Browser histories'
    
    def __str__(self):
        return f"{self.url} at {self.visited_at}"


class BrowserAppInteraction(models.Model):
    """Model to log which apps were used during browser sessions"""
    session = models.ForeignKey(BrowserSession, on_delete=models.CASCADE, related_name='app_interactions')
    app_name = models.CharField(max_length=100)
    action = models.CharField(max_length=200)
    target_url = models.URLField(max_length=2048, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    result = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.app_name} - {self.action} at {self.timestamp}"


class BrowserSettings(models.Model):
    """Model to store browser preferences"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    default_user_agent = models.CharField(max_length=500, blank=True)
    enable_javascript = models.BooleanField(default=True)
    enable_images = models.BooleanField(default=True)
    enable_plugins = models.BooleanField(default=False)
    proxy_enabled = models.BooleanField(default=False)
    proxy_host = models.CharField(max_length=255, blank=True)
    proxy_port = models.IntegerField(null=True, blank=True)
    settings_json = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Browser settings for {self.user.username if self.user else 'anonymous'}"
