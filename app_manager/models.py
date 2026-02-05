from django.db import models
from django.contrib.auth.models import User


class AppConfiguration(models.Model):
    """Model to store app configuration and enabled/disabled state"""
    app_name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=200)
    description = models.TextField()
    is_enabled = models.BooleanField(default=True)
    icon = models.CharField(max_length=50, default='🔧')
    category = models.CharField(max_length=50, default='security')
    capabilities = models.TextField(help_text='Comma-separated list of capabilities')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['display_name']
    
    def __str__(self):
        return f"{self.display_name} ({'Enabled' if self.is_enabled else 'Disabled'})"
    
    def get_capabilities_list(self):
        """Return capabilities as a list"""
        return [cap.strip() for cap in self.capabilities.split(',') if cap.strip()]


class AppStateChange(models.Model):
    """Model to track app state changes for audit logging"""
    app_config = models.ForeignKey(AppConfiguration, on_delete=models.CASCADE, related_name='state_changes')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    previous_state = models.BooleanField()
    new_state = models.BooleanField()
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.app_config.app_name} changed from {self.previous_state} to {self.new_state}"


class AppSettings(models.Model):
    """Model to store app-specific settings"""
    app_config = models.OneToOneField(AppConfiguration, on_delete=models.CASCADE, related_name='settings')
    settings_json = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Settings for {self.app_config.app_name}"
