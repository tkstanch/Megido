from django.db import models
from django.contrib.auth.models import User
import json


class ProxyConfiguration(models.Model):
    """Configuration for proxy settings"""
    # Authentication settings
    auth_enabled = models.BooleanField(default=False, help_text="Enable proxy authentication")
    auth_username = models.CharField(max_length=255, blank=True, null=True)
    auth_password = models.CharField(max_length=255, blank=True, null=True)
    auth_token = models.CharField(max_length=512, blank=True, null=True)
    
    # IP filtering
    ip_whitelist = models.TextField(blank=True, null=True, help_text="Comma-separated list of allowed IPs")
    ip_blacklist = models.TextField(blank=True, null=True, help_text="Comma-separated list of blocked IPs")
    
    # Logging settings
    logging_enabled = models.BooleanField(default=True)
    log_request_body = models.BooleanField(default=True)
    log_response_body = models.BooleanField(default=True)
    log_directory = models.CharField(max_length=512, default='logs/proxy')
    
    # Performance settings
    connection_timeout = models.IntegerField(default=30, help_text="Connection timeout in seconds")
    transfer_timeout = models.IntegerField(default=300, help_text="Transfer timeout in seconds")
    max_concurrent_clients = models.IntegerField(default=100)
    cache_enabled = models.BooleanField(default=False)
    
    # WebSocket settings
    websocket_enabled = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Proxy Configuration"
        verbose_name_plural = "Proxy Configurations"
    
    def __str__(self):
        return f"Proxy Config (Updated: {self.updated_at})"
    
    def get_whitelist_ips(self):
        """Return list of whitelisted IPs"""
        if self.ip_whitelist:
            return [ip.strip() for ip in self.ip_whitelist.split(',') if ip.strip()]
        return []
    
    def get_blacklist_ips(self):
        """Return list of blacklisted IPs"""
        if self.ip_blacklist:
            return [ip.strip() for ip in self.ip_blacklist.split(',') if ip.strip()]
        return []


class ProxyRequest(models.Model):
    """Model to store HTTP requests passing through the proxy"""
    url = models.URLField(max_length=2048)
    method = models.CharField(max_length=10)
    headers = models.TextField()
    body = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    
    # Enhanced logging fields
    source_ip = models.GenericIPAddressField(blank=True, null=True, help_text="Client IP address")
    protocol = models.CharField(max_length=10, default='HTTP', choices=[
        ('HTTP', 'HTTP'),
        ('HTTPS', 'HTTPS'),
        ('WS', 'WebSocket'),
        ('WSS', 'Secure WebSocket'),
    ])
    request_size = models.IntegerField(default=0, help_text="Request size in bytes")
    user_agent = models.CharField(max_length=512, blank=True, null=True)
    
    # Security tracking
    auth_attempted = models.BooleanField(default=False)
    auth_success = models.BooleanField(default=False)
    auth_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Replay tracking
    is_replay = models.BooleanField(default=False)
    original_request = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='replays')
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['method']),
            models.Index(fields=['protocol']),
        ]
    
    def __str__(self):
        return f"{self.method} {self.url}"
    
    def get_headers_dict(self):
        """Parse headers text to dictionary"""
        try:
            if isinstance(self.headers, str):
                return json.loads(self.headers)
            return self.headers
        except (json.JSONDecodeError, TypeError):
            return {}


class ProxyResponse(models.Model):
    """Model to store HTTP responses from the proxy"""
    request = models.OneToOneField(ProxyRequest, on_delete=models.CASCADE, related_name='response')
    status_code = models.IntegerField()
    headers = models.TextField()
    body = models.TextField(blank=True, null=True)
    response_time = models.FloatField()  # in milliseconds
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Enhanced fields
    response_size = models.IntegerField(default=0, help_text="Response size in bytes")
    cached = models.BooleanField(default=False)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['status_code']),
        ]
    
    def __str__(self):
        return f"{self.status_code} for {self.request.method} {self.request.url}"
    
    def get_headers_dict(self):
        """Parse headers text to dictionary"""
        try:
            if isinstance(self.headers, str):
                return json.loads(self.headers)
            return self.headers
        except (json.JSONDecodeError, TypeError):
            return {}


class WebSocketMessage(models.Model):
    """Model to store WebSocket messages"""
    connection_id = models.CharField(max_length=255, help_text="Unique WebSocket connection identifier")
    url = models.URLField(max_length=2048)
    direction = models.CharField(max_length=10, choices=[
        ('SEND', 'Client to Server'),
        ('RECEIVE', 'Server to Client'),
    ])
    message_type = models.CharField(max_length=20, choices=[
        ('TEXT', 'Text'),
        ('BINARY', 'Binary'),
        ('PING', 'Ping'),
        ('PONG', 'Pong'),
        ('CLOSE', 'Close'),
    ])
    payload = models.TextField()
    payload_size = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['connection_id', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.direction} {self.message_type} on {self.connection_id}"


class ProxyError(models.Model):
    """Model to track proxy errors and exceptional conditions"""
    ERROR_TYPES = [
        ('CONNECTION_RESET', 'Connection Reset'),
        ('TIMEOUT', 'Timeout'),
        ('AUTH_FAILURE', 'Authentication Failure'),
        ('PROTOCOL_ERROR', 'Protocol Error'),
        ('SSL_ERROR', 'SSL/TLS Error'),
        ('DNS_ERROR', 'DNS Resolution Error'),
        ('OTHER', 'Other Error'),
    ]
    
    error_type = models.CharField(max_length=50, choices=ERROR_TYPES)
    error_message = models.TextField()
    stack_trace = models.TextField(blank=True, null=True)
    url = models.URLField(max_length=2048, blank=True, null=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    request = models.ForeignKey(ProxyRequest, on_delete=models.SET_NULL, null=True, blank=True, related_name='errors')
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['error_type']),
        ]
    
    def __str__(self):
        return f"{self.error_type}: {self.error_message[:100]}"


class AuthenticationAttempt(models.Model):
    """Track authentication attempts for security monitoring"""
    username = models.CharField(max_length=255, blank=True, null=True)
    source_ip = models.GenericIPAddressField()
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=255, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['source_ip', '-timestamp']),
            models.Index(fields=['-timestamp']),
        ]
    
    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{status} - {self.username or 'Anonymous'} from {self.source_ip}"
