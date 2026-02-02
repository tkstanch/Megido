from django.db import models


class CollaboratorServer(models.Model):
    """Model to store Collaborator server configuration"""
    domain = models.CharField(max_length=255, unique=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.domain} ({self.ip_address or 'No IP'})"


class Interaction(models.Model):
    """Model to store all types of interactions"""
    INTERACTION_TYPES = [
        ('http', 'HTTP Request'),
        ('dns', 'DNS Query'),
        ('smtp', 'SMTP Connection'),
        ('other', 'Other'),
    ]
    
    server = models.ForeignKey(
        CollaboratorServer, 
        on_delete=models.CASCADE, 
        related_name='interactions'
    )
    interaction_type = models.CharField(max_length=20, choices=INTERACTION_TYPES)
    source_ip = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    raw_data = models.TextField()
    
    # HTTP specific fields
    http_method = models.CharField(max_length=10, blank=True, null=True)
    http_path = models.CharField(max_length=2048, blank=True, null=True)
    http_headers = models.TextField(blank=True, null=True)
    http_body = models.TextField(blank=True, null=True)
    
    # DNS specific fields
    dns_query_type = models.CharField(max_length=20, blank=True, null=True)
    dns_query_name = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['interaction_type']),
            models.Index(fields=['source_ip']),
        ]
    
    def __str__(self):
        return f"{self.get_interaction_type_display()} from {self.source_ip} at {self.timestamp}"
