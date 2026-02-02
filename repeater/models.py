from django.db import models


class RepeaterRequest(models.Model):
    """Model to store and replay HTTP requests"""
    url = models.URLField(max_length=2048)
    method = models.CharField(max_length=10, default='GET')
    headers = models.TextField(help_text="JSON formatted headers")
    body = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name or self.id} - {self.method} {self.url}"


class RepeaterResponse(models.Model):
    """Model to store responses from repeater requests"""
    request = models.ForeignKey(RepeaterRequest, on_delete=models.CASCADE, related_name='responses')
    status_code = models.IntegerField()
    headers = models.TextField()
    body = models.TextField(blank=True, null=True)
    response_time = models.FloatField()  # in milliseconds
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.status_code} - Response to {self.request}"
