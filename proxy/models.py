from django.db import models


class ProxyRequest(models.Model):
    """Model to store HTTP requests passing through the proxy"""
    url = models.URLField(max_length=2048)
    method = models.CharField(max_length=10)
    headers = models.TextField()
    body = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.method} {self.url}"


class ProxyResponse(models.Model):
    """Model to store HTTP responses from the proxy"""
    request = models.OneToOneField(ProxyRequest, on_delete=models.CASCADE, related_name='response')
    status_code = models.IntegerField()
    headers = models.TextField()
    body = models.TextField(blank=True, null=True)
    response_time = models.FloatField()  # in milliseconds
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.status_code} for {self.request.method} {self.request.url}"
