from django.db import models


SOURCE_CHOICES = [
    ('manual', 'Manual'),
    ('scanner', 'Scanner'),
    ('interceptor', 'Interceptor'),
    ('exploit', 'Exploit'),
    ('manipulator', 'Manipulator'),
]


class RepeaterTab(models.Model):
    """Model to represent a repeater tab (like Burp Suite tabs)"""
    name = models.CharField(max_length=255, default='New Tab')
    order = models.IntegerField(default=0)
    # Per-tab configuration stored as JSON
    follow_redirects = models.BooleanField(default=True)
    max_redirects = models.IntegerField(default=10)
    timeout = models.FloatField(default=30.0)
    verify_ssl = models.BooleanField(default=False)
    auto_content_length = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['order', 'created_at']

    def __str__(self):
        return f"Tab {self.order}: {self.name}"

    def to_config_dict(self):
        return {
            'follow_redirects': self.follow_redirects,
            'max_redirects': self.max_redirects,
            'timeout': self.timeout,
            'verify_ssl': self.verify_ssl,
            'auto_content_length': self.auto_content_length,
        }


class RepeaterRequest(models.Model):
    """Model to store and replay HTTP requests"""
    url = models.URLField(max_length=2048)
    method = models.CharField(max_length=10, default='GET')
    headers = models.TextField(help_text="JSON formatted headers")
    body = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    tab = models.ForeignKey(
        RepeaterTab,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='requests',
    )
    tab_history_index = models.IntegerField(default=0)
    scan = models.ForeignKey(
        'scanner.Scan',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='repeater_requests',
    )
    source = models.CharField(
        max_length=20,
        choices=SOURCE_CHOICES,
        default='manual',
    )
    analysis_advice = models.TextField(blank=True, null=True)
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
