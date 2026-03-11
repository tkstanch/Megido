from django.db import models

class ScanTarget(models.Model):
    name = models.CharField(max_length=255)
    url = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Scan(models.Model):
    target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE)
    status = models.CharField(max_length=50)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Scan {self.id} for {self.target.name}"

class Vulnerability(models.Model):
    vulnerability_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=50)
    url = models.URLField()
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    discovered_at = models.DateTimeField(auto_now_add=True)
    exploited = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    media_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Vulnerability in {self.url}"

    def media_count(self):
        count = self.exploit_media.count()
        return f"{count} file(s)" if count > 0 else "No media"
    media_count.short_description = 'Visual Proof'

class ExploitMedia(models.Model):
    media_type = models.CharField(max_length=50)
    title = models.CharField(max_length=255)
    description = models.TextField()
    file_path = models.FileField(upload_to='exploit_media/')
    file_name = models.CharField(max_length=255)
    file_size = models.FloatField()
    sequence_order = models.IntegerField()
    exploit_step = models.CharField(max_length=50, null=True, blank=True)
    payload_used = models.CharField(max_length=255, null=True, blank=True)
    capture_timestamp = models.DateTimeField(auto_now_add=True)

    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)

    def __str__(self):
        return self.title
