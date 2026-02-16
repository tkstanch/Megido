"""
Models for the Forensics app.

Stores information about uploaded forensic files and analysis results.
"""
from django.db import models
from django.utils import timezone


class ForensicFile(models.Model):
    """
    Model to store uploaded forensic files and their analysis results.
    
    Fields include file metadata, hash values, device information (if extractable),
    and analysis results.
    """
    # File information
    uploaded_file = models.FileField(upload_to='forensics/%Y/%m/%d/')
    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField(help_text="File size in bytes")
    upload_date = models.DateTimeField(default=timezone.now)
    
    # Hash values
    sha256_hash = models.CharField(max_length=64, blank=True)
    md5_hash = models.CharField(max_length=32, blank=True)
    
    # Device/System information (extracted when available)
    device_model = models.CharField(max_length=255, blank=True, null=True)
    os_version = models.CharField(max_length=100, blank=True, null=True)
    serial_number = models.CharField(max_length=100, blank=True, null=True)
    
    # File type and analysis
    file_type = models.CharField(max_length=100, blank=True)
    mime_type = models.CharField(max_length=100, blank=True)
    
    # Sample data (first few bytes in hex)
    hex_sample = models.TextField(blank=True, help_text="First 256 bytes in hex format")
    
    # Analysis notes
    analysis_notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-upload_date']
        verbose_name = 'Forensic File'
        verbose_name_plural = 'Forensic Files'
    
    def __str__(self):
        return f"{self.original_filename} - {self.upload_date.strftime('%Y-%m-%d %H:%M')}"
