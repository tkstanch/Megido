"""
Admin configuration for the Forensics app.
"""
from django.contrib import admin
from .models import ForensicFile


@admin.register(ForensicFile)
class ForensicFileAdmin(admin.ModelAdmin):
    """
    Admin interface for ForensicFile model.
    """
    list_display = ('original_filename', 'file_size', 'sha256_hash', 'upload_date')
    list_filter = ('upload_date', 'file_type')
    search_fields = ('original_filename', 'sha256_hash', 'device_model', 'serial_number')
    readonly_fields = ('upload_date', 'sha256_hash', 'md5_hash', 'file_size', 'hex_sample')
    
    fieldsets = (
        ('File Information', {
            'fields': ('uploaded_file', 'original_filename', 'file_size', 'upload_date')
        }),
        ('Hash Values', {
            'fields': ('sha256_hash', 'md5_hash')
        }),
        ('Device/System Information', {
            'fields': ('device_model', 'os_version', 'serial_number'),
            'classes': ('collapse',)
        }),
        ('File Analysis', {
            'fields': ('file_type', 'mime_type', 'hex_sample'),
            'classes': ('collapse',)
        }),
        ('Notes', {
            'fields': ('analysis_notes',),
            'classes': ('collapse',)
        }),
    )
