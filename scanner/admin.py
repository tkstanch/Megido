from django.contrib import admin
from .models import ScanTarget, Scan, Vulnerability, ExploitMedia


class ExploitMediaInline(admin.TabularInline):
    """Inline admin for ExploitMedia to show in Vulnerability admin."""
    model = ExploitMedia
    extra = 0
    readonly_fields = ['capture_timestamp', 'file_size', 'width', 'height', 'frame_count']
    fields = [
        'media_type', 'title', 'description', 'file_path', 'file_name',
        'file_size', 'sequence_order', 'exploit_step', 'payload_used',
        'capture_timestamp'
    ]
    ordering = ['sequence_order', 'capture_timestamp']


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ('name', 'url', 'created_at')
    search_fields = ('name', 'url')
    ordering = ('-created_at',)


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'target', 'status', 'started_at', 'completed_at')
    list_filter = ('status', 'started_at')
    ordering = ('-started_at',)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('vulnerability_type', 'severity', 'url', 'scan', 'discovered_at', 'media_count')
    list_filter = ('severity', 'vulnerability_type', 'discovered_at', 'exploited', 'verified')
    search_fields = ('url', 'description')
    ordering = ('-discovered_at',)
    inlines = [ExploitMediaInline]
    
    def media_count(self, obj):
        """Display count of exploit media files."""
        count = obj.exploit_media.count()
        return f"{count} file(s)" if count > 0 else "No media"
    media_count.short_description = 'Visual Proof'


@admin.register(ExploitMedia)
class ExploitMediaAdmin(admin.ModelAdmin):
    """Admin interface for ExploitMedia."""
    list_display = [
        'id', 'vulnerability', 'media_type', 'title', 'file_size_display',
        'sequence_order', 'capture_timestamp'
    ]
    list_filter = ['media_type', 'capture_timestamp']
    search_fields = ['title', 'description', 'vulnerability__url']
    readonly_fields = ['capture_timestamp', 'file_size', 'width', 'height', 'frame_count', 'duration_seconds']
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'vulnerability', 'media_type', 'title', 'description', 'sequence_order'
            )
        }),
        ('File Details', {
            'fields': (
                'file_path', 'file_name', 'file_size', 'mime_type',
                'width', 'height', 'frame_count', 'duration_seconds', 'capture_timestamp'
            )
        }),
        ('Exploit Context', {
            'fields': (
                'exploit_step', 'payload_used'
            )
        }),
    )
    
    def file_size_display(self, obj):
        """Display file size in human-readable format."""
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    file_size_display.short_description = 'File Size'
