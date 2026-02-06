from django.contrib import admin
from .models import Scan, SensitiveFinding


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'scan_date', 'total_urls', 'total_emails', 'sensitive_scan_completed', 'total_findings', 'high_risk_findings')
    list_filter = ('scan_date', 'sensitive_scan_completed')
    search_fields = ('target',)
    readonly_fields = ('scan_date', 'sensitive_scan_date')


@admin.register(SensitiveFinding)
class SensitiveFindingAdmin(admin.ModelAdmin):
    list_display = ('finding_type', 'severity', 'url_short', 'discovered_at', 'verified', 'false_positive')
    list_filter = ('severity', 'finding_type', 'verified', 'false_positive', 'discovered_at')
    search_fields = ('url', 'finding_type', 'value', 'notes')
    readonly_fields = ('discovered_at',)
    list_editable = ('verified', 'false_positive')
    
    def url_short(self, obj):
        return obj.url[:50] + '...' if len(obj.url) > 50 else obj.url
    url_short.short_description = 'URL'
