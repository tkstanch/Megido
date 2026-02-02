from django.contrib import admin
from .models import ScanTarget, Scan, Vulnerability


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
    list_display = ('vulnerability_type', 'severity', 'url', 'scan', 'discovered_at')
    list_filter = ('severity', 'vulnerability_type', 'discovered_at')
    search_fields = ('url', 'description')
    ordering = ('-discovered_at',)
