from django.contrib import admin
from .models import Scan, SensitiveFinding, UserActivity, ScanRecommendation, Dashboard


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'user', 'scan_date', 'total_urls', 'total_emails', 'sensitive_scan_completed', 'total_findings', 'high_risk_findings')
    list_filter = ('scan_date', 'sensitive_scan_completed', 'user')
    search_fields = ('target', 'user__username')
    readonly_fields = ('scan_date', 'sensitive_scan_date')
    raw_id_fields = ('user',)


@admin.register(SensitiveFinding)
class SensitiveFindingAdmin(admin.ModelAdmin):
    list_display = ('finding_type', 'severity', 'url_short', 'discovered_at', 'verified', 'false_positive')
    list_filter = ('severity', 'finding_type', 'verified', 'false_positive', 'discovered_at')
    search_fields = ('url', 'finding_type', 'value', 'notes')
    readonly_fields = ('discovered_at',)
    list_editable = ('verified', 'false_positive')
    raw_id_fields = ('scan',)
    
    def url_short(self, obj):
        return obj.url[:50] + '...' if len(obj.url) > 50 else obj.url
    url_short.short_description = 'URL'


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'target', 'timestamp', 'ip_address')
    list_filter = ('action', 'timestamp')
    search_fields = ('user__username', 'target', 'ip_address')
    readonly_fields = ('timestamp',)
    raw_id_fields = ('user', 'scan')
    date_hierarchy = 'timestamp'


@admin.register(ScanRecommendation)
class ScanRecommendationAdmin(admin.ModelAdmin):
    list_display = ('user', 'recommended_target', 'confidence_score', 'created_at', 'accepted')
    list_filter = ('accepted', 'created_at')
    search_fields = ('user__username', 'recommended_target', 'reason')
    readonly_fields = ('created_at',)
    raw_id_fields = ('user', 'based_on_scan')
    list_editable = ('accepted',)


@admin.register(Dashboard)
class DashboardAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'is_default', 'created_at', 'updated_at')
    list_filter = ('is_default', 'created_at')
    search_fields = ('user__username', 'name')
    readonly_fields = ('created_at', 'updated_at')
    raw_id_fields = ('user',)

