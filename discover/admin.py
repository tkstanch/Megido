from django.contrib import admin
from .models import (
    Scan, SensitiveFinding, UserActivity, ScanRecommendation, Dashboard,
    Subdomain, DNSRecord, Certificate, Technology, EmailAddress, SocialProfile,
    CloudResource, PortService, ThreatIntelIndicator, ScanModule,
    CorrelationLink, ReconReport,
)


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


@admin.register(Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'ip_address', 'source', 'status_code', 'discovered_at')
    list_filter = ('source', 'discovered_at')
    search_fields = ('subdomain', 'ip_address')
    raw_id_fields = ('scan',)


@admin.register(DNSRecord)
class DNSRecordAdmin(admin.ModelAdmin):
    list_display = ('record_type', 'name', 'value_short', 'ttl', 'discovered_at')
    list_filter = ('record_type', 'discovered_at')
    search_fields = ('name', 'value')
    raw_id_fields = ('scan',)

    def value_short(self, obj):
        return obj.value[:80] + '...' if len(obj.value) > 80 else obj.value
    value_short.short_description = 'Value'


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ('subject_short', 'issuer_short', 'is_expired', 'is_self_signed', 'not_after', 'discovered_at')
    list_filter = ('is_expired', 'is_self_signed', 'discovered_at')
    search_fields = ('subject', 'issuer')
    raw_id_fields = ('scan',)

    def subject_short(self, obj):
        return obj.subject[:60] if obj.subject else '—'
    subject_short.short_description = 'Subject'

    def issuer_short(self, obj):
        return obj.issuer[:60] if obj.issuer else '—'
    issuer_short.short_description = 'Issuer'


@admin.register(Technology)
class TechnologyAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'version', 'confidence', 'discovered_at')
    list_filter = ('category', 'confidence', 'discovered_at')
    search_fields = ('name', 'version')
    raw_id_fields = ('scan',)


@admin.register(EmailAddress)
class EmailAddressAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'source', 'verified', 'breach_count', 'discovered_at')
    list_filter = ('verified', 'source', 'discovered_at')
    search_fields = ('email', 'first_name', 'last_name')
    raw_id_fields = ('scan',)


@admin.register(SocialProfile)
class SocialProfileAdmin(admin.ModelAdmin):
    list_display = ('platform', 'username', 'display_name', 'verified_exists', 'discovered_at')
    list_filter = ('platform', 'verified_exists', 'discovered_at')
    search_fields = ('platform', 'username', 'display_name')
    raw_id_fields = ('scan',)


@admin.register(CloudResource)
class CloudResourceAdmin(admin.ModelAdmin):
    list_display = ('resource_type', 'name', 'access_level', 'discovered_at')
    list_filter = ('resource_type', 'access_level', 'discovered_at')
    search_fields = ('name', 'url')
    raw_id_fields = ('scan',)


@admin.register(PortService)
class PortServiceAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'port', 'protocol', 'service_name', 'service_version', 'source', 'discovered_at')
    list_filter = ('protocol', 'source', 'discovered_at')
    search_fields = ('ip_address', 'service_name', 'banner')
    raw_id_fields = ('scan',)


@admin.register(ThreatIntelIndicator)
class ThreatIntelIndicatorAdmin(admin.ModelAdmin):
    list_display = ('indicator_type', 'value_short', 'source', 'threat_score', 'malicious_votes', 'discovered_at')
    list_filter = ('indicator_type', 'source', 'discovered_at')
    search_fields = ('value', 'source')
    raw_id_fields = ('scan',)

    def value_short(self, obj):
        return obj.value[:80] if obj.value else '—'
    value_short.short_description = 'Value'


@admin.register(ScanModule)
class ScanModuleAdmin(admin.ModelAdmin):
    list_display = ('module_name', 'status', 'items_found', 'duration_seconds', 'started_at', 'completed_at')
    list_filter = ('status', 'module_name')
    search_fields = ('module_name',)
    raw_id_fields = ('scan',)


@admin.register(CorrelationLink)
class CorrelationLinkAdmin(admin.ModelAdmin):
    list_display = ('link_type', 'source_entity_short', 'target_entity_short', 'confidence', 'created_at')
    list_filter = ('link_type', 'created_at')
    search_fields = ('source_entity', 'target_entity')
    raw_id_fields = ('scan',)

    def source_entity_short(self, obj):
        return obj.source_entity[:60]
    source_entity_short.short_description = 'Source'

    def target_entity_short(self, obj):
        return obj.target_entity[:60]
    target_entity_short.short_description = 'Target'


@admin.register(ReconReport)
class ReconReportAdmin(admin.ModelAdmin):
    list_display = ('title_short', 'format', 'risk_score', 'generated_at')
    list_filter = ('format', 'generated_at')
    search_fields = ('title', 'executive_summary')
    raw_id_fields = ('scan',)
    readonly_fields = ('generated_at',)

    def title_short(self, obj):
        return obj.title[:80] if obj.title else '—'
    title_short.short_description = 'Title'
