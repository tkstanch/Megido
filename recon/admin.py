"""
Django admin registration for the Recon app.
"""
from django.contrib import admin

from .models import (
    ReconProject,
    ScopeTarget,
    WhoisResult,
    IPDiscovery,
    CertificateDiscovery,
    SubdomainResult,
    ServicePort,
    DirectoryFinding,
    BucketFinding,
    GitHubFinding,
    TechFingerprint,
    ReconTask,
)


@admin.register(ReconProject)
class ReconProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description', 'user__username')
    readonly_fields = ('created_at', 'updated_at')
    raw_id_fields = ('user',)


@admin.register(ScopeTarget)
class ScopeTargetAdmin(admin.ModelAdmin):
    list_display = ('target', 'target_type', 'is_in_scope', 'project', 'added_at')
    list_filter = ('target_type', 'is_in_scope', 'added_at')
    search_fields = ('target', 'notes', 'project__name')
    raw_id_fields = ('project',)


@admin.register(WhoisResult)
class WhoisResultAdmin(admin.ModelAdmin):
    list_display = ('domain', 'registrar', 'registrant_org', 'creation_date', 'expiration_date', 'queried_at')
    list_filter = ('queried_at',)
    search_fields = ('domain', 'registrar', 'registrant_name', 'registrant_email', 'registrant_org')
    readonly_fields = ('queried_at',)
    raw_id_fields = ('project',)


@admin.register(IPDiscovery)
class IPDiscoveryAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'domain', 'asn_number', 'asn_org', 'asn_country', 'discovered_at')
    list_filter = ('asn_country', 'discovered_at')
    search_fields = ('ip_address', 'domain', 'asn_number', 'asn_org')
    readonly_fields = ('discovered_at',)
    raw_id_fields = ('project',)


@admin.register(CertificateDiscovery)
class CertificateDiscoveryAdmin(admin.ModelAdmin):
    list_display = ('domain', 'issuer', 'not_before', 'not_after', 'source', 'discovered_at')
    list_filter = ('source', 'discovered_at')
    search_fields = ('domain', 'issuer', 'subject', 'cert_id')
    readonly_fields = ('discovered_at',)
    raw_id_fields = ('project',)


@admin.register(SubdomainResult)
class SubdomainResultAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'ip_address', 'status_code', 'is_alive', 'source', 'discovered_at')
    list_filter = ('is_alive', 'source', 'discovered_at')
    search_fields = ('subdomain', 'ip_address', 'title')
    readonly_fields = ('discovered_at', 'last_checked')
    raw_id_fields = ('project',)


@admin.register(ServicePort)
class ServicePortAdmin(admin.ModelAdmin):
    list_display = ('host', 'port', 'protocol', 'service_name', 'service_version', 'is_open', 'source', 'discovered_at')
    list_filter = ('protocol', 'is_open', 'source', 'discovered_at')
    search_fields = ('host', 'ip_address', 'service_name', 'banner')
    readonly_fields = ('discovered_at',)
    raw_id_fields = ('project',)


@admin.register(DirectoryFinding)
class DirectoryFindingAdmin(admin.ModelAdmin):
    list_display = ('path', 'status_code', 'content_length', 'is_interesting', 'target_url_short', 'discovered_at')
    list_filter = ('status_code', 'is_interesting', 'discovered_at')
    search_fields = ('path', 'full_url', 'target_url', 'content_type')
    readonly_fields = ('discovered_at',)
    raw_id_fields = ('project',)

    def target_url_short(self, obj):
        return obj.target_url[:60] + '...' if len(obj.target_url) > 60 else obj.target_url
    target_url_short.short_description = 'Target URL'


@admin.register(BucketFinding)
class BucketFindingAdmin(admin.ModelAdmin):
    list_display = ('bucket_name', 'provider', 'is_public', 'is_listable', 'is_writable', 'discovered_at')
    list_filter = ('provider', 'is_public', 'is_listable', 'is_writable', 'discovered_at')
    search_fields = ('bucket_name', 'bucket_url', 'keywords')
    readonly_fields = ('discovered_at',)
    raw_id_fields = ('project',)


@admin.register(GitHubFinding)
class GitHubFindingAdmin(admin.ModelAdmin):
    list_display = ('finding_type', 'repository', 'severity', 'is_verified', 'discovered_at')
    list_filter = ('finding_type', 'severity', 'is_verified', 'discovered_at')
    search_fields = ('repository', 'file_path', 'content', 'url')
    readonly_fields = ('discovered_at',)
    raw_id_fields = ('project',)


@admin.register(TechFingerprint)
class TechFingerprintAdmin(admin.ModelAdmin):
    list_display = ('technology', 'version', 'category', 'confidence', 'cve_count', 'target_url_short', 'discovered_at')
    list_filter = ('category', 'discovered_at')
    search_fields = ('technology', 'version', 'category', 'target_url')
    readonly_fields = ('discovered_at',)
    raw_id_fields = ('project',)

    def target_url_short(self, obj):
        return obj.target_url[:60] + '...' if len(obj.target_url) > 60 else obj.target_url
    target_url_short.short_description = 'Target URL'


@admin.register(ReconTask)
class ReconTaskAdmin(admin.ModelAdmin):
    list_display = ('task_type', 'status', 'target', 'progress', 'project', 'created_at', 'completed_at')
    list_filter = ('task_type', 'status', 'created_at')
    search_fields = ('target', 'celery_task_id', 'project__name', 'result_summary', 'error_message')
    readonly_fields = ('created_at', 'started_at', 'completed_at')
    raw_id_fields = ('project',)
