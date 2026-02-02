from django.contrib import admin
from .models import (
    SpiderTarget, SpiderSession, DiscoveredURL, 
    HiddenContent, BruteForceAttempt, InferredContent, 
    ToolScanResult
)


@admin.register(SpiderTarget)
class SpiderTargetAdmin(admin.ModelAdmin):
    list_display = ['name', 'url', 'max_depth', 'use_dirbuster', 'use_nikto', 'created_at']
    list_filter = ['use_dirbuster', 'use_nikto', 'use_wikto', 'enable_brute_force']
    search_fields = ['name', 'url', 'description']


@admin.register(SpiderSession)
class SpiderSessionAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'status', 'urls_discovered', 'hidden_content_found', 'started_at']
    list_filter = ['status', 'started_at']
    search_fields = ['target__name', 'target__url']
    readonly_fields = ['started_at', 'completed_at']


@admin.register(DiscoveredURL)
class DiscoveredURLAdmin(admin.ModelAdmin):
    list_display = ['url', 'discovery_method', 'status_code', 'is_hidden', 'is_interesting', 'discovered_at']
    list_filter = ['discovery_method', 'is_hidden', 'is_interesting', 'status_code']
    search_fields = ['url', 'title']


@admin.register(HiddenContent)
class HiddenContentAdmin(admin.ModelAdmin):
    list_display = ['url', 'content_type', 'discovery_method', 'risk_level', 'status_code', 'discovered_at']
    list_filter = ['content_type', 'risk_level', 'discovery_method']
    search_fields = ['url', 'notes']


@admin.register(BruteForceAttempt)
class BruteForceAttemptAdmin(admin.ModelAdmin):
    list_display = ['full_url', 'status_code', 'success', 'response_time', 'created_at']
    list_filter = ['success', 'status_code']
    search_fields = ['base_url', 'path_tested', 'full_url']


@admin.register(InferredContent)
class InferredContentAdmin(admin.ModelAdmin):
    list_display = ['inferred_url', 'inference_type', 'confidence', 'verified', 'exists', 'created_at']
    list_filter = ['inference_type', 'verified', 'exists']
    search_fields = ['source_url', 'inferred_url', 'reasoning']


@admin.register(ToolScanResult)
class ToolScanResultAdmin(admin.ModelAdmin):
    list_display = ['tool_name', 'session', 'status', 'findings_count', 'started_at', 'completed_at']
    list_filter = ['tool_name', 'status']
    readonly_fields = ['started_at', 'completed_at']
