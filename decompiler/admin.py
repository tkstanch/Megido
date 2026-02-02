"""
Django admin configuration for the Decompiler app.

Registers models for management via Django admin interface.
"""
from django.contrib import admin
from .models import (
    ExtensionPackage,
    DecompilationJob,
    ObfuscationTechnique,
    DetectedObfuscation,
    ExtensionAnalysis,
    TrafficInterception
)


@admin.register(ExtensionPackage)
class ExtensionPackageAdmin(admin.ModelAdmin):
    """Admin interface for ExtensionPackage model."""
    list_display = ['name', 'extension_type', 'status', 'downloaded_at', 'file_size']
    list_filter = ['extension_type', 'status', 'downloaded_at']
    search_fields = ['name', 'download_url']
    readonly_fields = ['package_id', 'downloaded_at', 'checksum_md5', 'checksum_sha256']
    fieldsets = (
        ('Package Information', {
            'fields': ('package_id', 'name', 'extension_type', 'version', 'status')
        }),
        ('Download Details', {
            'fields': ('download_url', 'downloaded_at', 'downloaded_by')
        }),
        ('File Information', {
            'fields': ('bytecode_file', 'file_size', 'checksum_md5', 'checksum_sha256')
        }),
        ('Notes', {
            'fields': ('notes',),
            'classes': ('collapse',)
        }),
    )


@admin.register(DecompilationJob)
class DecompilationJobAdmin(admin.ModelAdmin):
    """Admin interface for DecompilationJob model."""
    list_display = ['job_id', 'extension_package', 'status', 'decompiler_tool', 'created_at', 'completed_at']
    list_filter = ['status', 'decompiler_tool', 'obfuscation_detected', 'created_at']
    search_fields = ['job_id', 'extension_package__name']
    readonly_fields = ['job_id', 'created_at', 'started_at', 'completed_at']
    fieldsets = (
        ('Job Information', {
            'fields': ('job_id', 'extension_package', 'status', 'created_by')
        }),
        ('Timing', {
            'fields': ('created_at', 'started_at', 'completed_at')
        }),
        ('Decompiler Settings', {
            'fields': ('decompiler_tool', 'decompiler_version', 'options')
        }),
        ('Results', {
            'fields': ('decompiled_source', 'log_output', 'error_message')
        }),
        ('Metrics', {
            'fields': ('num_classes_found', 'num_methods_found', 'obfuscation_detected')
        }),
    )


@admin.register(ObfuscationTechnique)
class ObfuscationTechniqueAdmin(admin.ModelAdmin):
    """Admin interface for ObfuscationTechnique model."""
    list_display = ['name', 'obfuscation_type', 'severity', 'created_at']
    list_filter = ['obfuscation_type', 'severity']
    search_fields = ['name', 'description', 'common_tools']
    readonly_fields = ['technique_id', 'created_at', 'updated_at']
    fieldsets = (
        ('Technique Information', {
            'fields': ('technique_id', 'name', 'obfuscation_type', 'severity')
        }),
        ('Description', {
            'fields': ('description', 'common_tools')
        }),
        ('Detection & Deobfuscation', {
            'fields': ('detection_pattern', 'deobfuscation_strategy')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at')
        }),
    )


@admin.register(DetectedObfuscation)
class DetectedObfuscationAdmin(admin.ModelAdmin):
    """Admin interface for DetectedObfuscation model."""
    list_display = ['obfuscation_technique', 'decompilation_job', 'confidence_score', 'deobfuscated', 'detected_at']
    list_filter = ['obfuscation_technique', 'deobfuscated', 'deobfuscation_success', 'detected_at']
    search_fields = ['decompilation_job__job_id', 'obfuscation_technique__name', 'location']
    readonly_fields = ['detection_id', 'detected_at']


@admin.register(ExtensionAnalysis)
class ExtensionAnalysisAdmin(admin.ModelAdmin):
    """Admin interface for ExtensionAnalysis model."""
    list_display = ['decompilation_job', 'risk_level', 'analyzed_at', 'analyzed_by']
    list_filter = ['risk_level', 'analyzed_at']
    search_fields = ['decompilation_job__job_id', 'summary']
    readonly_fields = ['analysis_id', 'analyzed_at']
    fieldsets = (
        ('Analysis Information', {
            'fields': ('analysis_id', 'decompilation_job', 'analyzed_at', 'analyzed_by')
        }),
        ('Findings', {
            'fields': ('api_endpoints', 'network_requests', 'data_flows')
        }),
        ('Security', {
            'fields': ('vulnerabilities', 'privacy_concerns', 'risk_level')
        }),
        ('Manipulation', {
            'fields': ('javascript_hooks', 'dom_elements')
        }),
        ('Summary', {
            'fields': ('summary', 'recommendations')
        }),
    )


@admin.register(TrafficInterception)
class TrafficInterceptionAdmin(admin.ModelAdmin):
    """Admin interface for TrafficInterception model."""
    list_display = ['timestamp', 'protocol', 'request_method', 'request_url', 'response_status', 'is_serialized']
    list_filter = ['protocol', 'request_method', 'is_serialized', 'timestamp']
    search_fields = ['request_url', 'serialization_format']
    readonly_fields = ['interception_id', 'timestamp']
    fieldsets = (
        ('Interception Information', {
            'fields': ('interception_id', 'extension_package', 'timestamp', 'protocol')
        }),
        ('Request', {
            'fields': ('request_url', 'request_method', 'request_headers', 'request_body')
        }),
        ('Response', {
            'fields': ('response_status', 'response_headers', 'response_body')
        }),
        ('Analysis', {
            'fields': ('is_serialized', 'serialization_format', 'deserialized_data')
        }),
        ('Context', {
            'fields': ('user_agent', 'source_ip', 'notes')
        }),
    )

