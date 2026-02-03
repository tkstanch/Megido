from django.contrib import admin
from .models import SQLInjectionTask, SQLInjectionResult


@admin.register(SQLInjectionTask)
class SQLInjectionTaskAdmin(admin.ModelAdmin):
    list_display = ('id', 'target_url_short', 'http_method', 'status', 
                   'vulnerabilities_found', 'created_at', 'completed_at')
    list_filter = ('status', 'http_method', 'enable_error_based', 
                  'enable_time_based', 'enable_exploitation')
    search_fields = ('target_url', 'error_message')
    readonly_fields = ('created_at', 'started_at', 'completed_at', 'vulnerabilities_found')
    
    fieldsets = (
        ('Target Information', {
            'fields': ('target_url', 'http_method', 'get_params', 'post_params', 
                      'cookies', 'headers')
        }),
        ('Attack Configuration', {
            'fields': ('enable_error_based', 'enable_time_based', 'enable_exploitation')
        }),
        ('Stealth Configuration', {
            'fields': ('use_random_delays', 'min_delay', 'max_delay', 
                      'randomize_user_agent', 'use_payload_obfuscation'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('status', 'vulnerabilities_found', 'created_at', 
                      'started_at', 'completed_at', 'error_message')
        }),
    )
    
    def target_url_short(self, obj):
        """Return truncated URL for display"""
        if len(obj.target_url) > 50:
            return obj.target_url[:47] + '...'
        return obj.target_url
    target_url_short.short_description = 'Target URL'


@admin.register(SQLInjectionResult)
class SQLInjectionResultAdmin(admin.ModelAdmin):
    list_display = ('id', 'task_link', 'injection_type', 'vulnerable_parameter', 
                   'parameter_type', 'is_exploitable', 'database_type', 
                   'severity', 'detected_at')
    list_filter = ('injection_type', 'parameter_type', 'is_exploitable', 
                  'database_type', 'severity')
    search_fields = ('vulnerable_parameter', 'test_payload', 'detection_evidence')
    readonly_fields = ('detected_at',)
    
    fieldsets = (
        ('Task Information', {
            'fields': ('task',)
        }),
        ('Vulnerability Details', {
            'fields': ('injection_type', 'vulnerable_parameter', 'parameter_type',
                      'test_payload', 'detection_evidence', 'severity')
        }),
        ('Request/Response', {
            'fields': ('request_data', 'response_data'),
            'classes': ('collapse',)
        }),
        ('Exploitation Results', {
            'fields': ('is_exploitable', 'database_type', 'database_version',
                      'current_database', 'current_user', 'extracted_tables', 
                      'extracted_data'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('detected_at',)
        }),
    )
    
    def task_link(self, obj):
        """Return link to task"""
        return f"Task {obj.task.id}"
    task_link.short_description = 'Task'
