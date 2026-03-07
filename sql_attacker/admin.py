from django.contrib import admin
from .models import SQLInjectionTask, SQLInjectionResult, BugReport, BountyImpactReport


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


@admin.register(BugReport)
class BugReportAdmin(admin.ModelAdmin):
    list_display = (
        'bug_id', 'title_short', 'status', 'priority', 'assignee',
        'bounty_status', 'created_at',
    )
    list_filter = ('status', 'priority', 'bounty_status')
    search_fields = ('bug_id', 'title', 'assignee', 'triage_notes')
    readonly_fields = ('bug_id', 'created_at', 'updated_at')

    fieldsets = (
        ('Identification', {
            'fields': ('result', 'bug_id', 'title'),
        }),
        ('Triage', {
            'fields': ('status', 'priority', 'assignee', 'triage_notes',
                       'false_positive_reason', 'false_positive_indicators'),
        }),
        ('Verification', {
            'fields': ('verified_by', 'verified_at', 'resolution'),
            'classes': ('collapse',),
        }),
        ('Bounty', {
            'fields': ('bounty_status', 'bounty_amount', 'bounty_platform',
                       'bounty_submission_url'),
            'classes': ('collapse',),
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
        }),
    )

    def title_short(self, obj):
        return obj.title[:70] if len(obj.title) > 70 else obj.title
    title_short.short_description = 'Title'


@admin.register(BountyImpactReport)
class BountyImpactReportAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'bug_report', 'cvss_score', 'cwe_id',
        'estimated_bounty_range', 'submission_platform_template', 'created_at',
    )
    list_filter = ('submission_platform_template', 'cwe_id')
    search_fields = ('bug_report__bug_id', 'cwe_id', 'impact_summary')
    readonly_fields = ('created_at', 'updated_at')
