from django.contrib import admin
from .models import InterceptorSettings, InterceptedRequest, InterceptedResponse, PayloadRule


@admin.register(InterceptorSettings)
class InterceptorSettingsAdmin(admin.ModelAdmin):
    """Admin interface for interceptor settings"""
    list_display = ['is_enabled', 'updated_at']
    
    def has_add_permission(self, request):
        # Only allow one instance
        return not InterceptorSettings.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        # Don't allow deletion
        return False


@admin.register(InterceptedRequest)
class InterceptedRequestAdmin(admin.ModelAdmin):
    """Admin interface for intercepted requests"""
    list_display = ['id', 'method', 'url_short', 'source_app', 'timestamp']
    list_filter = ['method', 'source_app', 'timestamp']
    search_fields = ['url', 'body']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)
    
    def url_short(self, obj):
        """Show truncated URL"""
        if len(obj.url) > 60:
            return obj.url[:60] + "..."
        return obj.url
    url_short.short_description = 'URL'


@admin.register(InterceptedResponse)
class InterceptedResponseAdmin(admin.ModelAdmin):
    """Admin interface for intercepted responses"""
    list_display = ['id', 'request', 'status_code', 'response_time']
    list_filter = ['status_code']
    search_fields = ['body']
    
    def has_add_permission(self, request):
        # Responses are created by the system
        return False


@admin.register(PayloadRule)
class PayloadRuleAdmin(admin.ModelAdmin):
    """Admin interface for payload rules"""
    list_display = ['name', 'injection_type', 'active', 'created_by', 'created_at']
    list_filter = ['injection_type', 'active', 'created_at']
    search_fields = ['name', 'target_url_pattern']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'active', 'created_by')
        }),
        ('Targeting', {
            'fields': ('target_url_pattern', 'target_apps')
        }),
        ('Injection Configuration', {
            'fields': ('injection_type', 'injection_point', 'payload_content')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
