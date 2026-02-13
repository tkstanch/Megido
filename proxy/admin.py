from django.contrib import admin
from .models import (
    ProxyRequest, ProxyResponse, ProxyConfiguration,
    WebSocketMessage, ProxyError, AuthenticationAttempt
)


@admin.register(ProxyConfiguration)
class ProxyConfigurationAdmin(admin.ModelAdmin):
    """Admin for proxy configuration"""
    list_display = ['id', 'auth_enabled', 'logging_enabled', 'websocket_enabled', 'updated_at']
    fieldsets = (
        ('Authentication', {
            'fields': ('auth_enabled', 'auth_username', 'auth_password', 'auth_token')
        }),
        ('IP Filtering', {
            'fields': ('ip_whitelist', 'ip_blacklist')
        }),
        ('Logging', {
            'fields': ('logging_enabled', 'log_request_body', 'log_response_body', 'log_directory')
        }),
        ('Performance', {
            'fields': ('connection_timeout', 'transfer_timeout', 'max_concurrent_clients', 'cache_enabled')
        }),
        ('Features', {
            'fields': ('websocket_enabled',)
        }),
    )


@admin.register(ProxyRequest)
class ProxyRequestAdmin(admin.ModelAdmin):
    """Admin for proxy requests"""
    list_display = ['id', 'method', 'protocol', 'host', 'source_ip', 'is_replay', 'timestamp']
    list_filter = ['method', 'protocol', 'is_replay', 'timestamp']
    search_fields = ['url', 'host', 'source_ip', 'user_agent']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Request Info', {
            'fields': ('method', 'url', 'protocol', 'host', 'port')
        }),
        ('Headers & Body', {
            'fields': ('headers', 'body', 'request_size')
        }),
        ('Client Info', {
            'fields': ('source_ip', 'user_agent')
        }),
        ('Security', {
            'fields': ('auth_attempted', 'auth_success', 'auth_user')
        }),
        ('Replay', {
            'fields': ('is_replay', 'original_request')
        }),
        ('Metadata', {
            'fields': ('timestamp',)
        }),
    )


@admin.register(ProxyResponse)
class ProxyResponseAdmin(admin.ModelAdmin):
    """Admin for proxy responses"""
    list_display = ['id', 'status_code', 'response_time', 'response_size', 'cached', 'timestamp']
    list_filter = ['status_code', 'cached', 'timestamp']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Response Info', {
            'fields': ('request', 'status_code', 'response_time', 'response_size', 'cached')
        }),
        ('Headers & Body', {
            'fields': ('headers', 'body')
        }),
        ('Error Info', {
            'fields': ('error_message',)
        }),
        ('Metadata', {
            'fields': ('timestamp',)
        }),
    )


@admin.register(WebSocketMessage)
class WebSocketMessageAdmin(admin.ModelAdmin):
    """Admin for WebSocket messages"""
    list_display = ['id', 'connection_id', 'direction', 'message_type', 'payload_size', 'timestamp']
    list_filter = ['direction', 'message_type', 'timestamp']
    search_fields = ['connection_id', 'url', 'source_ip']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Connection Info', {
            'fields': ('connection_id', 'url', 'source_ip')
        }),
        ('Message Info', {
            'fields': ('direction', 'message_type', 'payload', 'payload_size')
        }),
        ('Metadata', {
            'fields': ('timestamp',)
        }),
    )


@admin.register(ProxyError)
class ProxyErrorAdmin(admin.ModelAdmin):
    """Admin for proxy errors"""
    list_display = ['id', 'error_type', 'error_message_short', 'source_ip', 'timestamp']
    list_filter = ['error_type', 'timestamp']
    search_fields = ['error_message', 'url', 'source_ip']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Error Info', {
            'fields': ('error_type', 'error_message', 'stack_trace')
        }),
        ('Context', {
            'fields': ('url', 'source_ip', 'request')
        }),
        ('Metadata', {
            'fields': ('timestamp',)
        }),
    )
    
    def error_message_short(self, obj):
        """Show truncated error message"""
        return obj.error_message[:100] + '...' if len(obj.error_message) > 100 else obj.error_message
    error_message_short.short_description = 'Error Message'


@admin.register(AuthenticationAttempt)
class AuthenticationAttemptAdmin(admin.ModelAdmin):
    """Admin for authentication attempts"""
    list_display = ['id', 'username', 'source_ip', 'success', 'timestamp']
    list_filter = ['success', 'timestamp']
    search_fields = ['username', 'source_ip']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Auth Info', {
            'fields': ('username', 'source_ip', 'success', 'failure_reason')
        }),
        ('Metadata', {
            'fields': ('timestamp',)
        }),
    )
