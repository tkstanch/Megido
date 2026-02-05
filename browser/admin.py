from django.contrib import admin
from .models import BrowserSession, BrowserHistory, BrowserAppInteraction, BrowserSettings


@admin.register(BrowserSession)
class BrowserSessionAdmin(admin.ModelAdmin):
    list_display = ['session_name', 'user', 'started_at', 'ended_at', 'is_active']
    list_filter = ['is_active', 'started_at']
    search_fields = ['session_name']
    readonly_fields = ['started_at']


@admin.register(BrowserHistory)
class BrowserHistoryAdmin(admin.ModelAdmin):
    list_display = ['url', 'title', 'session', 'visited_at']
    list_filter = ['visited_at']
    search_fields = ['url', 'title']
    readonly_fields = ['visited_at']


@admin.register(BrowserAppInteraction)
class BrowserAppInteractionAdmin(admin.ModelAdmin):
    list_display = ['app_name', 'action', 'target_url', 'session', 'timestamp']
    list_filter = ['app_name', 'timestamp']
    search_fields = ['app_name', 'action', 'target_url']
    readonly_fields = ['timestamp']


@admin.register(BrowserSettings)
class BrowserSettingsAdmin(admin.ModelAdmin):
    list_display = ['user', 'proxy_enabled', 'enable_javascript', 'updated_at']
    readonly_fields = ['updated_at']
