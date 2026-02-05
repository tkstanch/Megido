from django.contrib import admin
from .models import AppConfiguration, AppStateChange, AppSettings


@admin.register(AppConfiguration)
class AppConfigurationAdmin(admin.ModelAdmin):
    list_display = ['display_name', 'app_name', 'is_enabled', 'category', 'updated_at']
    list_filter = ['is_enabled', 'category']
    search_fields = ['app_name', 'display_name', 'description']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(AppStateChange)
class AppStateChangeAdmin(admin.ModelAdmin):
    list_display = ['app_config', 'user', 'previous_state', 'new_state', 'timestamp']
    list_filter = ['timestamp', 'new_state']
    readonly_fields = ['timestamp']


@admin.register(AppSettings)
class AppSettingsAdmin(admin.ModelAdmin):
    list_display = ['app_config', 'updated_at']
    readonly_fields = ['updated_at']
