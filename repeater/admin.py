from django.contrib import admin
from .models import RepeaterRequest, RepeaterResponse, RepeaterTab


@admin.register(RepeaterTab)
class RepeaterTabAdmin(admin.ModelAdmin):
    list_display = ('name', 'order', 'follow_redirects', 'timeout', 'verify_ssl', 'created_at')
    list_filter = ('follow_redirects', 'verify_ssl', 'auto_content_length')
    ordering = ('order', 'created_at')


@admin.register(RepeaterRequest)
class RepeaterRequestAdmin(admin.ModelAdmin):
    list_display = ('name', 'method', 'url', 'tab', 'tab_history_index', 'created_at')
    list_filter = ('method', 'created_at', 'tab')
    search_fields = ('name', 'url')
    ordering = ('-created_at',)


@admin.register(RepeaterResponse)
class RepeaterResponseAdmin(admin.ModelAdmin):
    list_display = ('request', 'status_code', 'response_time', 'timestamp')
    list_filter = ('status_code', 'timestamp')
    ordering = ('-timestamp',)
