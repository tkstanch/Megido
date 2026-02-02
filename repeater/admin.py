from django.contrib import admin
from .models import RepeaterRequest, RepeaterResponse


@admin.register(RepeaterRequest)
class RepeaterRequestAdmin(admin.ModelAdmin):
    list_display = ('name', 'method', 'url', 'created_at')
    list_filter = ('method', 'created_at')
    search_fields = ('name', 'url')
    ordering = ('-created_at',)


@admin.register(RepeaterResponse)
class RepeaterResponseAdmin(admin.ModelAdmin):
    list_display = ('request', 'status_code', 'response_time', 'timestamp')
    list_filter = ('status_code', 'timestamp')
    ordering = ('-timestamp',)
