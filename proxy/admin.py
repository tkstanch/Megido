from django.contrib import admin
from .models import ProxyRequest, ProxyResponse


@admin.register(ProxyRequest)
class ProxyRequestAdmin(admin.ModelAdmin):
    list_display = ('method', 'url', 'host', 'port', 'timestamp')
    list_filter = ('method', 'host', 'timestamp')
    search_fields = ('url', 'host')
    ordering = ('-timestamp',)


@admin.register(ProxyResponse)
class ProxyResponseAdmin(admin.ModelAdmin):
    list_display = ('request', 'status_code', 'response_time', 'timestamp')
    list_filter = ('status_code', 'timestamp')
    ordering = ('-timestamp',)
