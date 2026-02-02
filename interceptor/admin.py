from django.contrib import admin
from .models import InterceptedRequest


@admin.register(InterceptedRequest)
class InterceptedRequestAdmin(admin.ModelAdmin):
    list_display = ('original_method', 'original_url', 'status', 'timestamp')
    list_filter = ('status', 'original_method', 'timestamp')
    search_fields = ('original_url',)
    ordering = ('-timestamp',)
