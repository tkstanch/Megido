from django.contrib import admin
from .models import Scan


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('target', 'scan_date', 'total_urls', 'total_emails')
    list_filter = ('scan_date',)
    search_fields = ('target',)
    readonly_fields = ('scan_date',)
