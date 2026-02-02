from django.contrib import admin
from .models import CollaboratorServer, Interaction


@admin.register(CollaboratorServer)
class CollaboratorServerAdmin(admin.ModelAdmin):
    list_display = ('domain', 'ip_address', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('domain', 'ip_address', 'description')
    ordering = ('-created_at',)


@admin.register(Interaction)
class InteractionAdmin(admin.ModelAdmin):
    list_display = ('server', 'interaction_type', 'source_ip', 'timestamp')
    list_filter = ('interaction_type', 'timestamp')
    search_fields = ('source_ip', 'dns_query_name', 'http_path')
    ordering = ('-timestamp',)
    readonly_fields = ('timestamp',)
