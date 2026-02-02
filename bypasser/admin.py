from django.contrib import admin
from .models import (
    BypasserTarget, BypasserSession, CharacterProbe, 
    EncodingAttempt, BypassResult
)


@admin.register(BypasserTarget)
class BypasserTargetAdmin(admin.ModelAdmin):
    list_display = ('name', 'url', 'http_method', 'test_parameter', 'created_at')
    list_filter = ('http_method', 'created_at')
    search_fields = ('name', 'url', 'description')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(BypasserSession)
class BypasserSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'target', 'status', 'characters_tested', 'characters_blocked', 
                    'successful_bypasses', 'started_at')
    list_filter = ('status', 'started_at')
    search_fields = ('target__name', 'target__url')
    readonly_fields = ('started_at', 'completed_at')


@admin.register(CharacterProbe)
class CharacterProbeAdmin(admin.ModelAdmin):
    list_display = ('character', 'character_name', 'status', 'blocked_by_waf', 
                    'reflection_found', 'tested_at')
    list_filter = ('status', 'blocked_by_waf', 'reflection_found', 'tested_at')
    search_fields = ('character', 'character_name', 'character_code')
    readonly_fields = ('tested_at',)


@admin.register(EncodingAttempt)
class EncodingAttemptAdmin(admin.ModelAdmin):
    list_display = ('encoding_type', 'success', 'bypass_confirmed', 'original_payload', 
                    'encoded_payload', 'tested_at')
    list_filter = ('encoding_type', 'success', 'bypass_confirmed', 'tested_at')
    search_fields = ('original_payload', 'encoded_payload', 'notes')
    readonly_fields = ('tested_at',)


@admin.register(BypassResult)
class BypassResultAdmin(admin.ModelAdmin):
    list_display = ('character_probe', 'encoding_attempt', 'risk_level', 'discovered_at')
    list_filter = ('risk_level', 'discovered_at')
    search_fields = ('technique_description', 'payload_example', 'impact_description')
    readonly_fields = ('discovered_at',)
