from django.contrib import admin
from .models import (
    BypasserTarget, BypasserSession, CharacterProbe, 
    EncodingAttempt, BypassResult, CustomBypassTechnique,
    CustomTechniqueExecution, ReadyMadePayload, PayloadExecution
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


@admin.register(CustomBypassTechnique)
class CustomBypassTechniqueAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'times_used', 'times_successful', 'success_rate', 
                    'is_active', 'created_at')
    list_filter = ('category', 'is_active', 'is_public', 'created_at')
    search_fields = ('name', 'description', 'tags', 'author')
    readonly_fields = ('created_at', 'updated_at', 'success_rate')
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'category', 'author')
        }),
        ('Technique Definition', {
            'fields': ('technique_template', 'example_input', 'example_output')
        }),
        ('Metadata', {
            'fields': ('tags', 'is_active', 'is_public')
        }),
        ('Statistics', {
            'fields': ('times_used', 'times_successful', 'success_rate', 'created_at', 'updated_at')
        }),
    )


@admin.register(CustomTechniqueExecution)
class CustomTechniqueExecutionAdmin(admin.ModelAdmin):
    list_display = ('technique', 'session', 'success', 'bypass_confirmed', 
                    'reflection_found', 'executed_at')
    list_filter = ('success', 'bypass_confirmed', 'waf_triggered', 'executed_at')
    search_fields = ('technique__name', 'input_payload', 'output_payload', 'notes')
    readonly_fields = ('executed_at',)


@admin.register(ReadyMadePayload)
class ReadyMadePayloadAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'bypass_target', 'risk_level', 'times_used', 
                    'times_successful', 'success_rate', 'is_active')
    list_filter = ('category', 'bypass_target', 'risk_level', 'is_active', 'is_built_in')
    search_fields = ('name', 'description', 'payload', 'tags')
    readonly_fields = ('created_at', 'updated_at', 'success_rate')
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'category', 'bypass_target', 'risk_level')
        }),
        ('Payload', {
            'fields': ('payload',)
        }),
        ('Metadata', {
            'fields': ('tags', 'is_active', 'is_built_in')
        }),
        ('Statistics', {
            'fields': ('times_used', 'times_successful', 'success_rate', 'created_at', 'updated_at')
        }),
    )


@admin.register(PayloadExecution)
class PayloadExecutionAdmin(admin.ModelAdmin):
    list_display = ('payload', 'session', 'success', 'bypass_confirmed', 
                    'reflection_found', 'executed_at')
    list_filter = ('success', 'bypass_confirmed', 'waf_triggered', 'executed_at')
    search_fields = ('payload__name', 'original_payload', 'transformed_payload', 'notes')
    readonly_fields = ('executed_at',)
    fieldsets = (
        ('Basic Information', {
            'fields': ('session', 'payload')
        }),
        ('Transformations', {
            'fields': ('transformations_applied', 'original_payload', 'transformed_payload')
        }),
        ('Results', {
            'fields': ('success', 'bypass_confirmed', 'reflection_found', 'waf_triggered',
                      'http_status_code', 'response_time', 'response_length')
        }),
        ('Additional Details', {
            'fields': ('error_message', 'notes', 'executed_at')
        }),
    )
