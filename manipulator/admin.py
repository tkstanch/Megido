from django.contrib import admin
from .models import (
    VulnerabilityType, Payload, EncodingTechnique,
    PayloadManipulation, CraftedPayload
)


@admin.register(VulnerabilityType)
class VulnerabilityTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'severity', 'created_at')
    list_filter = ('category', 'severity')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at',)


@admin.register(Payload)
class PayloadAdmin(admin.ModelAdmin):
    list_display = ('name', 'vulnerability', 'platform', 'is_custom', 'success_rate', 'created_at')
    list_filter = ('vulnerability', 'platform', 'is_custom', 'is_obfuscated')
    search_fields = ('name', 'payload_text', 'description')
    readonly_fields = ('created_at',)
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'vulnerability', 'payload_text', 'description')
        }),
        ('Metadata', {
            'fields': ('platform', 'bypass_technique', 'is_obfuscated', 'success_rate')
        }),
        ('User Information', {
            'fields': ('is_custom', 'submitted_by', 'created_at')
        }),
    )


@admin.register(EncodingTechnique)
class EncodingTechniqueAdmin(admin.ModelAdmin):
    list_display = ('name', 'encoding_type', 'is_reversible')
    list_filter = ('encoding_type', 'is_reversible')
    search_fields = ('name', 'description')


@admin.register(PayloadManipulation)
class PayloadManipulationAdmin(admin.ModelAdmin):
    list_display = ('name', 'vulnerability', 'effectiveness', 'target_defense', 'created_at')
    list_filter = ('vulnerability', 'effectiveness')
    search_fields = ('name', 'technique', 'description')
    readonly_fields = ('created_at',)


@admin.register(CraftedPayload)
class CraftedPayloadAdmin(admin.ModelAdmin):
    list_display = ('base_payload', 'tested', 'successful', 'created_at')
    list_filter = ('tested', 'successful', 'created_at')
    search_fields = ('crafted_text', 'test_notes')
    readonly_fields = ('created_at', 'test_date')
    fieldsets = (
        ('Payload Information', {
            'fields': ('base_payload', 'crafted_text')
        }),
        ('Applied Techniques', {
            'fields': ('encodings_applied', 'manipulations_applied')
        }),
        ('Testing Results', {
            'fields': ('tested', 'successful', 'test_notes', 'test_date', 'created_at')
        }),
    )
