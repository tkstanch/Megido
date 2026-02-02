from django.contrib import admin
from .models import (
    ValidationRule, SecureFileUpload, RedirectLog, LoginAttempt,
    SecureSessionToken, AccessLog, SanitizedUserData, PasswordPolicy,
    ErrorLog, DependencyAudit
)


@admin.register(ValidationRule)
class ValidationRuleAdmin(admin.ModelAdmin):
    list_display = ['field_name', 'rule_type', 'is_active', 'created_at']
    list_filter = ['rule_type', 'is_active']
    search_fields = ['field_name']


@admin.register(SecureFileUpload)
class SecureFileUploadAdmin(admin.ModelAdmin):
    list_display = ['original_filename', 'file_id', 'uploaded_by', 'uploaded_at', 'is_scanned']
    list_filter = ['is_scanned', 'uploaded_at']
    search_fields = ['original_filename', 'file_id']
    readonly_fields = ['file_id']


@admin.register(RedirectLog)
class RedirectLogAdmin(admin.ModelAdmin):
    list_display = ['redirect_url', 'is_whitelisted', 'requested_by', 'requested_at', 'ip_address']
    list_filter = ['is_whitelisted', 'requested_at']
    search_fields = ['redirect_url', 'ip_address']


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['username', 'ip_address', 'success', 'attempted_at']
    list_filter = ['success', 'attempted_at']
    search_fields = ['username', 'ip_address']


@admin.register(SecureSessionToken)
class SecureSessionTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'is_active', 'created_at', 'expires_at', 'ip_address']
    list_filter = ['is_active', 'created_at']
    search_fields = ['user__username', 'token']
    readonly_fields = ['token']


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'resource_type', 'action', 'granted', 'accessed_at']
    list_filter = ['granted', 'action', 'accessed_at']
    search_fields = ['user__username', 'resource_type', 'resource_id']


@admin.register(SanitizedUserData)
class SanitizedUserDataAdmin(admin.ModelAdmin):
    list_display = ['user', 'field_name', 'created_at', 'updated_at']
    list_filter = ['created_at']
    search_fields = ['user__username', 'field_name']


@admin.register(PasswordPolicy)
class PasswordPolicyAdmin(admin.ModelAdmin):
    list_display = ['min_length', 'is_active', 'created_at']
    list_filter = ['is_active']


@admin.register(ErrorLog)
class ErrorLogAdmin(admin.ModelAdmin):
    list_display = ['error_code', 'error_type', 'user', 'occurred_at']
    list_filter = ['error_type', 'occurred_at']
    search_fields = ['error_code', 'error_type']
    readonly_fields = ['error_code']


@admin.register(DependencyAudit)
class DependencyAuditAdmin(admin.ModelAdmin):
    list_display = ['package_name', 'version', 'severity', 'is_patched', 'discovered_at']
    list_filter = ['severity', 'is_patched', 'discovered_at']
    search_fields = ['package_name', 'vulnerability_id']
