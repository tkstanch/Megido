from django.contrib import admin
from .models import (
    ScanTarget, ScanResult, PortScan, ServiceDetection,
    OSFingerprint, PacketCapture, StealthConfiguration, ScanLog
)


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ['target', 'status', 'scan_type', 'stealth_mode', 'created_by', 'created_at']
    list_filter = ['status', 'scan_type', 'stealth_mode', 'created_at']
    search_fields = ['target', 'notes']
    readonly_fields = ['id', 'created_at']


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['scan_target', 'started_at', 'completed_at', 'host_discovered', 'open_ports_count']
    list_filter = ['host_discovered', 'started_at']
    search_fields = ['scan_target__target', 'summary']
    readonly_fields = ['id', 'started_at']


@admin.register(PortScan)
class PortScanAdmin(admin.ModelAdmin):
    list_display = ['scan_result', 'port', 'protocol', 'state', 'scan_type', 'service_name']
    list_filter = ['state', 'protocol', 'scan_type']
    search_fields = ['service_name']
    readonly_fields = ['id', 'discovered_at']


@admin.register(ServiceDetection)
class ServiceDetectionAdmin(admin.ModelAdmin):
    list_display = ['port_scan', 'service_name', 'service_version', 'product', 'confidence']
    list_filter = ['service_name', 'confidence']
    search_fields = ['service_name', 'product', 'service_version']
    readonly_fields = ['id', 'detected_at']


@admin.register(OSFingerprint)
class OSFingerprintAdmin(admin.ModelAdmin):
    list_display = ['scan_result', 'os_name', 'os_family', 'accuracy', 'fingerprint_method']
    list_filter = ['os_family', 'fingerprint_method']
    search_fields = ['os_name', 'os_family']
    readonly_fields = ['id', 'detected_at']


@admin.register(PacketCapture)
class PacketCaptureAdmin(admin.ModelAdmin):
    list_display = ['scan_result', 'packet_type', 'source_ip', 'destination_ip', 'relevance', 'captured_at']
    list_filter = ['packet_type', 'relevance', 'captured_at']
    search_fields = ['source_ip', 'destination_ip', 'analysis_notes']
    readonly_fields = ['id', 'captured_at']


@admin.register(StealthConfiguration)
class StealthConfigurationAdmin(admin.ModelAdmin):
    list_display = ['name', 'timing_template', 'scan_delay', 'fragment_packets', 'is_default']
    list_filter = ['timing_template', 'fragment_packets', 'is_default']
    search_fields = ['name', 'description']
    readonly_fields = ['id', 'created_at']


@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ['scan_result', 'level', 'message', 'logged_at']
    list_filter = ['level', 'logged_at']
    search_fields = ['message']
    readonly_fields = ['id', 'logged_at']
