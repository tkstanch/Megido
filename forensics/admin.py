"""Admin configuration for the Forensics app."""
from django.contrib import admin
from .models import (ForensicCase, EvidenceItem, ChainOfCustodyEntry, ForensicFile,
                     TimelineEvent, IOCIndicator, ForensicReport, AnalysisTask,
                     YARARule, HashSet, Artifact, NetworkConnection, ProcessInfo)


@admin.register(ForensicCase)
class ForensicCaseAdmin(admin.ModelAdmin):
    list_display = ['case_number', 'title', 'status', 'classification', 'investigator', 'created_at']
    list_filter = ['status', 'classification', 'created_at']
    search_fields = ['case_number', 'title', 'description']
    date_hierarchy = 'created_at'


@admin.register(EvidenceItem)
class EvidenceItemAdmin(admin.ModelAdmin):
    list_display = ['name', 'case', 'acquisition_type', 'integrity_verified', 'acquisition_timestamp']
    list_filter = ['acquisition_type', 'integrity_verified']
    search_fields = ['name', 'description', 'sha256_hash']


@admin.register(ChainOfCustodyEntry)
class ChainOfCustodyEntryAdmin(admin.ModelAdmin):
    list_display = ['evidence', 'action', 'performed_by', 'timestamp', 'location']
    list_filter = ['timestamp']
    search_fields = ['action', 'notes']


@admin.register(ForensicFile)
class ForensicFileAdmin(admin.ModelAdmin):
    list_display = ['original_filename', 'file_size', 'file_type', 'sha256_hash', 'entropy', 'upload_date']
    list_filter = ['file_type', 'is_encrypted', 'is_packed', 'analysis_complete']
    search_fields = ['original_filename', 'sha256_hash', 'md5_hash']
    readonly_fields = ['sha256_hash', 'md5_hash', 'sha1_hash', 'sha512_hash', 'hex_sample', 'entropy']


@admin.register(TimelineEvent)
class TimelineEventAdmin(admin.ModelAdmin):
    list_display = ['event_time', 'event_type', 'source', 'description']
    list_filter = ['event_type', 'source']
    search_fields = ['description', 'artifact_path']
    date_hierarchy = 'event_time'


@admin.register(IOCIndicator)
class IOCIndicatorAdmin(admin.ModelAdmin):
    list_display = ['ioc_type', 'ioc_value', 'confidence', 'source', 'first_seen']
    list_filter = ['ioc_type', 'confidence']
    search_fields = ['ioc_value', 'source', 'mitre_technique']


@admin.register(ForensicReport)
class ForensicReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'case', 'report_type', 'format', 'generated_by', 'generated_at']
    list_filter = ['report_type', 'format']
    search_fields = ['title', 'summary']


@admin.register(AnalysisTask)
class AnalysisTaskAdmin(admin.ModelAdmin):
    list_display = ['task_type', 'status', 'forensic_file', 'created_at', 'progress_percent']
    list_filter = ['task_type', 'status']
    search_fields = ['celery_task_id', 'result_summary']


@admin.register(YARARule)
class YARARuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'author', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name', 'description', 'tags']


@admin.register(HashSet)
class HashSetAdmin(admin.ModelAdmin):
    list_display = ['name', 'hash_type', 'entry_count', 'source', 'created_at']
    search_fields = ['name', 'description']


@admin.register(Artifact)
class ArtifactAdmin(admin.ModelAdmin):
    list_display = ['artifact_type', 'name', 'path', 'timestamp']
    list_filter = ['artifact_type']
    search_fields = ['name', 'value', 'path']


@admin.register(NetworkConnection)
class NetworkConnectionAdmin(admin.ModelAdmin):
    list_display = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'state']
    list_filter = ['protocol']
    search_fields = ['src_ip', 'dst_ip', 'process_name']


@admin.register(ProcessInfo)
class ProcessInfoAdmin(admin.ModelAdmin):
    list_display = ['pid', 'name', 'username', 'is_hidden', 'is_injected', 'start_time']
    list_filter = ['is_hidden', 'is_injected']
    search_fields = ['name', 'path', 'command_line', 'username']
