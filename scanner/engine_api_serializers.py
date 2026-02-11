"""
Engine API Serializers

Django REST Framework serializers for the engine API.
"""

from rest_framework import serializers
from scanner.models import EngineScan, EngineExecution, EngineFinding


class EngineScanSerializer(serializers.ModelSerializer):
    """Serializer for EngineScan model"""
    
    class Meta:
        model = EngineScan
        fields = [
            'id', 'target_path', 'target_type', 'status',
            'started_at', 'completed_at', 'execution_time',
            'enabled_engines', 'engine_categories',
            'parallel_execution', 'max_workers',
            'total_engines_run', 'successful_engines', 'failed_engines',
            'total_findings', 'findings_by_severity',
            'created_by', 'config_snapshot'
        ]
        read_only_fields = [
            'id', 'started_at', 'completed_at', 'execution_time',
            'total_engines_run', 'successful_engines', 'failed_engines',
            'total_findings', 'findings_by_severity'
        ]


class EngineExecutionSerializer(serializers.ModelSerializer):
    """Serializer for EngineExecution model"""
    
    class Meta:
        model = EngineExecution
        fields = [
            'id', 'engine_scan', 'engine_id', 'engine_name',
            'engine_category', 'status', 'started_at', 'completed_at',
            'execution_time', 'findings_count', 'error_message',
            'engine_config'
        ]
        read_only_fields = [
            'id', 'started_at', 'completed_at', 'execution_time',
            'findings_count'
        ]


class EngineFindingSerializer(serializers.ModelSerializer):
    """Serializer for EngineFinding model"""
    
    class Meta:
        model = EngineFinding
        fields = [
            'id', 'engine_scan', 'engine_execution', 'engine_id',
            'engine_name', 'title', 'description', 'severity',
            'confidence', 'file_path', 'line_number', 'url',
            'category', 'cwe_id', 'cve_id', 'owasp_category',
            'evidence', 'remediation', 'references', 'discovered_at',
            'finding_hash', 'is_duplicate', 'duplicate_of',
            'reviewed', 'status', 'raw_output'
        ]
        read_only_fields = [
            'id', 'discovered_at', 'finding_hash', 'is_duplicate',
            'duplicate_of'
        ]


class CreateScanSerializer(serializers.Serializer):
    """Serializer for creating a new scan"""
    
    target_path = serializers.CharField(max_length=2048, required=True)
    target_type = serializers.ChoiceField(
        choices=['path', 'url', 'git'],
        default='path'
    )
    engine_ids = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )
    categories = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )
    parallel = serializers.BooleanField(default=True)
    max_workers = serializers.IntegerField(default=4, min_value=1, max_value=16)
    execute_immediately = serializers.BooleanField(default=False)


class ScanSummarySerializer(serializers.Serializer):
    """Serializer for scan summary"""
    
    id = serializers.IntegerField()
    target_path = serializers.CharField()
    target_type = serializers.CharField()
    status = serializers.CharField()
    started_at = serializers.DateTimeField()
    completed_at = serializers.DateTimeField(allow_null=True)
    execution_time = serializers.FloatField()
    total_engines_run = serializers.IntegerField()
    successful_engines = serializers.IntegerField()
    failed_engines = serializers.IntegerField()
    total_findings = serializers.IntegerField()
    findings_by_severity = serializers.DictField()
    enabled_engines = serializers.ListField()
