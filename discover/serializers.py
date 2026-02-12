"""
Serializers for the Discover app REST API.
"""
from rest_framework import serializers
from .models import Scan, SensitiveFinding
import json


class SensitiveFindingSerializer(serializers.ModelSerializer):
    """Serializer for SensitiveFinding model"""
    
    class Meta:
        model = SensitiveFinding
        fields = [
            'id', 'url', 'finding_type', 'value', 'context', 
            'severity', 'position', 'discovered_at', 'verified', 
            'false_positive', 'notes'
        ]
        read_only_fields = ['id', 'discovered_at']


class SensitiveFindingListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing findings"""
    
    class Meta:
        model = SensitiveFinding
        fields = ['id', 'finding_type', 'severity', 'url', 'discovered_at', 'verified']


class ScanSerializer(serializers.ModelSerializer):
    """Serializer for Scan model with all details"""
    sensitive_findings = SensitiveFindingListSerializer(many=True, read_only=True)
    wayback_urls_parsed = serializers.SerializerMethodField()
    shodan_data_parsed = serializers.SerializerMethodField()
    hunter_data_parsed = serializers.SerializerMethodField()
    dork_queries_parsed = serializers.SerializerMethodField()
    dork_results_parsed = serializers.SerializerMethodField()
    findings_by_severity = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'target', 'scan_date', 
            'wayback_urls', 'wayback_urls_parsed',
            'shodan_data', 'shodan_data_parsed',
            'hunter_data', 'hunter_data_parsed',
            'dork_queries', 'dork_queries_parsed',
            'dork_results', 'dork_results_parsed',
            'total_urls', 'total_emails',
            'sensitive_scan_completed', 'sensitive_scan_date',
            'total_findings', 'high_risk_findings',
            'sensitive_findings', 'findings_by_severity'
        ]
        read_only_fields = [
            'id', 'scan_date', 'sensitive_scan_completed', 
            'sensitive_scan_date', 'total_findings', 'high_risk_findings'
        ]
    
    def get_wayback_urls_parsed(self, obj):
        """Parse JSON wayback_urls field"""
        try:
            return json.loads(obj.wayback_urls) if obj.wayback_urls else []
        except json.JSONDecodeError:
            return []
    
    def get_shodan_data_parsed(self, obj):
        """Parse JSON shodan_data field"""
        try:
            return json.loads(obj.shodan_data) if obj.shodan_data else {}
        except json.JSONDecodeError:
            return {}
    
    def get_hunter_data_parsed(self, obj):
        """Parse JSON hunter_data field"""
        try:
            return json.loads(obj.hunter_data) if obj.hunter_data else []
        except json.JSONDecodeError:
            return []
    
    def get_dork_queries_parsed(self, obj):
        """Parse JSON dork_queries field"""
        try:
            return json.loads(obj.dork_queries) if obj.dork_queries else {}
        except json.JSONDecodeError:
            return {}
    
    def get_dork_results_parsed(self, obj):
        """Parse JSON dork_results field"""
        try:
            return json.loads(obj.dork_results) if obj.dork_results else {}
        except json.JSONDecodeError:
            return {}
    
    def get_findings_by_severity(self, obj):
        """Get count of findings by severity"""
        from django.db.models import Count, Q
        severity_counts = obj.sensitive_findings.aggregate(
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low')),
            info=Count('id', filter=Q(severity='info')),
        )
        return severity_counts


class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing scans"""
    findings_count = serializers.IntegerField(source='total_findings', read_only=True)
    
    class Meta:
        model = Scan
        fields = [
            'id', 'target', 'scan_date', 
            'total_urls', 'total_emails',
            'sensitive_scan_completed', 'findings_count', 'high_risk_findings'
        ]


class ScanCreateSerializer(serializers.Serializer):
    """Serializer for creating a new scan"""
    target = serializers.CharField(max_length=500, required=True)
    enable_sensitive_scan = serializers.BooleanField(default=True)
    enable_dork_search = serializers.BooleanField(default=False)


class ScanStatusSerializer(serializers.Serializer):
    """Serializer for scan status response"""
    scan_id = serializers.IntegerField()
    target = serializers.CharField()
    scan_completed = serializers.BooleanField()
    sensitive_scan_completed = serializers.BooleanField()
    total_findings = serializers.IntegerField()
    high_risk_findings = serializers.IntegerField()
    scan_date = serializers.DateTimeField()
