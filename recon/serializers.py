"""
DRF serializers for the Recon app.
"""
from rest_framework import serializers

from .models import (
    ReconProject,
    ScopeTarget,
    WhoisResult,
    IPDiscovery,
    CertificateDiscovery,
    SubdomainResult,
    ServicePort,
    DirectoryFinding,
    BucketFinding,
    GitHubFinding,
    TechFingerprint,
    ReconTask,
)


class ReconProjectSerializer(serializers.ModelSerializer):
    """Serializer for ReconProject."""

    class Meta:
        model = ReconProject
        fields = [
            'id', 'name', 'description', 'created_at', 'updated_at',
            'user', 'is_active',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScopeTargetSerializer(serializers.ModelSerializer):
    """Serializer for ScopeTarget."""

    class Meta:
        model = ScopeTarget
        fields = [
            'id', 'project', 'target', 'target_type', 'is_in_scope',
            'notes', 'added_at',
        ]
        read_only_fields = ['id', 'added_at']


class WhoisResultSerializer(serializers.ModelSerializer):
    """Serializer for WhoisResult."""

    class Meta:
        model = WhoisResult
        fields = [
            'id', 'project', 'domain', 'raw_data', 'registrar',
            'registrant_name', 'registrant_email', 'registrant_org',
            'registrant_phone', 'registrant_address', 'creation_date',
            'expiration_date', 'name_servers', 'status', 'queried_at',
        ]
        read_only_fields = ['id', 'queried_at']


class IPDiscoverySerializer(serializers.ModelSerializer):
    """Serializer for IPDiscovery."""

    class Meta:
        model = IPDiscovery
        fields = [
            'id', 'project', 'domain', 'ip_address', 'reverse_domains',
            'asn_number', 'asn_org', 'asn_country', 'ip_range',
            'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class CertificateDiscoverySerializer(serializers.ModelSerializer):
    """Serializer for CertificateDiscovery."""

    class Meta:
        model = CertificateDiscovery
        fields = [
            'id', 'project', 'domain', 'issuer', 'subject', 'not_before',
            'not_after', 'san_domains', 'source', 'cert_id', 'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class SubdomainResultSerializer(serializers.ModelSerializer):
    """Serializer for SubdomainResult."""

    class Meta:
        model = SubdomainResult
        fields = [
            'id', 'project', 'subdomain', 'ip_address', 'status_code',
            'is_alive', 'source', 'title', 'technologies', 'discovered_at',
            'last_checked',
        ]
        read_only_fields = ['id', 'discovered_at']


class ServicePortSerializer(serializers.ModelSerializer):
    """Serializer for ServicePort."""

    class Meta:
        model = ServicePort
        fields = [
            'id', 'project', 'host', 'ip_address', 'port', 'protocol',
            'service_name', 'service_version', 'banner', 'is_open', 'source',
            'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class DirectoryFindingSerializer(serializers.ModelSerializer):
    """Serializer for DirectoryFinding."""

    class Meta:
        model = DirectoryFinding
        fields = [
            'id', 'project', 'target_url', 'path', 'full_url', 'status_code',
            'content_length', 'content_type', 'redirect_url', 'is_interesting',
            'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class BucketFindingSerializer(serializers.ModelSerializer):
    """Serializer for BucketFinding."""

    class Meta:
        model = BucketFinding
        fields = [
            'id', 'project', 'bucket_name', 'bucket_url', 'provider',
            'is_public', 'is_listable', 'is_writable', 'keywords',
            'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class GitHubFindingSerializer(serializers.ModelSerializer):
    """Serializer for GitHubFinding."""

    class Meta:
        model = GitHubFinding
        fields = [
            'id', 'project', 'finding_type', 'repository', 'file_path',
            'content', 'url', 'severity', 'is_verified', 'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class TechFingerprintSerializer(serializers.ModelSerializer):
    """Serializer for TechFingerprint."""

    class Meta:
        model = TechFingerprint
        fields = [
            'id', 'project', 'target_url', 'technology', 'version',
            'category', 'evidence', 'cve_count', 'confidence', 'discovered_at',
        ]
        read_only_fields = ['id', 'discovered_at']


class ReconTaskSerializer(serializers.ModelSerializer):
    """Serializer for ReconTask."""

    class Meta:
        model = ReconTask
        fields = [
            'id', 'project', 'task_type', 'status', 'target',
            'celery_task_id', 'progress', 'result_summary', 'error_message',
            'created_at', 'started_at', 'completed_at',
        ]
        read_only_fields = ['id', 'created_at', 'started_at', 'completed_at']
