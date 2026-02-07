from rest_framework import serializers
from .models import InterceptedRequest, InterceptedResponse, PayloadRule


class InterceptedRequestSerializer(serializers.ModelSerializer):
    """Serializer for intercepted requests"""
    
    class Meta:
        model = InterceptedRequest
        fields = ['id', 'url', 'method', 'headers', 'body', 'timestamp', 'user', 'source_app']
        read_only_fields = ['id', 'timestamp']


class InterceptedResponseSerializer(serializers.ModelSerializer):
    """Serializer for intercepted responses"""
    request = InterceptedRequestSerializer(read_only=True)
    request_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = InterceptedResponse
        fields = ['id', 'request', 'request_id', 'status_code', 'headers', 'body', 'response_time']
        read_only_fields = ['id']


class PayloadRuleSerializer(serializers.ModelSerializer):
    """Serializer for payload rules"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = PayloadRule
        fields = [
            'id', 'name', 'target_url_pattern', 'injection_type', 
            'injection_point', 'payload_content', 'active', 
            'created_by', 'created_by_username', 'target_apps',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class PayloadRuleCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating payload rules"""
    
    class Meta:
        model = PayloadRule
        fields = [
            'name', 'target_url_pattern', 'injection_type', 
            'injection_point', 'payload_content', 'active', 'target_apps'
        ]
