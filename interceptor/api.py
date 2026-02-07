"""
API endpoints for interceptor integration with mitmproxy
"""
from django.utils import timezone
from django.db import models
from rest_framework import status, generics, filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.models import User
from .models import InterceptedRequest, InterceptedResponse, PayloadRule
from .serializers import (
    InterceptedRequestSerializer, 
    InterceptedResponseSerializer, 
    PayloadRuleSerializer,
    PayloadRuleCreateSerializer
)


@api_view(['POST'])
@permission_classes([AllowAny])  # mitmproxy addon needs access
def receive_request(request):
    """
    Receive intercepted requests from mitmproxy
    POST /api/interceptor/request/
    """
    try:
        data = request.data
        
        # Create intercepted request
        intercepted_request = InterceptedRequest.objects.create(
            url=data.get('url'),
            method=data.get('method', 'GET'),
            headers=data.get('headers', {}),
            body=data.get('body', ''),
            source_app=data.get('source_app', ''),
            user=None  # Can link to user if auth token is provided
        )
        
        serializer = InterceptedRequestSerializer(intercepted_request)
        return Response({
            'success': True,
            'request_id': intercepted_request.id,
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])  # mitmproxy addon needs access
def receive_response(request):
    """
    Receive intercepted responses from mitmproxy
    POST /api/interceptor/response/
    """
    try:
        data = request.data
        request_id = data.get('request_id')
        
        if not request_id:
            return Response({
                'success': False,
                'error': 'request_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get the associated request
        try:
            intercepted_request = InterceptedRequest.objects.get(id=request_id)
        except InterceptedRequest.DoesNotExist:
            return Response({
                'success': False,
                'error': f'Request with id {request_id} not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Create intercepted response
        intercepted_response = InterceptedResponse.objects.create(
            request=intercepted_request,
            status_code=data.get('status_code', 0),
            headers=data.get('headers', {}),
            body=data.get('body', ''),
            response_time=data.get('response_time', 0.0)
        )
        
        serializer = InterceptedResponseSerializer(intercepted_response)
        return Response({
            'success': True,
            'response_id': intercepted_response.id,
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])  # mitmproxy addon needs access
def get_active_payload_rules(request):
    """
    Get active payload rules for mitmproxy addon
    GET /api/interceptor/payload-rules/active/
    """
    try:
        source_app = request.query_params.get('source_app', None)
        
        # Get active rules
        rules = PayloadRule.objects.filter(active=True)
        
        # Filter by source_app if provided
        if source_app:
            # Check if source_app is in the target_apps JSONField list
            # Empty target_apps list means applies to all apps
            rules = rules.filter(
                models.Q(target_apps__contains=source_app) |
                models.Q(target_apps=[])  # Empty list means applies to all
            )
        
        serializer = PayloadRuleSerializer(rules, many=True)
        return Response({
            'success': True,
            'count': len(serializer.data),
            'rules': serializer.data
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


class PayloadRuleListCreateView(generics.ListCreateAPIView):
    """
    List and create payload rules
    GET/POST /api/interceptor/payload-rules/
    """
    queryset = PayloadRule.objects.all()
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'target_url_pattern']
    ordering_fields = ['created_at', 'name']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return PayloadRuleCreateSerializer
        return PayloadRuleSerializer
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class PayloadRuleDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a payload rule
    GET/PUT/PATCH/DELETE /api/interceptor/payload-rules/<id>/
    """
    queryset = PayloadRule.objects.all()
    serializer_class = PayloadRuleSerializer
    permission_classes = [IsAuthenticated]


class InterceptHistoryView(generics.ListAPIView):
    """
    Get intercept history with filtering
    GET /api/interceptor/history/
    """
    serializer_class = InterceptedRequestSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['url', 'method', 'body']
    ordering_fields = ['timestamp', 'method']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        queryset = InterceptedRequest.objects.all()
        
        # Filter by source_app
        source_app = self.request.query_params.get('source_app', None)
        if source_app:
            queryset = queryset.filter(source_app=source_app)
        
        # Filter by method
        method = self.request.query_params.get('method', None)
        if method:
            queryset = queryset.filter(method=method.upper())
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date', None)
        end_date = self.request.query_params.get('end_date', None)
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)
        
        return queryset.select_related('user')


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def manual_inject(request):
    """
    Manually trigger payload injection
    POST /api/interceptor/inject/
    """
    try:
        data = request.data
        request_id = data.get('request_id')
        payload_rule_id = data.get('payload_rule_id')
        
        if not request_id or not payload_rule_id:
            return Response({
                'success': False,
                'error': 'request_id and payload_rule_id are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get the request and rule
        try:
            intercepted_request = InterceptedRequest.objects.get(id=request_id)
            payload_rule = PayloadRule.objects.get(id=payload_rule_id)
        except (InterceptedRequest.DoesNotExist, PayloadRule.DoesNotExist) as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Apply the payload (this would typically be done in mitmproxy)
        # For now, just return the modified request data
        modified_data = {
            'original_request': InterceptedRequestSerializer(intercepted_request).data,
            'rule_applied': PayloadRuleSerializer(payload_rule).data,
            'message': 'Payload injection simulated. Use mitmproxy for real-time injection.'
        }
        
        return Response({
            'success': True,
            'data': modified_data
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def request_detail(request, request_id):
    """
    Get detailed information about an intercepted request
    GET /api/interceptor/request/<id>/
    """
    try:
        intercepted_request = InterceptedRequest.objects.get(id=request_id)
        
        # Get response if it exists
        try:
            response = intercepted_request.response
            response_data = InterceptedResponseSerializer(response).data
        except InterceptedResponse.DoesNotExist:
            response_data = None
        
        return Response({
            'success': True,
            'request': InterceptedRequestSerializer(intercepted_request).data,
            'response': response_data
        })
        
    except InterceptedRequest.DoesNotExist:
        return Response({
            'success': False,
            'error': f'Request with id {request_id} not found'
        }, status=status.HTTP_404_NOT_FOUND)
