from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.db.models import Q, Count, Avg
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import (
    ProxyRequest, ProxyResponse, ProxyConfiguration,
    WebSocketMessage, ProxyError, AuthenticationAttempt
)
from .replay_utils import replay_from_database
from .logging_utils import ProxyLogger
import json


@api_view(['GET', 'POST'])
def list_requests(request):
    """List all proxy requests with filtering"""
    if request.method == 'POST':
        # Create new request (for logging from proxy addon)
        return create_request(request)
    
    # GET: List requests with filters
    queryset = ProxyRequest.objects.select_related('response').all()
    
    # Apply filters
    method = request.GET.get('method')
    protocol = request.GET.get('protocol')
    source_ip = request.GET.get('source_ip')
    is_replay = request.GET.get('is_replay')
    search = request.GET.get('search')
    
    if method:
        queryset = queryset.filter(method=method.upper())
    if protocol:
        queryset = queryset.filter(protocol=protocol.upper())
    if source_ip:
        queryset = queryset.filter(source_ip=source_ip)
    if is_replay is not None:
        queryset = queryset.filter(is_replay=is_replay.lower() == 'true')
    if search:
        queryset = queryset.filter(
            Q(url__icontains=search) | 
            Q(host__icontains=search) |
            Q(user_agent__icontains=search)
        )
    
    # Pagination
    limit = int(request.GET.get('limit', 100))
    offset = int(request.GET.get('offset', 0))
    
    total_count = queryset.count()
    requests_list = queryset[offset:offset + limit]
    
    data = [{
        'id': req.id,
        'method': req.method,
        'url': req.url,
        'host': req.host,
        'protocol': req.protocol,
        'source_ip': req.source_ip,
        'timestamp': req.timestamp.isoformat(),
        'request_size': req.request_size,
        'is_replay': req.is_replay,
        'status_code': req.response.status_code if hasattr(req, 'response') else None,
        'response_time': req.response.response_time if hasattr(req, 'response') else None,
    } for req in requests_list]
    
    return Response({
        'requests': data,
        'total': total_count,
        'limit': limit,
        'offset': offset
    })


def create_request(request):
    """Create a new proxy request (called by proxy addon)"""
    try:
        data = request.data
        
        # Create request
        proxy_request = ProxyRequest.objects.create(
            url=data['url'],
            method=data['method'],
            headers=data.get('headers', '{}'),
            body=data.get('body', ''),
            host=data['host'],
            port=data['port'],
            source_ip=data.get('source_ip'),
            protocol=data.get('protocol', 'HTTP'),
            request_size=data.get('request_size', 0),
            user_agent=data.get('user_agent', '')
        )
        
        # Log to file if enabled
        try:
            logger = ProxyLogger()
            logger.log_request({
                'id': proxy_request.id,
                'url': proxy_request.url,
                'method': proxy_request.method,
                'source_ip': proxy_request.source_ip,
                'protocol': proxy_request.protocol
            })
        except Exception as e:
            pass  # Don't fail request creation if logging fails
        
        return Response({'id': proxy_request.id}, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def create_response(request):
    """Create a new proxy response (called by proxy addon)"""
    try:
        data = request.data
        
        # Get the request
        proxy_request = ProxyRequest.objects.get(id=data['request'])
        
        # Create response
        proxy_response = ProxyResponse.objects.create(
            request=proxy_request,
            status_code=data['status_code'],
            headers=data.get('headers', '{}'),
            body=data.get('body', ''),
            response_time=data.get('response_time', 0),
            response_size=data.get('response_size', 0),
            cached=data.get('cached', False),
            error_message=data.get('error_message')
        )
        
        # Log to file if enabled
        try:
            logger = ProxyLogger()
            logger.log_response({
                'id': proxy_response.id,
                'request_id': proxy_request.id,
                'status_code': proxy_response.status_code,
                'response_time': proxy_response.response_time
            })
        except Exception as e:
            pass
        
        return Response({'id': proxy_response.id}, status=status.HTTP_201_CREATED)
        
    except ProxyRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_request_detail(request, request_id):
    """Get details of a specific request"""
    try:
        proxy_request = ProxyRequest.objects.get(id=request_id)
        data = {
            'id': proxy_request.id,
            'method': proxy_request.method,
            'url': proxy_request.url,
            'headers': proxy_request.headers,
            'body': proxy_request.body,
            'timestamp': proxy_request.timestamp.isoformat(),
            'host': proxy_request.host,
            'port': proxy_request.port,
            'source_ip': proxy_request.source_ip,
            'protocol': proxy_request.protocol,
            'request_size': proxy_request.request_size,
            'user_agent': proxy_request.user_agent,
            'is_replay': proxy_request.is_replay,
            'original_request_id': proxy_request.original_request.id if proxy_request.original_request else None,
        }
        if hasattr(proxy_request, 'response'):
            data['response'] = {
                'status_code': proxy_request.response.status_code,
                'headers': proxy_request.response.headers,
                'body': proxy_request.response.body,
                'response_time': proxy_request.response.response_time,
                'response_size': proxy_request.response.response_size,
                'cached': proxy_request.response.cached,
                'error_message': proxy_request.response.error_message,
            }
        return Response(data)
    except ProxyRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)


@api_view(['POST'])
def replay_request(request, request_id):
    """Replay a captured request"""
    target_url = request.data.get('target_url')
    
    try:
        result = replay_from_database(request_id, target_url)
        return Response(result)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
def list_websocket_messages(request):
    """List WebSocket messages with filtering"""
    queryset = WebSocketMessage.objects.all()
    
    # Apply filters
    connection_id = request.GET.get('connection_id')
    direction = request.GET.get('direction')
    message_type = request.GET.get('message_type')
    
    if connection_id:
        queryset = queryset.filter(connection_id=connection_id)
    if direction:
        queryset = queryset.filter(direction=direction.upper())
    if message_type:
        queryset = queryset.filter(message_type=message_type.upper())
    
    # Pagination
    limit = int(request.GET.get('limit', 100))
    messages = queryset[:limit]
    
    data = [{
        'id': msg.id,
        'connection_id': msg.connection_id,
        'url': msg.url,
        'direction': msg.direction,
        'message_type': msg.message_type,
        'payload': msg.payload[:200] + '...' if len(msg.payload) > 200 else msg.payload,
        'payload_size': msg.payload_size,
        'timestamp': msg.timestamp.isoformat(),
        'source_ip': msg.source_ip,
    } for msg in messages]
    
    return Response({
        'messages': data,
        'total': queryset.count(),
        'limit': limit
    })


@api_view(['POST'])
def create_websocket_message(request):
    """Create a new WebSocket message (called by proxy addon)"""
    try:
        data = request.data
        
        ws_message = WebSocketMessage.objects.create(
            connection_id=data['connection_id'],
            url=data['url'],
            direction=data['direction'],
            message_type=data['message_type'],
            payload=data['payload'],
            payload_size=data.get('payload_size', 0),
            source_ip=data.get('source_ip')
        )
        
        # Log to file
        try:
            logger = ProxyLogger()
            logger.log_websocket({
                'connection_id': ws_message.connection_id,
                'direction': ws_message.direction,
                'message_type': ws_message.message_type
            })
        except Exception as e:
            pass
        
        return Response({'id': ws_message.id}, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def list_errors(request):
    """List proxy errors"""
    queryset = ProxyError.objects.all()
    
    # Apply filters
    error_type = request.GET.get('error_type')
    source_ip = request.GET.get('source_ip')
    
    if error_type:
        queryset = queryset.filter(error_type=error_type)
    if source_ip:
        queryset = queryset.filter(source_ip=source_ip)
    
    # Pagination
    limit = int(request.GET.get('limit', 50))
    errors = queryset[:limit]
    
    data = [{
        'id': err.id,
        'error_type': err.error_type,
        'error_message': err.error_message,
        'url': err.url,
        'source_ip': err.source_ip,
        'timestamp': err.timestamp.isoformat(),
        'request_id': err.request.id if err.request else None,
    } for err in errors]
    
    return Response({
        'errors': data,
        'total': queryset.count(),
        'limit': limit
    })


@api_view(['POST'])
def create_error(request):
    """Create a new error log (called by proxy addon)"""
    try:
        data = request.data
        
        proxy_error = ProxyError.objects.create(
            error_type=data.get('error_type', 'OTHER'),
            error_message=data['error_message'],
            stack_trace=data.get('stack_trace'),
            url=data.get('url'),
            source_ip=data.get('source_ip')
        )
        
        # Log to file
        try:
            logger = ProxyLogger()
            logger.log_error({
                'error_type': proxy_error.error_type,
                'error_message': proxy_error.error_message
            })
        except Exception as e:
            pass
        
        return Response({'id': proxy_error.id}, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def create_auth_attempt(request):
    """Log an authentication attempt (called by proxy addon)"""
    try:
        data = request.data
        
        auth_attempt = AuthenticationAttempt.objects.create(
            username=data.get('username'),
            source_ip=data['source_ip'],
            success=data.get('success', False),
            failure_reason=data.get('failure_reason')
        )
        
        # Log to file
        try:
            logger = ProxyLogger()
            logger.log_auth_attempt({
                'source_ip': auth_attempt.source_ip,
                'success': auth_attempt.success
            })
        except Exception as e:
            pass
        
        return Response({'id': auth_attempt.id}, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def proxy_stats(request):
    """Get proxy statistics"""
    total_requests = ProxyRequest.objects.count()
    total_websocket_messages = WebSocketMessage.objects.count()
    total_errors = ProxyError.objects.count()
    
    # Request stats by method
    requests_by_method = ProxyRequest.objects.values('method').annotate(count=Count('id'))
    
    # Request stats by protocol
    requests_by_protocol = ProxyRequest.objects.values('protocol').annotate(count=Count('id'))
    
    # Average response time
    avg_response_time = ProxyResponse.objects.aggregate(avg=Avg('response_time'))
    
    # Recent auth failures
    recent_auth_failures = AuthenticationAttempt.objects.filter(
        success=False
    ).count()
    
    return Response({
        'total_requests': total_requests,
        'total_websocket_messages': total_websocket_messages,
        'total_errors': total_errors,
        'requests_by_method': list(requests_by_method),
        'requests_by_protocol': list(requests_by_protocol),
        'avg_response_time': avg_response_time['avg'],
        'recent_auth_failures': recent_auth_failures,
    })


def proxy_dashboard(request):
    """Dashboard view for the proxy"""
    return render(request, 'proxy/dashboard.html')
