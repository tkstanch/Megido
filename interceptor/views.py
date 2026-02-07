from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import InterceptedRequest, InterceptorSettings
from proxy.models import ProxyRequest


@api_view(['GET'])
def list_intercepted(request):
    """List all intercepted requests"""
    intercepted = InterceptedRequest.objects.filter(status='pending')[:50]
    data = [{
        'id': req.id,
        'original_method': req.original_method,
        'original_url': req.original_url,
        'status': req.status,
        'timestamp': req.timestamp.isoformat(),
    } for req in intercepted]
    return Response(data)


@api_view(['GET', 'PUT'])
def intercepted_detail(request, request_id):
    """Get or update an intercepted request"""
    try:
        intercepted = InterceptedRequest.objects.get(id=request_id)
        
        if request.method == 'GET':
            data = {
                'id': intercepted.id,
                'original_method': intercepted.original_method,
                'original_url': intercepted.original_url,
                'original_headers': intercepted.original_headers,
                'original_body': intercepted.original_body,
                'modified_method': intercepted.modified_method,
                'modified_url': intercepted.modified_url,
                'modified_headers': intercepted.modified_headers,
                'modified_body': intercepted.modified_body,
                'status': intercepted.status,
            }
            return Response(data)
        
        elif request.method == 'PUT':
            # Update intercepted request
            intercepted.modified_method = request.data.get('method', intercepted.original_method)
            intercepted.modified_url = request.data.get('url', intercepted.original_url)
            intercepted.modified_headers = request.data.get('headers', intercepted.original_headers)
            intercepted.modified_body = request.data.get('body', intercepted.original_body)
            intercepted.status = request.data.get('status', 'modified')
            intercepted.save()
            return Response({'message': 'Request updated successfully'})
            
    except InterceptedRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)


def interceptor_dashboard(request):
    """Dashboard view for the interceptor"""
    settings = InterceptorSettings.get_settings()
    return render(request, 'interceptor/dashboard.html', {
        'interceptor_enabled': settings.is_enabled
    })


@api_view(['GET', 'POST'])
def interceptor_status(request):
    """Get or set interceptor status"""
    settings = InterceptorSettings.get_settings()
    
    if request.method == 'GET':
        return Response({
            'is_enabled': settings.is_enabled,
            'updated_at': settings.updated_at.isoformat()
        })
    
    elif request.method == 'POST':
        is_enabled = request.data.get('is_enabled', settings.is_enabled)
        
        # Validate boolean type
        if not isinstance(is_enabled, bool):
            return Response({
                'error': 'is_enabled must be a boolean value'
            }, status=400)
        
        settings.is_enabled = is_enabled
        settings.save()
        return Response({
            'success': True,
            'is_enabled': settings.is_enabled,
            'message': f"Interceptor {'enabled' if settings.is_enabled else 'disabled'}"
        })
