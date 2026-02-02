from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import ProxyRequest, ProxyResponse
import json


@api_view(['GET'])
def list_requests(request):
    """List all proxy requests"""
    requests = ProxyRequest.objects.all()[:100]
    data = [{
        'id': req.id,
        'method': req.method,
        'url': req.url,
        'host': req.host,
        'timestamp': req.timestamp.isoformat(),
        'status_code': req.response.status_code if hasattr(req, 'response') else None
    } for req in requests]
    return Response(data)


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
        }
        if hasattr(proxy_request, 'response'):
            data['response'] = {
                'status_code': proxy_request.response.status_code,
                'headers': proxy_request.response.headers,
                'body': proxy_request.response.body,
                'response_time': proxy_request.response.response_time,
            }
        return Response(data)
    except ProxyRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)


def proxy_dashboard(request):
    """Dashboard view for the proxy"""
    return render(request, 'proxy/dashboard.html')
