"""
Health Check Views for Network Monitoring

Provides API endpoints and UI for monitoring network health and service availability.
"""

from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from scanner.utils.health_check import get_health_checker
import logging

logger = logging.getLogger(__name__)


@api_view(['GET'])
def health_check_api(request):
    """
    API endpoint for network health check.
    
    Returns:
        JSON response with health status of all services
    
    Example response:
    {
        "overall_status": "healthy",
        "message": "All services are operational",
        "last_check": "2024-01-15T10:30:00",
        "stats": {
            "total_services": 2,
            "healthy": 2,
            "degraded": 0,
            "unhealthy": 0,
            "avg_response_time_ms": 125.5
        },
        "services": {
            "fireblocks_api": {
                "status": "healthy",
                "response_time_ms": 120.3,
                "last_check": "2024-01-15T10:30:00",
                "error_message": null,
                "consecutive_failures": 0
            }
        }
    }
    """
    try:
        health_checker = get_health_checker()
        
        # Perform health check if requested
        if request.GET.get('refresh', 'false').lower() == 'true':
            health_checker.check_all_services()
        
        health_data = health_checker.get_overall_health()
        
        return Response(health_data)
    
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return Response({
            'overall_status': 'error',
            'message': f'Health check failed: {str(e)}',
            'services': {}
        }, status=500)


@api_view(['POST'])
def check_service_health(request):
    """
    API endpoint to check health of a specific service.
    
    Request body:
    {
        "service_name": "fireblocks_api",
        "endpoint": "https://sb-console-api.fireblocks.io/health",
        "method": "GET"
    }
    
    Returns:
        JSON response with service health status
    """
    try:
        service_name = request.data.get('service_name')
        endpoint = request.data.get('endpoint')
        method = request.data.get('method', 'GET')
        
        if not service_name or not endpoint:
            return Response({
                'error': 'service_name and endpoint are required'
            }, status=400)
        
        health_checker = get_health_checker()
        status = health_checker.check_service_health(
            service_name=service_name,
            endpoint=endpoint,
            method=method
        )
        
        return Response({
            'service_name': status.service_name,
            'status': status.status,
            'response_time_ms': round(status.response_time_ms, 2) if status.response_time_ms else None,
            'last_check': status.last_check.isoformat(),
            'error_message': status.error_message,
            'error_type': status.error_type,
            'consecutive_failures': status.consecutive_failures
        })
    
    except Exception as e:
        logger.error(f"Service health check failed: {e}", exc_info=True)
        return Response({
            'error': str(e)
        }, status=500)


def health_dashboard(request):
    """
    Render health monitoring dashboard.
    
    Shows:
    - Overall system health
    - Individual service status
    - Response times
    - Error details
    """
    try:
        health_checker = get_health_checker()
        health_data = health_checker.get_overall_health()
        
        context = {
            'health_data': health_data,
            'page_title': 'Network Health Monitor'
        }
        
        return render(request, 'scanner/health_dashboard.html', context)
    
    except Exception as e:
        logger.error(f"Health dashboard failed: {e}", exc_info=True)
        context = {
            'error': str(e),
            'page_title': 'Network Health Monitor'
        }
        return render(request, 'scanner/health_dashboard.html', context)
