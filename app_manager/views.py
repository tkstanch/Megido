from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import AppConfiguration, AppStateChange, AppSettings
import json
import logging

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def dashboard(request):
    """Main dashboard view for app management"""
    apps = AppConfiguration.objects.all()
    logger.info(f"Dashboard: Loading {apps.count()} apps for user {request.user}")
    
    return render(request, 'app_manager/dashboard.html', {'apps': apps})


@api_view(['GET'])
def list_apps(request):
    """API endpoint to list all apps"""
    apps = AppConfiguration.objects.all()
    data = [{
        'id': app.id,
        'app_name': app.app_name,
        'display_name': app.display_name,
        'description': app.description,
        'is_enabled': app.is_enabled,
        'icon': app.icon,
        'category': app.category,
        'capabilities': app.get_capabilities_list(),
    } for app in apps]
    return Response(data)


@api_view(['POST'])
def toggle_app(request, app_id):
    """API endpoint to toggle app enabled/disabled state"""
    try:
        app = AppConfiguration.objects.get(id=app_id)
        previous_state = app.is_enabled
        app.is_enabled = not app.is_enabled
        app.save()
        
        logger.info(f"App '{app.app_name}' toggled from {previous_state} to {app.is_enabled} by {request.user}")
        
        # Log the state change
        user = request.user if request.user.is_authenticated else None
        AppStateChange.objects.create(
            app_config=app,
            user=user,
            previous_state=previous_state,
            new_state=app.is_enabled,
            ip_address=get_client_ip(request)
        )
        
        return Response({
            'success': True,
            'app_name': app.app_name,
            'is_enabled': app.is_enabled
        })
    except AppConfiguration.DoesNotExist:
        logger.error(f"Attempted to toggle non-existent app with ID: {app_id}")
        return Response({'success': False, 'error': 'App not found'}, status=404)
    except Exception as e:
        logger.error(f"Error toggling app {app_id}: {str(e)}")
        return Response({'success': False, 'error': str(e)}, status=500)


@api_view(['GET'])
def app_detail(request, app_id):
    """API endpoint to get app details"""
    try:
        app = AppConfiguration.objects.get(id=app_id)
        data = {
            'id': app.id,
            'app_name': app.app_name,
            'display_name': app.display_name,
            'description': app.description,
            'is_enabled': app.is_enabled,
            'icon': app.icon,
            'category': app.category,
            'capabilities': app.get_capabilities_list(),
            'created_at': app.created_at.isoformat(),
            'updated_at': app.updated_at.isoformat(),
        }
        return Response(data)
    except AppConfiguration.DoesNotExist:
        return Response({'error': 'App not found'}, status=404)


@api_view(['GET'])
def app_state_history(request, app_id):
    """API endpoint to get app state change history"""
    try:
        app = AppConfiguration.objects.get(id=app_id)
        changes = app.state_changes.all()[:50]
        data = [{
            'user': change.user.username if change.user else 'Anonymous',
            'previous_state': change.previous_state,
            'new_state': change.new_state,
            'timestamp': change.timestamp.isoformat(),
            'ip_address': change.ip_address,
        } for change in changes]
        return Response(data)
    except AppConfiguration.DoesNotExist:
        return Response({'error': 'App not found'}, status=404)
