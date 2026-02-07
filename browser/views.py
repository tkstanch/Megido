from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import BrowserSession, BrowserHistory, BrowserAppInteraction, BrowserSettings
from app_manager.models import AppConfiguration
from interceptor.models import InterceptorSettings
import json
import subprocess
import sys
import os
from pathlib import Path


def browser_view(request):
    """Main browser interface view"""
    # Get or create browser session
    user = request.user if request.user.is_authenticated else None
    session = BrowserSession.objects.create(user=user, session_name='Browser Session')
    
    # Get all enabled apps for the toolbar
    enabled_apps = AppConfiguration.objects.filter(is_enabled=True)
    
    # Get interceptor status
    interceptor_settings = InterceptorSettings.get_settings()
    
    return render(request, 'browser/browser.html', {
        'session': session,
        'enabled_apps': enabled_apps,
        'interceptor_enabled': interceptor_settings.is_enabled
    })


@api_view(['GET'])
def list_sessions(request):
    """API endpoint to list browser sessions"""
    sessions = BrowserSession.objects.all()[:50]
    data = [{
        'id': session.id,
        'session_name': session.session_name,
        'user': session.user.username if session.user else 'Anonymous',
        'started_at': session.started_at.isoformat(),
        'ended_at': session.ended_at.isoformat() if session.ended_at else None,
        'is_active': session.is_active,
    } for session in sessions]
    return Response(data)


@api_view(['POST'])
def add_history(request):
    """API endpoint to add browser history entry"""
    session_id = request.data.get('session_id')
    url = request.data.get('url')
    title = request.data.get('title', '')
    
    try:
        session = BrowserSession.objects.get(id=session_id)
        history = BrowserHistory.objects.create(
            session=session,
            url=url,
            title=title
        )
        return Response({
            'success': True,
            'history_id': history.id
        })
    except BrowserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['GET'])
def get_history(request, session_id):
    """API endpoint to get browser history for a session"""
    try:
        session = BrowserSession.objects.get(id=session_id)
        history = session.history.all()[:100]
        data = [{
            'id': h.id,
            'url': h.url,
            'title': h.title,
            'visited_at': h.visited_at.isoformat(),
        } for h in history]
        return Response(data)
    except BrowserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['POST'])
def log_app_interaction(request):
    """API endpoint to log app interaction from browser"""
    session_id = request.data.get('session_id')
    app_name = request.data.get('app_name')
    action = request.data.get('action')
    target_url = request.data.get('target_url', '')
    result = request.data.get('result', '')
    
    try:
        session = BrowserSession.objects.get(id=session_id)
        interaction = BrowserAppInteraction.objects.create(
            session=session,
            app_name=app_name,
            action=action,
            target_url=target_url,
            result=result
        )
        return Response({
            'success': True,
            'interaction_id': interaction.id
        })
    except BrowserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['GET'])
def get_enabled_apps(request):
    """API endpoint to get all enabled apps"""
    apps = AppConfiguration.objects.filter(is_enabled=True)
    data = [{
        'app_name': app.app_name,
        'display_name': app.display_name,
        'icon': app.icon,
        'capabilities': app.get_capabilities_list(),
    } for app in apps]
    return Response(data)


@api_view(['GET', 'POST'])
def browser_interceptor_status(request):
    """API endpoint to get or toggle interceptor status from browser"""
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


@api_view(['POST'])
def launch_cef_browser(request):
    """API endpoint to launch CEF desktop browser"""
    # Check if CEF is installed first
    try:
        import cefpython3
    except (ImportError, Exception) as e:
        # Handle both ImportError and the Python version exception that cefpython3 raises
        error_msg = str(e)
        if 'not installed' in error_msg.lower() or 'no module' in error_msg.lower():
            error_msg = 'CEF Python is not installed. Install with: pip install cefpython3'
        return Response({
            'success': False,
            'error': error_msg
        }, status=400)
    
    try:
        # Get Django URL from request or use default
        django_url = request.data.get('django_url', 'http://127.0.0.1:8000')
        
        # Validate django_url to prevent command injection
        # Only allow URLs starting with http:// or https://
        if not (django_url.startswith('http://') or django_url.startswith('https://')):
            return Response({
                'success': False,
                'error': 'Invalid Django URL. Must start with http:// or https://'
            }, status=400)
        
        # Path to desktop launcher
        base_dir = Path(__file__).parent.parent
        launcher_path = base_dir / 'browser' / 'desktop_launcher.py'
        
        if not launcher_path.exists():
            return Response({
                'success': False,
                'error': 'Desktop launcher not found'
            }, status=500)
        
        # Launch CEF browser in background (browser-only mode)
        subprocess.Popen(
            [sys.executable, str(launcher_path), '--mode', 'browser-only', '--django-url', django_url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True  # Detach from parent process
        )
        
        return Response({
            'success': True,
            'message': 'CEF browser launched successfully'
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=500)
