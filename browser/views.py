from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import BrowserSession, BrowserHistory, BrowserAppInteraction, BrowserSettings
from app_manager.models import AppConfiguration
import json


def browser_view(request):
    """Main browser interface view"""
    # Get or create browser session
    user = request.user if request.user.is_authenticated else None
    session = BrowserSession.objects.create(user=user, session_name='Browser Session')
    
    # Get all enabled apps for the toolbar
    enabled_apps = AppConfiguration.objects.filter(is_enabled=True)
    
    return render(request, 'browser/browser.html', {
        'session': session,
        'enabled_apps': enabled_apps
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
