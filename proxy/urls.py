from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'proxy'

urlpatterns = [
    # Dashboard
    path('', views.proxy_dashboard, name='dashboard'),
    
    # Request endpoints
    path('api/requests/', views.list_requests, name='list_requests'),
    path('api/requests/<int:request_id>/', views.get_request_detail, name='request_detail'),
    path('api/requests/<int:request_id>/replay/', views.replay_request, name='replay_request'),
    
    # Response endpoints
    path('api/responses/', views.create_response, name='create_response'),
    
    # WebSocket endpoints
    path('api/websocket-messages/', views.create_websocket_message, name='create_websocket_message'),
    path('api/websocket-messages/list/', views.list_websocket_messages, name='list_websocket_messages'),
    
    # Error endpoints
    path('api/errors/', views.create_error, name='create_error'),
    path('api/errors/list/', views.list_errors, name='list_errors'),
    
    # Authentication endpoints
    path('api/auth-attempt/', views.create_auth_attempt, name='create_auth_attempt'),
    
    # Statistics
    path('api/stats/', views.proxy_stats, name='proxy_stats'),
    
    # Browser integration
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
