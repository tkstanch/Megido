from django.urls import path
from . import views

app_name = 'browser'

urlpatterns = [
    path('', views.browser_view, name='browser'),
    path('api/sessions/', views.list_sessions, name='list_sessions'),
    path('api/history/', views.add_history, name='add_history'),
    path('api/history/<int:session_id>/', views.get_history, name='get_history'),
    path('api/interaction/', views.log_app_interaction, name='log_app_interaction'),
    path('api/enabled-apps/', views.get_enabled_apps, name='get_enabled_apps'),
    path('api/interceptor-status/', views.browser_interceptor_status, name='browser_interceptor_status'),
    path('api/launch-cef/', views.launch_cef_browser, name='launch_cef'),
]
