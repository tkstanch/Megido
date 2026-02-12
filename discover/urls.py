from django.urls import path, include
from . import views
from . import dashboard_views
from browser.views import launch_pyqt_browser

app_name = 'discover'

urlpatterns = [
    # Web UI routes
    path('', views.discover_home, name='home'),
    path('scan/', views.start_scan, name='start_scan'),
    path('report/<int:scan_id>/', views.view_report, name='view_report'),
    path('history/', views.scan_history, name='history'),
    path('scan-status/<int:scan_id>/', views.scan_status, name='scan_status'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
    
    # Dashboard routes
    path('dashboard/', dashboard_views.user_dashboard, name='user_dashboard'),
    path('dashboard/admin/', dashboard_views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/analytics-api/', dashboard_views.analytics_api, name='analytics_api'),
    
    # REST API routes
    path('api/v1/', include('discover.api_urls')),
]
