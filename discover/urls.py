from django.urls import path, include
from . import views
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
    
    # REST API routes
    path('api/v1/', include('discover.api_urls')),
]
