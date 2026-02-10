from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'scanner'

urlpatterns = [
    path('', views.scanner_dashboard, name='dashboard'),
    path('api/targets/', views.scan_targets, name='scan_targets'),
    path('api/targets/<int:target_id>/scan/', views.start_scan, name='start_scan'),
    path('api/scans/<int:scan_id>/results/', views.scan_results, name='scan_results'),
    path('api/scans/<int:scan_id>/exploit/', views.exploit_vulnerabilities, name='exploit_vulnerabilities'),
    path('api/scans/<int:scan_id>/apply_advanced_features/', views.apply_advanced_features, name='apply_advanced_features'),
    path('api/exploit_status/<str:task_id>/', views.exploit_status, name='exploit_status'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
