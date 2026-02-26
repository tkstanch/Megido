from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'data_tracer'

urlpatterns = [
    # Existing URLs
    path('', views.data_tracer_home, name='home'),
    path('create/', views.create_scan, name='create_scan'),
    path('scans/', views.scan_list, name='scan_list'),
    path('scan/<uuid:scan_id>/', views.scan_detail, name='scan_detail'),
    path('scan/<uuid:scan_id>/execute/', views.execute_scan, name='execute_scan'),
    path('result/<uuid:result_id>/', views.result_detail, name='result_detail'),
    path('result/<uuid:result_id>/packets/', views.packet_analysis, name='packet_analysis'),
    path('stealth/', views.stealth_config, name='stealth_config'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),

    # New dashboard URLs
    path('vulnerabilities/', views.vulnerability_dashboard, name='vulnerability_dashboard'),
    path('result/<uuid:result_id>/topology/', views.network_topology, name='network_topology'),
    path('traffic/', views.traffic_analysis_dashboard, name='traffic_analysis'),
    path('threat-intel/', views.threat_intelligence_dashboard, name='threat_intelligence'),
    path('cloud/', views.cloud_security_dashboard, name='cloud_security'),
    path('api-security/', views.api_security_dashboard, name='api_security'),
    path('wireless/', views.wireless_networks_dashboard, name='wireless_networks'),
    path('credentials/', views.credential_scan_dashboard, name='credential_scan'),
    path('result/<uuid:result_id>/report/', views.generate_report, name='generate_report'),
    path('schedule/', views.scan_schedule_list, name='scan_schedule'),
    path('comparison/', views.scan_comparison, name='scan_comparison'),

    # REST API endpoints
    path('api/scans/', views.api_scan_list, name='api_scan_list'),
    path('api/scans/create/', views.api_create_scan, name='api_create_scan'),
    path('api/result/<uuid:result_id>/', views.api_scan_result, name='api_scan_result'),
    path('api/vulnerability-scan/', views.api_vulnerability_scan, name='api_vulnerability_scan'),
    path('api/threat-intel/', views.api_threat_intel_check, name='api_threat_intel_check'),
]
