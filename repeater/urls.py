from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'repeater'

urlpatterns = [
    # Dashboard
    path('', views.repeater_dashboard, name='dashboard'),

    # -------------------------------------------------------------------------
    # Existing endpoints (backward compatible)
    # -------------------------------------------------------------------------
    path('api/requests/', views.repeater_requests, name='repeater_requests'),
    path('api/requests/<int:request_id>/', views.repeater_request_detail, name='repeater_request_detail'),
    path('api/requests/<int:request_id>/send/', views.send_request, name='send_request'),
    path('api/scans/<int:scan_id>/requests/', views.scan_requests, name='scan_requests'),

    # -------------------------------------------------------------------------
    # Tabs
    # -------------------------------------------------------------------------
    path('api/tabs/', views.tab_list, name='tab_list'),
    path('api/tabs/<int:tab_id>/', views.tab_detail, name='tab_detail'),
    path('api/tabs/<int:tab_id>/history/', views.tab_history, name='tab_history'),
    path('api/tabs/<int:tab_id>/navigate/', views.tab_navigate, name='tab_navigate'),

    # -------------------------------------------------------------------------
    # Per-request extras
    # -------------------------------------------------------------------------
    path('api/requests/<int:request_id>/target-info/', views.target_info, name='target_info'),
    path('api/requests/<int:request_id>/send-to/<str:tool>/', views.send_to_tool, name='send_to_tool'),
    path('api/requests/<int:request_id>/inject/', views.inject_payloads, name='inject_payloads'),

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------
    path('api/compare/', views.compare_responses_view, name='compare_responses'),
    path('api/encode-decode/', views.encode_decode, name='encode_decode'),
    path('api/parse-raw/', views.parse_raw, name='parse_raw'),
    path('api/build-raw/', views.build_raw, name='build_raw'),
    path('api/hexdump/', views.hexdump_view, name='hexdump'),
    path('api/bypass-techniques/', views.bypass_techniques, name='bypass_techniques'),

    # -------------------------------------------------------------------------
    # Scanner → Repeater integration
    # -------------------------------------------------------------------------
    path('api/from-scanner/', views.from_scanner, name='from_scanner'),

    # Desktop browser launcher
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
