from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .engine_api_views import (
    EngineViewSet,
    EngineScanViewSet,
    EngineExecutionViewSet,
    EngineFindingViewSet
)
from browser.views import launch_pyqt_browser

app_name = 'scanner'

# Create router for engine API
router = DefaultRouter()
router.register(r'engines', EngineViewSet, basename='engine')
router.register(r'engine-scans', EngineScanViewSet, basename='engine-scan')
router.register(r'engine-executions', EngineExecutionViewSet, basename='engine-execution')
router.register(r'engine-findings', EngineFindingViewSet, basename='engine-finding')

urlpatterns = [
    path('', views.scanner_dashboard, name='dashboard'),
    path('api/targets/', views.scan_targets, name='scan_targets'),
    path('api/targets/<int:target_id>/scan/', views.start_scan, name='start_scan'),
    path('api/scans/<int:scan_id>/results/', views.scan_results, name='scan_results'),
    path('api/scans/<int:scan_id>/exploit/', views.exploit_vulnerabilities, name='exploit_vulnerabilities'),
    path('api/scans/<int:scan_id>/apply_advanced_features/', views.apply_advanced_features, name='apply_advanced_features'),
    path('api/vulnerabilities/<int:vuln_id>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('api/exploit_status/<str:task_id>/', views.exploit_status, name='exploit_status'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
    
    # Engine API routes
    path('api/', include(router.urls)),
]
