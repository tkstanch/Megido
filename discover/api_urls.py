"""
API URL patterns for the Discover app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import api_views

# Create router for ViewSets
router = DefaultRouter()
router.register(r'scans', api_views.ScanViewSet, basename='scan')
router.register(r'findings', api_views.SensitiveFindingViewSet, basename='finding')

app_name = 'discover_api'

urlpatterns = [
    # Health check
    path('health/', api_views.api_health, name='health'),
    
    # ViewSet routes
    path('', include(router.urls)),
]
