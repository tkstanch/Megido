from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.scanner_dashboard, name='dashboard'),
    path('api/targets/', views.scan_targets, name='scan_targets'),
    path('api/targets/<int:target_id>/scan/', views.start_scan, name='start_scan'),
    path('api/scans/<int:scan_id>/results/', views.scan_results, name='scan_results'),
]
