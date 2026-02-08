"""
URL configuration for the Decompiler app.

This module defines URL patterns for all decompiler endpoints.
"""
from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'decompiler'

urlpatterns = [
    # Home and dashboard
    path('', views.decompiler_home, name='home'),
    
    # Extension package management
    path('packages/', views.list_extension_packages, name='list_packages'),
    path('packages/upload/', views.upload_extension_package, name='upload_package'),
    path('packages/<uuid:package_id>/', views.get_extension_package, name='get_package'),
    path('packages/<uuid:package_id>/bytecode/', views.download_extension_bytecode, name='download_bytecode'),
    
    # Decompilation workflow
    path('jobs/start/', views.start_decompilation_job, name='start_job'),
    path('jobs/<uuid:job_id>/status/', views.get_decompilation_job_status, name='job_status'),
    path('jobs/<uuid:job_id>/source/', views.download_decompiled_source, name='download_source'),
    path('jobs/<uuid:job_id>/view/', views.view_decompiled_source, name='view_source'),
    
    # Analysis and recompilation
    path('analyze/', views.analyze_decompiled_code, name='analyze_code'),
    path('analysis/<uuid:analysis_id>/', views.get_analysis_results, name='analysis_results'),
    path('recompile/', views.recompile_and_execute, name='recompile'),
    
    # JavaScript manipulation
    path('hooks/inject/', views.inject_javascript_hook, name='inject_hook'),
    path('hooks/', views.list_javascript_hooks, name='list_hooks'),
    
    # Obfuscation detection and defeat
    path('obfuscation/techniques/', views.list_obfuscation_techniques, name='list_techniques'),
    path('obfuscation/detect/', views.detect_obfuscation, name='detect_obfuscation'),
    path('obfuscation/deobfuscate/', views.deobfuscate_code, name='deobfuscate'),
    
    # Traffic interception
    path('traffic/', views.list_intercepted_traffic, name='list_traffic'),
    path('traffic/capture/', views.capture_traffic, name='capture_traffic'),
    path('traffic/<uuid:interception_id>/', views.view_traffic_details, name='traffic_details'),
    path('traffic/replay/', views.replay_traffic, name='replay_traffic'),
    
    # Target web app interaction
    path('interact/', views.interact_with_webapp, name='interact_webapp'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
