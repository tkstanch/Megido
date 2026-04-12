"""
URL configuration for the Recon app.
"""
from django.urls import path

from . import views
from .cancel_views import cancel_recon_task

app_name = 'recon'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    path('project/create/', views.create_project, name='create_project'),
    path('project/<int:project_id>/', views.project_detail, name='project_detail'),

    # WHOIS
    path('project/<int:project_id>/whois/', views.whois_results, name='whois_results'),
    path('project/<int:project_id>/whois/lookup/', views.whois_lookup, name='whois_lookup'),

    # Subdomains
    path('project/<int:project_id>/subdomains/', views.subdomain_results, name='subdomain_results'),
    path('project/<int:project_id>/subdomains/enum/', views.subdomain_enum, name='subdomain_enum'),

    # Services/Ports
    path('project/<int:project_id>/services/', views.service_results, name='service_results'),
    path('project/<int:project_id>/services/scan/', views.service_scan, name='service_scan'),

    # Directories
    path('project/<int:project_id>/directories/', views.directory_results, name='directory_results'),
    path('project/<int:project_id>/directories/bruteforce/', views.directory_bruteforce, name='directory_bruteforce'),

    # Buckets
    path('project/<int:project_id>/buckets/', views.bucket_results, name='bucket_results'),
    path('project/<int:project_id>/buckets/discover/', views.bucket_discovery, name='bucket_discovery'),

    # GitHub Recon
    path('project/<int:project_id>/github/', views.github_results, name='github_results'),
    path('project/<int:project_id>/github/scan/', views.github_recon, name='github_recon'),

    # Fingerprinting
    path('project/<int:project_id>/fingerprint/', views.fingerprint_results, name='fingerprint_results'),
    path('project/<int:project_id>/fingerprint/scan/', views.fingerprint_scan, name='fingerprint_scan'),

    # Report
    path('project/<int:project_id>/report/', views.generate_report, name='generate_report'),

    # API
    path('api/task/<int:task_id>/status/', views.task_status_api, name='task_status_api'),
    path('api/task/<int:task_id>/cancel/', cancel_recon_task, name='cancel_recon_task'),
    path('api/project/<int:project_id>/active-tasks/', views.project_active_tasks_api, name='project_active_tasks_api'),

    # Report export
    path('project/<int:project_id>/report/export/json/', views.export_report_json, name='export_report_json'),
]
