"""URL configuration for the Forensics app."""
from django.urls import path
from . import views, api_views

app_name = 'forensics'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    # Files
    path('upload/', views.upload_file, name='upload'),
    path('file/<int:pk>/', views.file_detail, name='file_detail'),
    path('files/', views.file_list, name='file_list'),
    # Cases
    path('cases/', views.case_list, name='case_list'),
    path('cases/create/', views.case_create, name='case_create'),
    path('cases/<int:pk>/', views.case_detail, name='case_detail'),
    # Evidence
    path('evidence/<int:pk>/', views.evidence_detail, name='evidence_detail'),
    # Analysis
    path('analysis/disk/<int:pk>/', views.analysis_disk, name='analysis_disk'),
    path('analysis/memory/<int:pk>/', views.analysis_memory, name='analysis_memory'),
    path('analysis/network/<int:pk>/', views.analysis_network, name='analysis_network'),
    path('analysis/timeline/<int:pk>/', views.analysis_timeline, name='analysis_timeline'),
    # IOCs
    path('iocs/', views.ioc_list, name='ioc_list'),
    path('iocs/export/', views.ioc_export, name='ioc_export'),
    # Reports
    path('reports/', views.report_list, name='report_list'),
    path('reports/generate/<int:case_pk>/', views.report_generate, name='report_generate'),
    # YARA
    path('yara/', views.yara_rule_list, name='yara_rule_list'),
    # API endpoints
    path('api/stats/', api_views.api_stats, name='api_stats'),
    path('api/cases/', api_views.api_cases, name='api_cases'),
    path('api/cases/<int:pk>/', api_views.api_case_detail, name='api_case_detail'),
    path('api/evidence/', api_views.api_evidence, name='api_evidence'),
    path('api/evidence/<int:case_pk>/', api_views.api_evidence, name='api_evidence_by_case'),
    path('api/files/', api_views.api_files, name='api_files'),
    path('api/files/<int:pk>/', api_views.api_file_detail, name='api_file_detail'),
    path('api/iocs/', api_views.api_iocs, name='api_iocs'),
    path('api/timeline/', api_views.api_timeline, name='api_timeline'),
]
