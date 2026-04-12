from django.urls import path
from . import views
from .cancel_views import cancel_sql_task
from browser.views import launch_pyqt_browser

app_name = 'sql_attacker'

urlpatterns = [
    # Web UI URLs
    path('', views.dashboard, name='dashboard'),
    path('tasks/', views.task_list, name='task_list'),
    path('tasks/create/', views.task_create, name='task_create'),
    path('tasks/<int:pk>/', views.task_detail, name='task_detail'),
    path('tasks/<int:task_id>/confirm/', views.confirm_parameters, name='confirm_parameters'),  # NEW
    path('results/<int:pk>/', views.result_detail, name='result_detail'),

    # Bug Tracker Web UI
    path('bugs/', views.bug_tracker_dashboard, name='bug_tracker_dashboard'),
    path('bugs/<str:bug_id>/', views.bug_detail, name='bug_detail'),
    path('bugs/<str:bug_id>/triage/', views.bug_triage, name='bug_triage'),

    # Bounty Dashboard Web UI
    path('bounty/', views.bounty_dashboard, name='bounty_dashboard'),

    # Client-Side Scanning URLs
    path('client-side/', views.client_side_dashboard, name='client_side_dashboard'),

    # REST API URLs
    path('api/tasks/', views.api_tasks, name='api_tasks'),
    path('api/tasks/<int:pk>/', views.api_task_detail, name='api_task_detail'),
    path('api/tasks/<int:pk>/status/', views.api_task_status, name='api_task_status'),
    path('api/tasks/<int:pk>/cancel/', cancel_sql_task, name='cancel_sql_task'),
    path('api/tasks/<int:pk>/execute/', views.api_task_execute, name='api_task_execute'),
    path('api/tasks/<int:pk>/progress/', views.api_task_progress, name='api_task_progress'),
    path('api/results/', views.api_results, name='api_results'),
    path('api/results/<int:result_id>/union-poc/', views.api_union_poc_evidence, name='api_union_poc_evidence'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),

    # OOB Payload Generation API URLs
    path('api/oob/generate/', views.api_generate_oob_payloads, name='api_generate_oob_payloads'),
    path('api/oob/listener-guide/', views.api_oob_listener_guide, name='api_oob_listener_guide'),

    # Manipulator Integration API URLs
    path('api/manipulator/tricks/', views.api_manipulator_tricks, name='api_manipulator_tricks'),
    path('api/manipulator/apply/', views.api_apply_manipulation, name='api_apply_manipulation'),

    # Client-Side Scanning API URLs
    path('api/client-side/scan/', views.api_client_side_scan, name='api_client_side_scan'),
    path('api/client-side/export/', views.api_client_side_export, name='api_client_side_export'),

    # Bug Tracker REST API
    path('api/bugs/', views.api_bugs, name='api_bugs'),
    path('api/bugs/<str:bug_id>/', views.api_bug_detail, name='api_bug_detail'),
    path('api/bugs/<str:bug_id>/triage/', views.api_bug_triage, name='api_bug_triage'),
    path('api/bugs/<str:bug_id>/impact-report/', views.api_generate_impact_report, name='api_generate_impact_report'),
    path('api/bugs/<str:bug_id>/export-report/', views.api_export_bounty_report, name='api_export_bounty_report'),
]
