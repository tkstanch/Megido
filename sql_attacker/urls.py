from django.urls import path
from . import views
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
    
    # Client-Side Scanning URLs
    path('client-side/', views.client_side_dashboard, name='client_side_dashboard'),
    
    # REST API URLs
    path('api/tasks/', views.api_tasks, name='api_tasks'),
    path('api/tasks/<int:pk>/', views.api_task_detail, name='api_task_detail'),
    path('api/tasks/<int:pk>/execute/', views.api_task_execute, name='api_task_execute'),
    path('api/results/', views.api_results, name='api_results'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
    
    # OOB Payload Generation API URLs
    path('api/oob/generate/', views.api_generate_oob_payloads, name='api_generate_oob_payloads'),
    path('api/oob/listener-guide/', views.api_oob_listener_guide, name='api_oob_listener_guide'),
    
    # Client-Side Scanning API URLs
    path('api/client-side/scan/', views.api_client_side_scan, name='api_client_side_scan'),
    path('api/client-side/export/', views.api_client_side_export, name='api_client_side_export'),
]
