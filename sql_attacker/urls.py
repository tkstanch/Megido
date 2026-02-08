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
    path('results/<int:pk>/', views.result_detail, name='result_detail'),
    
    # REST API URLs
    path('api/tasks/', views.api_tasks, name='api_tasks'),
    path('api/tasks/<int:pk>/', views.api_task_detail, name='api_task_detail'),
    path('api/tasks/<int:pk>/execute/', views.api_task_execute, name='api_task_execute'),
    path('api/results/', views.api_results, name='api_results'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
