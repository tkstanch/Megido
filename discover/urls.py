from django.urls import path
from . import views

app_name = 'discover'

urlpatterns = [
    path('', views.discover_home, name='home'),
    path('scan/', views.start_scan, name='start_scan'),
    path('report/<int:scan_id>/', views.view_report, name='view_report'),
    path('history/', views.scan_history, name='history'),
]
