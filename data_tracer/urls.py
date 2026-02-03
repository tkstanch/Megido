from django.urls import path
from . import views

app_name = 'data_tracer'

urlpatterns = [
    path('', views.data_tracer_home, name='home'),
    path('create/', views.create_scan, name='create_scan'),
    path('scans/', views.scan_list, name='scan_list'),
    path('scan/<uuid:scan_id>/', views.scan_detail, name='scan_detail'),
    path('scan/<uuid:scan_id>/execute/', views.execute_scan, name='execute_scan'),
    path('result/<uuid:result_id>/', views.result_detail, name='result_detail'),
    path('result/<uuid:result_id>/packets/', views.packet_analysis, name='packet_analysis'),
    path('stealth/', views.stealth_config, name='stealth_config'),
]
