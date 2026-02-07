from django.urls import path
from . import views

app_name = 'interceptor'

urlpatterns = [
    path('', views.interceptor_dashboard, name='dashboard'),
    path('api/status/', views.interceptor_status, name='interceptor_status'),
    path('api/intercepted/', views.list_intercepted, name='list_intercepted'),
    path('api/intercepted/<int:request_id>/', views.intercepted_detail, name='intercepted_detail'),
]
