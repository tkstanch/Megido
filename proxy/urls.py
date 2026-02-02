from django.urls import path
from . import views

app_name = 'proxy'

urlpatterns = [
    path('', views.proxy_dashboard, name='dashboard'),
    path('api/requests/', views.list_requests, name='list_requests'),
    path('api/requests/<int:request_id>/', views.get_request_detail, name='request_detail'),
]
