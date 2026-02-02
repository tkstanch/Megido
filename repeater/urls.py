from django.urls import path
from . import views

app_name = 'repeater'

urlpatterns = [
    path('', views.repeater_dashboard, name='dashboard'),
    path('api/requests/', views.repeater_requests, name='repeater_requests'),
    path('api/requests/<int:request_id>/send/', views.send_request, name='send_request'),
]
