from django.urls import path
from . import views

urlpatterns = [
    path('', views.repeater_dashboard, name='repeater_dashboard'),
    path('api/requests/', views.repeater_requests, name='repeater_requests'),
    path('api/requests/<int:request_id>/', views.repeater_request_detail, name='repeater_request_detail'),
    path('api/requests/<int:request_id>/send/', views.send_request, name='send_request'),
    path('api/requests/<int:request_id>/send-to/<str:tool>/', views.send_to_tool, name='send_to_tool'),
    path('api/tabs/', views.tab_list, name='tab_list'),
    path('api/tabs/<int:tab_id>/', views.tab_detail, name='tab_detail'),
    path('api/bypass-techniques/', views.bypass_techniques, name='bypass_techniques'),
]
