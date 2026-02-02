from django.urls import path
from . import views

app_name = 'collaborator'

urlpatterns = [
    path('', views.collaborator_dashboard, name='dashboard'),
    path('api/servers/', views.collaborator_servers, name='servers'),
    path('api/servers/<int:server_id>/', views.collaborator_server_detail, name='server_detail'),
    path('api/servers/<int:server_id>/interactions/', views.interactions, name='interactions'),
    path('api/servers/<int:server_id>/interactions/log/', views.log_interaction, name='log_interaction'),
    path('api/servers/<int:server_id>/interactions/clear/', views.clear_interactions, name='clear_interactions'),
    path('api/servers/<int:server_id>/interactions/poll/', views.poll_interactions, name='poll_interactions'),
]
