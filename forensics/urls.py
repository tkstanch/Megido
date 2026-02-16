"""
URL configuration for the Forensics app.
"""
from django.urls import path
from . import views

app_name = 'forensics'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('upload/', views.upload_file, name='upload'),
    path('file/<int:pk>/', views.file_detail, name='file_detail'),
    path('files/', views.file_list, name='file_list'),
]
