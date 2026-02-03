from django.urls import path
from . import views

app_name = 'response_analyser'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('vulnerabilities/', views.vulnerability_list, name='vulnerability_list'),
    path('vulnerabilities/<int:pk>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('vulnerabilities/<int:pk>/html/', views.render_evidence_html, name='render_evidence_html'),
]
