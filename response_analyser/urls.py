from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'response_analyser'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('vulnerabilities/', views.vulnerability_list, name='vulnerability_list'),
    path('vulnerabilities/<int:pk>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('vulnerabilities/<int:pk>/html/', views.render_evidence_html, name='render_evidence_html'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
