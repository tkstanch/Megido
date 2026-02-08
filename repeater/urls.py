from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'repeater'

urlpatterns = [
    path('', views.repeater_dashboard, name='dashboard'),
    path('api/requests/', views.repeater_requests, name='repeater_requests'),
    path('api/requests/<int:request_id>/send/', views.send_request, name='send_request'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
