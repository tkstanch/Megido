from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'proxy'

urlpatterns = [
    path('', views.proxy_dashboard, name='dashboard'),
    path('api/requests/', views.list_requests, name='list_requests'),
    path('api/requests/<int:request_id>/', views.get_request_detail, name='request_detail'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
