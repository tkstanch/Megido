from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'app_manager'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('api/apps/', views.list_apps, name='list_apps'),
    path('api/apps/<int:app_id>/', views.app_detail, name='app_detail'),
    path('api/apps/<int:app_id>/toggle/', views.toggle_app, name='toggle_app'),
    path('api/apps/<int:app_id>/history/', views.app_state_history, name='app_state_history'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
