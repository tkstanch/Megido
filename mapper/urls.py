from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'mapper'

urlpatterns = [
    path('', views.mapper_home, name='home'),
    path('login/', views.secure_login, name='secure_login'),
    path('upload/', views.secure_file_upload, name='file_upload'),
    path('download/<uuid:file_id>/', views.secure_file_download, name='file_download'),
    path('redirect/', views.secure_redirect, name='redirect'),
    path('user-data/', views.user_data_view, name='user_data'),
    path('submit-data/', views.submit_user_data, name='submit_data'),
    path('query/', views.secure_query, name='secure_query'),
    path('validate/', views.validate_input, name='validate_input'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
