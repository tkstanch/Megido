from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

app_name = 'spider'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/targets/', views.spider_targets, name='spider_targets'),
    path('api/targets/<int:target_id>/spider/', views.start_spider, name='start_spider'),
    path('api/sessions/<int:session_id>/results/', views.spider_results, name='spider_results'),
    path('api/analytics/', views.session_analytics, name='session_analytics'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
