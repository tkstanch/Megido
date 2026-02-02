from django.urls import path
from . import views

app_name = 'spider'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/targets/', views.spider_targets, name='spider_targets'),
    path('api/targets/<int:target_id>/spider/', views.start_spider, name='start_spider'),
    path('api/sessions/<int:session_id>/results/', views.spider_results, name='spider_results'),
]
