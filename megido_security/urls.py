"""
URL configuration for Megido Security project.
"""
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import render
from django.conf import settings
from django.conf.urls.static import static
from app_manager.cancel_views import cancel_task
import os

ADMIN_PATH = os.environ.get('ADMIN_PATH', 'admin')


def home(request):
    return render(request, 'home.html')


urlpatterns = [
    path(f'{ADMIN_PATH}/', admin.site.urls),
    path('', home, name='home'),
    path('dashboard/', home, name='dashboard'),
    path('api/cancel-task/', cancel_task, name='cancel_task'),
    path('app-manager/', include('app_manager.urls')),
    path('browser/', include('browser.urls')),
    path('proxy/', include('proxy.urls')),
    path('interceptor/', include('interceptor.urls')),
    path('repeater/', include('repeater.urls')),
    path('scanner/', include('scanner.urls')),
    path('spider/', include('spider.urls')),
    path('mapper/', include('mapper.urls')),
    path('bypasser/', include('bypasser.urls')),
    path('collaborator/', include('collaborator.urls')),
    path('decompiler/', include('decompiler.urls')),
    path('malware-analyser/', include('malware_analyser.urls')),
    path('response-analyser/', include('response_analyser.urls')),
    path('sql-attacker/', include('sql_attacker.urls')),
    path('data-tracer/', include('data_tracer.urls')),
    path('discover/', include('discover.urls')),
    path('manipulator/', include('manipulator.urls')),
    path('forensics/', include('forensics.urls')),
    path('recon/', include('recon.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
