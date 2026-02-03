"""
URL configuration for megido_security project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import render


def home(request):
    """Home page"""
    return render(request, 'home.html')


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
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
]
