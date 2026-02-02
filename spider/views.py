from django.shortcuts import render
from django.http import HttpResponse


def index(request):
    """Placeholder index view for the spider app"""
    return HttpResponse("Spider app is working!")
