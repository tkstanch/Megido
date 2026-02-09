"""
WebSocket routing configuration for megido_security project.

This module defines WebSocket URL patterns for real-time communication.
"""

from django.urls import re_path
from scanner import consumers

websocket_urlpatterns = [
    re_path(r'ws/scanner/task/(?P<task_id>[^/]+)/$', consumers.TaskStatusConsumer.as_asgi()),
]
