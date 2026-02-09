"""
WebSocket consumers for real-time task status updates.

This module provides WebSocket consumers that enable real-time
communication between the server and clients for task progress updates.
"""

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser

logger = logging.getLogger(__name__)


class TaskStatusConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time task status updates.
    
    Clients connect to ws://server/ws/scanner/task/<task_id>/
    to receive real-time updates about task progress, completion, or errors.
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.task_id = self.scope['url_route']['kwargs']['task_id']
        self.group_name = f'task_{self.task_id}'
        
        # Join task-specific group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        
        await self.accept()
        
        logger.info(f"WebSocket connected for task {self.task_id}")
        
        # Send initial connection confirmation
        await self.send(text_data=json.dumps({
            'type': 'connection',
            'status': 'connected',
            'task_id': self.task_id
        }))
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        logger.info(f"WebSocket disconnected for task {self.task_id} (code: {close_code})")
        
        # Leave task-specific group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        """
        Handle messages from WebSocket client.
        
        Currently not used, but can be extended for client commands
        like pause/resume if needed in the future.
        """
        try:
            data = json.loads(text_data)
            logger.debug(f"Received message from client: {data}")
            
            # Echo back for now (can add commands later)
            await self.send(text_data=json.dumps({
                'type': 'echo',
                'message': 'Message received'
            }))
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received: {text_data}")
    
    async def task_update(self, event):
        """
        Handle task update messages from the channel layer.
        
        This is called when a message is sent to the group from
        Celery tasks or other parts of the application.
        """
        # Forward the update to the WebSocket client
        await self.send(text_data=json.dumps(event['data']))
