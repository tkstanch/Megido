"""
Tests for WebSocket consumers and real-time updates.
"""

import pytest
from channels.testing import WebsocketCommunicator
from channels.routing import URLRouter
from channels.layers import get_channel_layer
from django.urls import re_path
from django.test import override_settings
from scanner.consumers import TaskStatusConsumer
import json


# Use in-memory channel layer for testing
TEST_CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer'
    }
}


@pytest.mark.asyncio
@override_settings(CHANNEL_LAYERS=TEST_CHANNEL_LAYERS)
async def test_task_status_consumer_connection():
    """Test that WebSocket consumer accepts connections."""
    application = URLRouter([
        re_path(r'ws/scanner/task/(?P<task_id>[^/]+)/$', TaskStatusConsumer.as_asgi()),
    ])
    
    task_id = 'test-task-123'
    communicator = WebsocketCommunicator(application, f'/ws/scanner/task/{task_id}/')
    
    # Test connection
    connected, subprotocol = await communicator.connect()
    assert connected
    
    # Should receive a connection confirmation message
    response = await communicator.receive_json_from(timeout=5)
    assert response['type'] == 'connection'
    assert response['status'] == 'connected'
    assert response['task_id'] == task_id
    
    # Close connection
    await communicator.disconnect()


@pytest.mark.asyncio
@override_settings(CHANNEL_LAYERS=TEST_CHANNEL_LAYERS)
async def test_task_status_consumer_receives_updates():
    """Test that consumer receives and forwards task updates."""
    application = URLRouter([
        re_path(r'ws/scanner/task/(?P<task_id>[^/]+)/$', TaskStatusConsumer.as_asgi()),
    ])
    
    task_id = 'test-task-456'
    communicator = WebsocketCommunicator(application, f'/ws/scanner/task/{task_id}/')
    
    # Connect
    connected, _ = await communicator.connect()
    assert connected
    
    # Receive initial connection message
    await communicator.receive_json_from(timeout=5)
    
    # Send a test message to the consumer
    await communicator.send_json_to({
        'type': 'test',
        'message': 'hello'
    })
    
    # Should receive echo back
    response = await communicator.receive_json_from(timeout=5)
    assert response['type'] == 'echo'
    assert response['message'] == 'Message received'
    
    # Close connection
    await communicator.disconnect()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
