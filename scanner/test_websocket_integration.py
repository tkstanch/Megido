"""
Integration test demonstrating WebSocket real-time updates with Celery tasks.

This test simulates the complete flow:
1. Start an exploitation task
2. Receive progress updates via WebSocket
3. Get final results when task completes
"""

import pytest
import asyncio
from channels.testing import WebsocketCommunicator
from channels.layers import get_channel_layer
from django.test import override_settings
from scanner.consumers import TaskStatusConsumer
from scanner.websocket_utils import (
    send_progress_update_async,
    send_success_update_async
)


# Use in-memory channel layer for testing
TEST_CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer'
    }
}


@pytest.mark.asyncio
@override_settings(CHANNEL_LAYERS=TEST_CHANNEL_LAYERS)
async def test_websocket_receives_task_progress():
    """Test that WebSocket receives progress updates from Celery task simulation."""
    from channels.routing import URLRouter
    from django.urls import re_path
    
    task_id = 'test-task-progress-789'
    
    # Create application with routing
    application = URLRouter([
        re_path(r'ws/scanner/task/(?P<task_id>[^/]+)/$', TaskStatusConsumer.as_asgi()),
    ])
    
    # Create WebSocket connection
    communicator = WebsocketCommunicator(
        application,
        f'/ws/scanner/task/{task_id}/'
    )
    
    # Connect
    connected, _ = await communicator.connect()
    assert connected
    
    # Receive connection message
    response = await communicator.receive_json_from(timeout=5)
    assert response['type'] == 'connection'
    
    # Simulate sending progress update from Celery task (async version for tests)
    await send_progress_update_async(task_id, current=1, total=3, status='Processing vulnerability 1/3')
    
    # WebSocket should receive the update
    response = await communicator.receive_json_from(timeout=5)
    assert response['update_type'] == 'progress'
    assert response['current'] == 1
    assert response['total'] == 3
    assert response['percent'] == 33  # 1/3 * 100
    
    # Simulate another progress update
    await send_progress_update_async(task_id, current=2, total=3, status='Processing vulnerability 2/3')
    
    response = await communicator.receive_json_from(timeout=5)
    assert response['update_type'] == 'progress'
    assert response['current'] == 2
    assert response['total'] == 3
    assert response['percent'] == 66  # 2/3 * 100
    
    # Simulate task completion
    final_result = {
        'total': 3,
        'exploited': 2,
        'failed': 1,
        'no_plugin': 0,
        'results': []
    }
    await send_success_update_async(task_id, final_result)
    
    response = await communicator.receive_json_from(timeout=5)
    assert response['update_type'] == 'success'
    assert response['result']['total'] == 3
    assert response['result']['exploited'] == 2
    
    # Clean up
    await communicator.disconnect()


@pytest.mark.asyncio
@override_settings(CHANNEL_LAYERS=TEST_CHANNEL_LAYERS)
async def test_multiple_websocket_clients_receive_updates():
    """Test that multiple WebSocket clients can receive the same task updates."""
    from channels.routing import URLRouter
    from django.urls import re_path
    
    task_id = 'test-task-multi-999'
    
    # Create application with routing
    application = URLRouter([
        re_path(r'ws/scanner/task/(?P<task_id>[^/]+)/$', TaskStatusConsumer.as_asgi()),
    ])
    
    # Create two WebSocket connections for the same task
    communicator1 = WebsocketCommunicator(
        application,
        f'/ws/scanner/task/{task_id}/'
    )
    communicator2 = WebsocketCommunicator(
        application,
        f'/ws/scanner/task/{task_id}/'
    )
    
    # Connect both
    connected1, _ = await communicator1.connect()
    connected2, _ = await communicator2.connect()
    assert connected1 and connected2
    
    # Receive connection messages
    await communicator1.receive_json_from(timeout=5)
    await communicator2.receive_json_from(timeout=5)
    
    # Send one progress update (async version for tests)
    await send_progress_update_async(task_id, current=1, total=1, status='Complete')
    
    # Both clients should receive it
    response1 = await communicator1.receive_json_from(timeout=5)
    response2 = await communicator2.receive_json_from(timeout=5)
    
    assert response1['update_type'] == 'progress'
    assert response2['update_type'] == 'progress'
    assert response1['current'] == 1
    assert response2['current'] == 1
    
    # Clean up
    await communicator1.disconnect()
    await communicator2.disconnect()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
