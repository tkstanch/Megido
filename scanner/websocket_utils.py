"""
Utility functions for sending real-time updates via WebSockets.

This module provides helper functions to send task status updates
to WebSocket clients through Django Channels.
"""

import logging
from typing import Dict, Any
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import asyncio

logger = logging.getLogger(__name__)


async def send_task_update_async(task_id: str, update_type: str, data: Dict[str, Any]) -> None:
    """
    Async version: Send a task update to all WebSocket clients listening to this task.
    
    Args:
        task_id: The Celery task ID
        update_type: Type of update (progress, success, failure, etc.)
        data: Additional data to send with the update
    """
    channel_layer = get_channel_layer()
    
    if channel_layer is None:
        logger.warning("Channel layer not configured, skipping WebSocket update")
        return
    
    group_name = f'task_{task_id}'
    
    message = {
        'type': 'task_update',
        'data': {
            'task_id': task_id,
            'update_type': update_type,
            **data
        }
    }
    
    try:
        await channel_layer.group_send(group_name, message)
        logger.debug(f"Sent {update_type} update for task {task_id}")
    except Exception as e:
        logger.error(f"Failed to send WebSocket update for task {task_id}: {e}")


def send_task_update(task_id: str, update_type: str, data: Dict[str, Any]) -> None:
    """
    Sync version: Send a task update to all WebSocket clients listening to this task.
    
    Args:
        task_id: The Celery task ID
        update_type: Type of update (progress, success, failure, etc.)
        data: Additional data to send with the update
    """
    channel_layer = get_channel_layer()
    
    if channel_layer is None:
        logger.warning("Channel layer not configured, skipping WebSocket update")
        return
    
    group_name = f'task_{task_id}'
    
    message = {
        'type': 'task_update',
        'data': {
            'task_id': task_id,
            'update_type': update_type,
            **data
        }
    }
    
    try:
        # Check if we're in an async context
        try:
            asyncio.get_running_loop()
            # We're in an async context, can't use async_to_sync
            logger.warning(f"send_task_update called from async context for task {task_id}, use send_task_update_async instead")
            return
        except RuntimeError:
            # No running loop, we can use async_to_sync
            async_to_sync(channel_layer.group_send)(group_name, message)
            logger.debug(f"Sent {update_type} update for task {task_id}")
    except Exception as e:
        logger.error(f"Failed to send WebSocket update for task {task_id}: {e}")


def send_progress_update(task_id: str, current: int, total: int, status: str = None) -> None:
    """
    Send a progress update for a task.
    
    Args:
        task_id: The Celery task ID
        current: Current progress count
        total: Total items to process
        status: Optional status message
    """
    data = {
        'current': current,
        'total': total,
        'percent': int(current / total * 100) if total > 0 else 0,
    }
    
    if status:
        data['status'] = status
    
    send_task_update(task_id, 'progress', data)


async def send_progress_update_async(task_id: str, current: int, total: int, status: str = None) -> None:
    """
    Async version: Send a progress update for a task.
    
    Args:
        task_id: The Celery task ID
        current: Current progress count
        total: Total items to process
        status: Optional status message
    """
    data = {
        'current': current,
        'total': total,
        'percent': int(current / total * 100) if total > 0 else 0,
    }
    
    if status:
        data['status'] = status
    
    await send_task_update_async(task_id, 'progress', data)


def send_success_update(task_id: str, result: Dict[str, Any]) -> None:
    """
    Send a success notification for a completed task.
    
    Args:
        task_id: The Celery task ID
        result: Task result data
    """
    send_task_update(task_id, 'success', {'result': result})


async def send_success_update_async(task_id: str, result: Dict[str, Any]) -> None:
    """
    Async version: Send a success notification for a completed task.
    
    Args:
        task_id: The Celery task ID
        result: Task result data
    """
    await send_task_update_async(task_id, 'success', {'result': result})


def send_failure_update(task_id: str, error: str) -> None:
    """
    Send a failure notification for a failed task.
    
    Args:
        task_id: The Celery task ID
        error: Error message
    """
    send_task_update(task_id, 'failure', {'error': error})


async def send_failure_update_async(task_id: str, error: str) -> None:
    """
    Async version: Send a failure notification for a failed task.
    
    Args:
        task_id: The Celery task ID
        error: Error message
    """
    await send_task_update_async(task_id, 'failure', {'error': error})

