"""
Celery tasks for SQL Attacker application.

This module contains background tasks for long-running SQL injection operations.
"""

import logging
from typing import Any, Dict

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded

logger = logging.getLogger(__name__)


@shared_task(bind=True, name='sql_attacker.sql_injection_task', time_limit=3600, soft_time_limit=3540)
def sql_injection_task(self, task_id: int) -> Dict[str, Any]:
    """
    Celery task to perform a SQL injection attack asynchronously.

    Args:
        task_id: The SQLInjectionTask ID to execute.

    Returns:
        Dictionary containing task_id and status information.
    """
    celery_task_id = self.request.id if self.request.id else 'eager-mode'
    logger.info(f"Starting sql_injection_task for task {task_id} (celery_task_id: {celery_task_id})")

    try:
        from .views import execute_task
        execute_task(task_id)
        logger.info(f"sql_injection_task for task {task_id} completed successfully.")
        return {'task_id': task_id, 'status': 'completed', 'celery_task_id': celery_task_id}
    except SoftTimeLimitExceeded:
        logger.warning(f"Soft time limit reached for sql_injection_task {task_id}.")
        return {'task_id': task_id, 'status': 'failed', 'error': 'Task exceeded time limit', 'celery_task_id': celery_task_id}
    except Exception as e:
        logger.error(f"Error in sql_injection_task for task {task_id}: {e}", exc_info=True)
        return {'task_id': task_id, 'status': 'failed', 'error': str(e), 'celery_task_id': celery_task_id}


@shared_task(bind=True, name='sql_attacker.sql_injection_task_with_selection', time_limit=3600, soft_time_limit=3540)
def sql_injection_task_with_selection(self, task_id: int) -> Dict[str, Any]:
    """
    Celery task to perform a SQL injection attack with manually selected parameters.

    Args:
        task_id: The SQLInjectionTask ID to execute with parameter selection.

    Returns:
        Dictionary containing task_id and status information.
    """
    celery_task_id = self.request.id if self.request.id else 'eager-mode'
    logger.info(f"Starting sql_injection_task_with_selection for task {task_id} (celery_task_id: {celery_task_id})")

    try:
        from .views import execute_task_with_selection
        execute_task_with_selection(task_id)
        logger.info(f"sql_injection_task_with_selection for task {task_id} completed successfully.")
        return {'task_id': task_id, 'status': 'completed', 'celery_task_id': celery_task_id}
    except SoftTimeLimitExceeded:
        logger.warning(f"Soft time limit reached for sql_injection_task_with_selection {task_id}.")
        return {'task_id': task_id, 'status': 'failed', 'error': 'Task exceeded time limit', 'celery_task_id': celery_task_id}
    except Exception as e:
        logger.error(f"Error in sql_injection_task_with_selection for task {task_id}: {e}", exc_info=True)
        return {'task_id': task_id, 'status': 'failed', 'error': str(e), 'celery_task_id': celery_task_id}
