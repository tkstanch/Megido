"""
Generic task cancellation views for all Megido apps.

Any app with a Celery-backed long-running process can POST to
``/api/cancel-task/`` with ``{"task_id": "<celery-task-id>"}`` to revoke the
task.  App-specific cancel endpoints (e.g. for Scanner, Recon, SQL Attacker)
are provided in each app's own ``cancel_views.py`` and also update the
database record's status to ``'cancelled'``.
"""
import logging

from celery.result import AsyncResult
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_task(request):
    """
    Generic endpoint — cancel any running Celery task by its task_id.

    POST body: ``{"task_id": "<celery-task-id>"}``

    Sends SIGTERM to the worker process so the task function can catch
    ``celery.exceptions.Terminated`` and clean up gracefully.
    """
    task_id = request.data.get('task_id')
    if not task_id:
        return Response({'success': False, 'error': 'task_id is required'}, status=400)

    try:
        result = AsyncResult(task_id)
        result.revoke(terminate=True, signal='SIGTERM')
        logger.info("Task %s revoked by user %s", task_id, request.user)
        return Response({
            'success': True,
            'task_id': task_id,
            'message': 'Task cancellation signal sent.',
        })
    except Exception as exc:
        logger.error("Error cancelling task %s: %s", task_id, exc)
        return Response({'success': False, 'error': str(exc)}, status=500)
