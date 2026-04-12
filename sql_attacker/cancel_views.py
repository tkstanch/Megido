"""
Cancel endpoints for the SQL Attacker app.
"""
import logging

from celery.result import AsyncResult
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_sql_task(request, pk):
    """
    Cancel a running SQLInjectionTask by its primary key.

    Revokes the associated Celery task and marks the task status as
    ``'cancelled'``.
    """
    from sql_attacker.models import SQLInjectionTask

    try:
        task_obj = SQLInjectionTask.objects.get(id=pk)
    except SQLInjectionTask.DoesNotExist:
        return Response({'success': False, 'error': 'SQLInjectionTask not found'}, status=404)

    if task_obj.status in ('completed', 'failed', 'cancelled'):
        return Response({
            'success': False,
            'error': f'Task is already {task_obj.status}',
        }, status=400)

    if task_obj.celery_task_id:
        result = AsyncResult(task_obj.celery_task_id)
        result.revoke(terminate=True, signal='SIGTERM')
        logger.info(
            "SQLInjectionTask %s Celery task %s revoked by user %s",
            pk, task_obj.celery_task_id, request.user,
        )

    task_obj.status = 'cancelled'
    task_obj.save(update_fields=['status'])

    return Response({
        'success': True,
        'task_id': pk,
        'message': 'SQL injection task cancelled successfully.',
    })
