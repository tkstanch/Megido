"""
Cancel endpoints for the Recon app.
"""
import logging

from celery.result import AsyncResult
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_recon_task(request, task_id):
    """
    Cancel a running ReconTask by its database primary key.

    Revokes the associated Celery task and marks the ReconTask status as
    ``'cancelled'``.
    """
    from recon.models import ReconTask

    try:
        task_obj = ReconTask.objects.get(id=task_id)
    except ReconTask.DoesNotExist:
        return Response({'success': False, 'error': 'ReconTask not found'}, status=404)

    if task_obj.status in ('completed', 'failed', 'cancelled'):
        return Response({
            'success': False,
            'error': f'Task is already {task_obj.status}',
        }, status=400)

    if task_obj.celery_task_id:
        result = AsyncResult(task_obj.celery_task_id)
        result.revoke(terminate=True, signal='SIGTERM')
        logger.info(
            "ReconTask %s Celery task %s revoked by user %s",
            task_id, task_obj.celery_task_id, request.user,
        )

    task_obj.status = 'cancelled'
    task_obj.save(update_fields=['status'])

    return Response({
        'success': True,
        'task_id': task_id,
        'message': 'Recon task cancelled successfully.',
    })
