"""
Cancel endpoints for the Scanner app.
"""
import logging

from celery.result import AsyncResult
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_scan(request, scan_id):
    """
    Cancel a running scan by its scan_id.

    Looks up the Celery task_id from the Scan model, revokes the task,
    and marks the scan status as ``'cancelled'``.
    """
    from scanner.models import Scan

    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'success': False, 'error': 'Scan not found'}, status=404)

    if scan.status in ('completed', 'failed', 'cancelled'):
        return Response({
            'success': False,
            'error': f'Scan is already {scan.status}',
        }, status=400)

    if scan.task_id:
        result = AsyncResult(scan.task_id)
        result.revoke(terminate=True, signal='SIGTERM')
        logger.info("Scan %s Celery task %s revoked by user %s", scan_id, scan.task_id, request.user)

    scan.status = 'cancelled'
    scan.save(update_fields=['status'])

    return Response({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan cancelled successfully.',
    })
