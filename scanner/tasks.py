"""
Celery tasks for scanner application

This module contains background tasks for long-running exploit operations.
"""

from celery import shared_task
from typing import Dict, Any, Optional, List
import logging

from scanner.models import Scan, Vulnerability
from scanner.exploit_integration import (
    exploit_vulnerability,
    format_exploit_result
)
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(bind=True, name='scanner.exploit_all_vulnerabilities')
def async_exploit_all_vulnerabilities(self, scan_id: int, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Celery task to exploit all vulnerabilities in a scan.
    
    This task runs in the background and can take several minutes to complete
    depending on the number of vulnerabilities and complexity of exploit attempts.
    
    Args:
        scan_id: The scan ID to process
        config: Optional configuration for attacks (timeout, verify_ssl, etc.)
    
    Returns:
        Dictionary containing:
        - total: Total number of vulnerabilities
        - exploited: Number successfully exploited
        - failed: Number that failed
        - no_plugin: Number with no compatible plugin
        - results: List of individual exploit results
        - task_id: The Celery task ID for tracking
    """
    task_id = self.request.id if self.request.id else 'eager-mode'
    logger.info(f"Starting async exploit task for scan {scan_id} (task_id: {task_id})")
    
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        error_result = {
            'error': f'Scan {scan_id} not found',
            'total': 0,
            'exploited': 0,
            'failed': 0,
            'no_plugin': 0,
            'results': [],
            'task_id': task_id,
        }
        logger.error(f"Scan {scan_id} not found")
        return error_result
    
    config = config or {}
    vulnerabilities = scan.vulnerabilities.all()
    total = vulnerabilities.count()
    
    results = {
        'total': total,
        'exploited': 0,
        'failed': 0,
        'no_plugin': 0,
        'results': [],
        'task_id': task_id,
    }
    
    logger.info(f"Processing {total} vulnerabilities for scan {scan_id}")
    
    for idx, vuln in enumerate(vulnerabilities, 1):
        # Update task state for progress tracking (only if not in eager mode)
        if self.request.id:
            self.update_state(
                state='PROGRESS',
                meta={
                    'current': idx,
                    'total': total,
                    'status': f'Processing vulnerability {idx}/{total}'
                }
            )
        
        _exploit_vulnerability_and_update(vuln, config, results)
    
    logger.info(
        f"Completed exploit task for scan {scan_id}: "
        f"{results['exploited']} exploited, {results['failed']} failed, "
        f"{results['no_plugin']} no plugin"
    )
    
    return results


@shared_task(bind=True, name='scanner.exploit_selected_vulnerabilities')
def async_exploit_selected_vulnerabilities(
    self,
    vulnerability_ids: List[int],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Celery task to exploit specific vulnerabilities by ID.
    
    Args:
        vulnerability_ids: List of vulnerability IDs to exploit
        config: Optional configuration for attacks
    
    Returns:
        Dictionary containing:
        - total: Total number of vulnerabilities processed
        - exploited: Number successfully exploited
        - failed: Number that failed
        - no_plugin: Number with no compatible plugin
        - results: List of individual exploit results
        - task_id: The Celery task ID for tracking
    """
    task_id = self.request.id if self.request.id else 'eager-mode'
    logger.info(
        f"Starting async exploit task for {len(vulnerability_ids)} vulnerabilities "
        f"(task_id: {task_id})"
    )
    
    config = config or {}
    vulnerabilities = Vulnerability.objects.filter(id__in=vulnerability_ids)
    total = vulnerabilities.count()
    
    results = {
        'total': total,
        'exploited': 0,
        'failed': 0,
        'no_plugin': 0,
        'results': [],
        'task_id': task_id,
    }
    
    logger.info(f"Processing {total} selected vulnerabilities")
    
    for idx, vuln in enumerate(vulnerabilities, 1):
        # Update task state for progress tracking (only if not in eager mode)
        if self.request.id:
            self.update_state(
                state='PROGRESS',
                meta={
                    'current': idx,
                    'total': total,
                    'status': f'Processing vulnerability {idx}/{total}'
                }
            )
        
        _exploit_vulnerability_and_update(vuln, config, results)
    
    logger.info(
        f"Completed selected exploit task: "
        f"{results['exploited']} exploited, {results['failed']} failed, "
        f"{results['no_plugin']} no plugin"
    )
    
    return results


def _exploit_vulnerability_and_update(
    vuln: Vulnerability,
    config: Optional[Dict[str, Any]],
    results: Dict[str, Any]
) -> None:
    """
    Helper function to exploit a single vulnerability and update tracking results.
    
    This is a shared helper used by both async tasks to avoid code duplication.
    
    Args:
        vuln: Vulnerability instance to exploit
        config: Optional configuration for attacks
        results: Dictionary to update with results (modified in place)
    """
    # Mark as in progress
    vuln.exploit_status = 'in_progress'
    vuln.save()
    
    # Attempt exploitation
    try:
        result = exploit_vulnerability(vuln, config)
    except Exception as e:
        logger.error(f"Exception during exploitation of vulnerability {vuln.id}: {e}")
        result = {
            'success': False,
            'plugin_used': None,
            'error': f'Exception during exploitation: {str(e)}',
            'findings': [],
            'data': {},
            'evidence': ''
        }
    
    # Update vulnerability with results
    vuln.exploit_attempted_at = timezone.now()
    
    if result['success']:
        vuln.exploited = True
        vuln.exploit_status = 'success'
        results['exploited'] += 1
    elif result.get('plugin_used') is None:
        vuln.exploit_status = 'no_plugin'
        results['no_plugin'] += 1
    else:
        vuln.exploit_status = 'failed'
        results['failed'] += 1
    
    # Store detailed results
    vuln.exploit_result = format_exploit_result(result)
    vuln.save()
    
    # Add to results list
    results['results'].append({
        'vulnerability_id': vuln.id,
        'vulnerability_type': vuln.get_vulnerability_type_display(),
        'url': vuln.url,
        'success': result['success'],
        'plugin_used': result.get('plugin_used'),
        'evidence': result.get('evidence', ''),
        'error': result.get('error', ''),
    })
    
    logger.info(
        f"Exploit attempt for vulnerability {vuln.id} ({vuln.vulnerability_type}): "
        f"{'SUCCESS' if result['success'] else 'FAILED'}"
    )
