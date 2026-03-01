"""
Celery tasks for scanner application

This module contains background tasks for long-running operations including:
- Scan execution (async_scan_task) 
- Exploit operations (async_exploit_all_vulnerabilities, async_exploit_selected_vulnerabilities)
"""

import logging
import os
from typing import Dict, Any, Optional, List

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone

from scanner.models import Scan, Vulnerability
from scanner.exploit_integration import (
    exploit_vulnerability,
    format_exploit_result
)
from scanner.websocket_utils import (
    send_progress_update,
    send_success_update,
    send_failure_update
)
from scanner.config_defaults import get_default_proof_config

logger = logging.getLogger(__name__)


@shared_task(bind=True, name='scanner.async_scan_task', time_limit=3600, soft_time_limit=3500)
def async_scan_task(self, scan_id: int) -> Dict[str, Any]:
    """
    Celery task to perform vulnerability scan asynchronously.
    
    This task runs the scan in the background, allowing Gunicorn to respond immediately
    and preventing worker blocking during long-running scans.
    
    Args:
        scan_id: The scan ID to execute
    
    Returns:
        Dictionary containing:
        - scan_id: The scan ID
        - status: Final status ('completed' or 'failed')
        - message: Status message
        - vulnerabilities_found: Number of vulnerabilities discovered
        - task_id: The Celery task ID for tracking
    """
    task_id = self.request.id if self.request.id else 'eager-mode'
    logger.info(f"Starting async scan task for scan {scan_id} (task_id: {task_id})")
    
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        error_result = {
            'scan_id': scan_id,
            'status': 'failed',
            'error': f'Scan {scan_id} not found',
            'task_id': task_id,
        }
        logger.error(f"Scan {scan_id} not found")
        return error_result
    
    # Update scan status to 'running'
    scan.status = 'running'
    scan.save()
    
    # Collect visual proof diagnostics at scan start
    try:
        from scanner.visual_proof_diagnostics import get_visual_proof_warnings
        visual_proof_warnings = get_visual_proof_warnings()
        if visual_proof_warnings:
            # Initialize warnings list if it doesn't exist (for migration compatibility)
            if not hasattr(scan, 'warnings') or scan.warnings is None:
                scan.warnings = []
            scan.warnings.extend(visual_proof_warnings)
            scan.save()
            logger.warning(f"Visual proof diagnostics found {len(visual_proof_warnings)} issue(s) for scan {scan_id}")
    except Exception as e:
        logger.error(f"Failed to collect visual proof warnings for scan {scan_id}: {e}")
    
    try:
        # Import here to avoid circular imports
        from scanner.views import perform_basic_scan
        
        # Perform the scan
        logger.info(f"Executing scan for target: {scan.target.url}")
        perform_basic_scan(scan, scan.target.url)
        
        # Update scan status to completed
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()
        
        vulnerabilities_count = scan.vulnerabilities.count()
        logger.info(f"Scan {scan_id} completed successfully. Found {vulnerabilities_count} vulnerabilities.")
        
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'message': 'Scan completed successfully',
            'vulnerabilities_found': vulnerabilities_count,
            'task_id': task_id,
        }
        
    except SoftTimeLimitExceeded:
        logger.warning(f"Soft time limit reached for scan {scan_id}.")
        vulnerabilities_count = scan.vulnerabilities.count()
        if vulnerabilities_count > 0:
            logger.warning(
                f"Scan {scan_id} has {vulnerabilities_count} partial result(s). "
                "Marking as completed with warnings."
            )
            if scan.warnings is None:
                scan.warnings = []
            scan.warnings.append('Scan exceeded time limit. Results may be incomplete.')
            scan.status = 'completed'
        else:
            logger.warning(f"Scan {scan_id} has no results. Marking as failed.")
            scan.status = 'failed'
        scan.completed_at = timezone.now()
        scan.save()

        return {
            'scan_id': scan_id,
            'status': scan.status,
            'error': 'Scan exceeded time limit',
            'vulnerabilities_found': vulnerabilities_count,
            'task_id': task_id,
        }
        
    except Exception as e:
        logger.error(f"Error during scan {scan_id}: {str(e)}", exc_info=True)
        scan.status = 'failed'
        scan.completed_at = timezone.now()
        scan.save()
        
        return {
            'scan_id': scan_id,
            'status': 'failed',
            'error': str(e),
            'task_id': task_id,
        }


# Time limit increased from 30 minutes to 1 hour to handle large numbers of vulnerabilities
# Soft time limit set to 58:20 to allow graceful cleanup before hard termination
@shared_task(bind=True, name='scanner.exploit_all_vulnerabilities', time_limit=3600, soft_time_limit=3500)
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
    
    config = config or get_default_proof_config()
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
    
    try:
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
    except SoftTimeLimitExceeded:
        logger.warning(
            f"Soft time limit reached for scan {scan_id}. "
            f"Processed {len(results['results'])}/{total} vulnerabilities. "
            "Terminating gracefully."
        )
        results['error'] = f'Task exceeded time limit. Processed {len(results["results"])}/{total} vulnerabilities.'
    
    logger.info(
        f"Completed exploit task for scan {scan_id}: "
        f"{results['exploited']} exploited, {results['failed']} failed, "
        f"{results['no_plugin']} no plugin"
    )
    
    # Send final success update via WebSocket
    send_success_update(task_id=task_id, result=results)
    
    return results


@shared_task(bind=True, name='scanner.exploit_selected_vulnerabilities', time_limit=3600, soft_time_limit=3500)
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
    
    config = config or get_default_proof_config()
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
    
    try:
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
                
                # Send WebSocket update for real-time UI updates
                send_progress_update(
                    task_id=task_id,
                    current=idx,
                    total=total,
                    status=f'Processing vulnerability {idx}/{total}'
                )
            
            _exploit_vulnerability_and_update(vuln, config, results)
    except SoftTimeLimitExceeded:
        logger.warning(
            f"Soft time limit reached for selected vulnerabilities. "
            f"Processed {len(results['results'])}/{total} vulnerabilities. "
            "Terminating gracefully."
        )
        results['error'] = f'Task exceeded time limit. Processed {len(results["results"])}/{total} vulnerabilities.'
    
    logger.info(
        f"Completed selected exploit task: "
        f"{results['exploited']} exploited, {results['failed']} failed, "
        f"{results['no_plugin']} no plugin"
    )
    
    # Send final success update via WebSocket
    send_success_update(task_id=task_id, result=results)
    
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
