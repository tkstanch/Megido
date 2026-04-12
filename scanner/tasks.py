"""
Celery tasks for scanner application

This module contains background tasks for long-running operations including:
- Scan execution (async_scan_task, async_stealth_scan_task)
- Exploit operations (async_exploit_all_vulnerabilities, async_exploit_selected_vulnerabilities)
"""

import logging
import os
import random
import time
import threading
import concurrent.futures
from typing import Dict, Any, Optional, List

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded, Terminated
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


# ---------------------------------------------------------------------------
# Memory helpers
# ---------------------------------------------------------------------------

def _memory_usage_percent() -> float:
    """Return the current process memory usage as a percentage of total RAM.

    Uses :mod:`psutil` when available; falls back to ``0.0`` so callers can
    always treat the return value as a valid percentage.

    Returns:
        float: Memory usage percentage (0.0–100.0).
    """
    try:
        import psutil
        process = psutil.Process(os.getpid())
        mem_info = process.memory_percent()
        return float(mem_info)
    except Exception:
        return 0.0


@shared_task(bind=True, name='scanner.async_scan_task', time_limit=3600, soft_time_limit=3500)
def async_scan_task(self, scan_id: int) -> Dict[str, Any]:
    """
    Celery task to perform vulnerability scan asynchronously.

    This task runs the scan in the background, allowing Gunicorn to respond immediately
    and preventing worker blocking during long-running scans.

    Per-plugin progress updates are sent via WebSocket so the UI can display
    real-time status.  Memory usage is monitored; if it exceeds 80 % the scan
    is stopped gracefully and partial results are saved.

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

    # Re-validate scope before running plugins (rules may have changed since submission)
    if scan.program_scope_id is not None:
        try:
            from scanner.scope_validator import ScopeValidator
            validator = ScopeValidator(scan.target.url, scan.program_scope)
            validation_result = validator.validate()
            if not validation_result['is_valid']:
                logger.warning(
                    f"Scan {scan_id} failed scope re-validation: {validation_result['violations']}"
                )
                scope_error = f"Scope re-validation failed: {validation_result['violations']}"
                scan.status = 'failed'
                scan.completed_at = timezone.now()
                scan.error_message = scope_error
                if scan.warnings is None:
                    scan.warnings = []
                scan.warnings.append(
                    f'Scan aborted: scope re-validation failed — {validation_result["violations"]}'
                )
                scan.save()
                return {
                    'scan_id': scan_id,
                    'status': 'failed',
                    'error': scope_error,
                    'violations': validation_result['violations'],
                    'task_id': task_id,
                }
        except Exception as scope_exc:
            logger.error(f"Scope re-validation error for scan {scan_id}: {scope_exc}")

    # Update scan status to 'running'
    scan.status = 'running'
    scan.save()

    # Collect visual proof diagnostics at scan start
    try:
        from scanner.visual_proof_diagnostics import get_visual_proof_warnings
        visual_proof_warnings = get_visual_proof_warnings()
        if visual_proof_warnings:
            if scan.warnings is None:
                scan.warnings = []
            scan.warnings.extend(visual_proof_warnings)
            scan.save()
            logger.warning(f"Visual proof diagnostics found {len(visual_proof_warnings)} issue(s) for scan {scan_id}")
    except Exception as e:
        logger.error(f"Failed to collect visual proof warnings for scan {scan_id}: {e}")

    try:
        from scanner.scan_plugins import get_scan_registry
        from scanner.scan_engine import ScanEngine

        # --- WAF / blocking bypass: fingerprint target first ---
        fingerprint: Dict[str, Any] = {}
        try:
            from scanner.scan_plugins.fingerprinter import TargetFingerprinter
            fingerprinter = TargetFingerprinter()
            fingerprint = fingerprinter.fingerprint(scan.target.url, {})
        except Exception as fp_exc:
            logger.warning("Fingerprinting failed for scan %d: %s", scan_id, fp_exc)

        registry = get_scan_registry()
        plugins = registry.get_all_plugins()
        total_plugins = len(plugins)

        # Send initial progress
        if self.request.id:
            send_progress_update(
                task_id=task_id,
                current=0,
                total=total_plugins,
                status='Starting scan',
            )

        # Build a scan engine and run plugins concurrently for faster scanning
        # while still sending per-plugin progress updates.
        engine = ScanEngine()

        # --- Enable stealth by default to bypass WAF/rate-limiting ---
        config: Dict[str, Any] = {
            'enable_stealth': True,
            'verify_ssl': False,
            'timeout': 15,
        }

        waf_detected = fingerprint.get('waf_detected', False)
        has_rate_limiting = fingerprint.get('has_rate_limiting', False)

        if waf_detected or has_rate_limiting:
            logger.info(
                "Scan %d: WAF=%s, rate_limit=%s — applying aggressive stealth",
                scan_id,
                fingerprint.get('waf_name', 'unknown'),
                has_rate_limiting,
            )
            config['stealth_timing'] = 'slow'
            config['timeout'] = 20
            config['waf_detected'] = True
            config['waf_name'] = fingerprint.get('waf_name')
            if scan.warnings is None:
                scan.warnings = []
            scan.warnings.append(
                f"WAF detected ({fingerprint.get('waf_name', 'unknown')}). "
                "Stealth mode activated with adaptive timing."
            )
            scan.save()

        # Inject stealth headers into the engine so all plugins inherit them
        try:
            engine.enable_stealth = True
        except AttributeError:
            pass
        try:
            from scanner.stealth_engine import StealthEngine
            engine._stealth_engine = StealthEngine()
        except ImportError:
            pass
        if hasattr(engine, '_apply_stealth_session'):
            engine._apply_stealth_session(config)

        all_findings = []

        MAX_WORKERS = int(os.environ.get('SCAN_MAX_WORKERS', 4))
        lock = threading.Lock()
        # Use a single-element list as a mutable counter (avoids nonlocal for Python 2 compat)
        completed_count = [0]

        def _run_plugin_concurrent(plugin):
            """Run a single plugin and return (plugin, findings, status)."""
            # Memory guard — check before running this plugin
            mem_pct = _memory_usage_percent()
            if mem_pct > 80.0:
                logger.warning(
                    "Memory usage %.1f%% exceeds 80%% threshold. "
                    "Skipping plugin %s for scan %d.",
                    mem_pct, plugin.name, scan_id,
                )
                return plugin, [], 'skipped'

            plugin_findings: List = []
            plugin_status = 'error'
            try:
                plugin_findings = plugin.scan(scan.target.url, config)
                plugin_status = 'complete'
                logger.debug(
                    "Plugin %s found %d issue(s) for scan %d",
                    plugin.name, len(plugin_findings), scan_id,
                )
            except SoftTimeLimitExceeded:
                raise
            except Exception as exc:
                plugin_status = 'error'
                logger.error(
                    "Plugin %s error during scan %d: %s",
                    plugin.name, scan_id, exc,
                )
                # --- Retry with fresh stealth headers on failure ---
                try:
                    logger.info(
                        "Retrying plugin %s for scan %d with fresh stealth headers",
                        plugin.name, scan_id,
                    )
                    retry_config = dict(config)
                    retry_config['enable_stealth'] = True
                    retry_config['timeout'] = config.get('timeout', 15) + 10
                    time.sleep(random.uniform(1.0, 3.0))
                    plugin_findings = plugin.scan(scan.target.url, retry_config)
                    plugin_status = 'complete'
                    logger.info(
                        "Retry succeeded for plugin %s on scan %d: %d finding(s)",
                        plugin.name, scan_id, len(plugin_findings),
                    )
                except SoftTimeLimitExceeded:
                    raise
                except Exception as retry_exc:
                    plugin_status = 'error'
                    logger.error(
                        "Retry also failed for plugin %s on scan %d: %s",
                        plugin.name, scan_id, retry_exc,
                    )
            return plugin, plugin_findings, plugin_status

        # Check memory before submitting — abort if already over threshold
        mem_pct = _memory_usage_percent()
        if mem_pct > 80.0:
            logger.warning(
                "Memory usage %.1f%% exceeds 80%% threshold before scan %d started.",
                mem_pct, scan_id,
            )
            if scan.warnings is None:
                scan.warnings = []
            scan.warnings.append(
                f'Scan stopped early: memory usage {mem_pct:.1f}% exceeded 80% threshold.'
            )
            plugins = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_plugin = {
                executor.submit(_run_plugin_concurrent, plugin): plugin
                for plugin in plugins
            }

            for future in concurrent.futures.as_completed(future_to_plugin):
                try:
                    plugin, plugin_findings, plugin_status = future.result()
                except SoftTimeLimitExceeded:
                    raise
                except Exception as exc:
                    plugin = future_to_plugin[future]
                    plugin_findings = []
                    plugin_status = 'error'
                    logger.error(
                        "Unexpected error running plugin %s for scan %d: %s",
                        plugin.name, scan_id, exc,
                    )

                with lock:
                    all_findings.extend(plugin_findings)
                    completed_count[0] += 1
                    current = completed_count[0]
                    findings_so_far = len(all_findings)

                if self.request.id:
                    send_progress_update(
                        task_id=task_id,
                        current=current,
                        total=total_plugins,
                        status=f'Plugin {plugin.name} {plugin_status} ({current}/{total_plugins})',
                        extra={
                            'plugin_name': plugin.name,
                            'plugin_status': plugin_status,
                            'plugin_findings': len(plugin_findings),
                            'findings_so_far': findings_so_far,
                        },
                    )

        # Persist findings to the database
        engine.save_findings_to_db(scan, all_findings)

        # Update scan status to completed
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()

        vulnerabilities_count = scan.vulnerabilities.count()
        logger.info(f"Scan {scan_id} completed successfully. Found {vulnerabilities_count} vulnerabilities.")

        # Run SQL Injection testing if enabled
        if getattr(scan, 'enable_sqli_testing', False):
            try:
                from scanner.views import _run_sqli_testing
                _run_sqli_testing(scan)
            except Exception as sqli_exc:
                logger.warning(f"SQLi testing failed for scan {scan_id}: {sqli_exc}")

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
            scan.error_message = 'Scan exceeded time limit'
        scan.completed_at = timezone.now()
        scan.save()

        return {
            'scan_id': scan_id,
            'status': scan.status,
            'error': 'Scan exceeded time limit',
            'vulnerabilities_found': vulnerabilities_count,
            'task_id': task_id,
        }

    except Terminated:
        logger.info(f"Scan {scan_id} was cancelled by user.")
        scan.status = 'cancelled'
        scan.completed_at = timezone.now()
        scan.save(update_fields=['status', 'completed_at'])
        return {
            'scan_id': scan_id,
            'status': 'cancelled',
            'task_id': task_id,
        }

    except Exception as e:
        logger.error(f"Error during scan {scan_id}: {str(e)}", exc_info=True)
        scan.status = 'failed'
        scan.error_message = str(e)
        scan.completed_at = timezone.now()
        scan.save()

        return {
            'scan_id': scan_id,
            'status': 'failed',
            'error': str(e),
            'task_id': task_id,
        }


@shared_task(bind=True, name='scanner.async_stealth_scan_task', time_limit=7200, soft_time_limit=7100)
def async_stealth_scan_task(
    self,
    scan_id: int,
    scan_profile: str = 'balanced',
) -> Dict[str, Any]:
    """
    Celery task to perform a stealth-aware vulnerability scan using a named profile.

    Supported profiles (defined in :attr:`~scanner.scan_engine.ScanEngine.SCAN_PROFILES`):
    - ``'stealth'``    — slow, paranoid timing, maximum evasion
    - ``'balanced'``   — moderate timing, standard payloads  *(default)*
    - ``'aggressive'`` — no delays, maximum payloads
    - ``'quick'``      — fast, only high-severity checks

    The task has a generous 2-hour time limit to accommodate the stealth profile
    which inserts long delays between plugin executions.

    Args:
        scan_id: The database ID of the :class:`~scanner.models.Scan` to execute.
        scan_profile: Name of the scan profile to apply.

    Returns:
        Dictionary containing:
        - scan_id: The scan ID
        - status: Final status (``'completed'`` or ``'failed'``)
        - scan_profile: The profile used
        - vulnerabilities_found: Number of vulnerabilities discovered
        - task_id: The Celery task ID for tracking
    """
    task_id = self.request.id if self.request.id else 'eager-mode'
    logger.info(
        "Starting stealth scan task for scan %d (profile=%s, task_id=%s)",
        scan_id, scan_profile, task_id,
    )

    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error("Scan %d not found", scan_id)
        return {
            'scan_id': scan_id,
            'status': 'failed',
            'scan_profile': scan_profile,
            'error': f'Scan {scan_id} not found',
            'task_id': task_id,
        }

    scan.status = 'running'
    scan.save()

    try:
        from scanner.scan_engine import ScanEngine

        engine = ScanEngine()
        findings = engine.scan_with_profile(scan.target.url, profile_name=scan_profile)
        engine.save_findings_to_db(scan, findings)

        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()

        vulnerabilities_count = scan.vulnerabilities.count()
        logger.info(
            "Stealth scan %d completed (profile=%s). Found %d vulnerabilities.",
            scan_id, scan_profile, vulnerabilities_count,
        )

        return {
            'scan_id': scan_id,
            'status': 'completed',
            'scan_profile': scan_profile,
            'message': f"Stealth scan completed using '{scan_profile}' profile",
            'vulnerabilities_found': vulnerabilities_count,
            'task_id': task_id,
        }

    except SoftTimeLimitExceeded:
        logger.warning("Soft time limit reached for stealth scan %d.", scan_id)
        vulnerabilities_count = scan.vulnerabilities.count()
        if vulnerabilities_count > 0:
            if scan.warnings is None:
                scan.warnings = []
            scan.warnings.append('Stealth scan exceeded time limit. Results may be incomplete.')
            scan.status = 'completed'
        else:
            scan.status = 'failed'
            scan.error_message = 'Scan exceeded time limit'
        scan.completed_at = timezone.now()
        scan.save()

        return {
            'scan_id': scan_id,
            'status': scan.status,
            'scan_profile': scan_profile,
            'error': 'Scan exceeded time limit',
            'vulnerabilities_found': vulnerabilities_count,
            'task_id': task_id,
        }

    except Terminated:
        logger.info("Stealth scan %d was cancelled by user.", scan_id)
        scan.status = 'cancelled'
        scan.completed_at = timezone.now()
        scan.save(update_fields=['status', 'completed_at'])
        return {
            'scan_id': scan_id,
            'status': 'cancelled',
            'scan_profile': scan_profile,
            'task_id': task_id,
        }

    except Exception as exc:
        logger.error("Error during stealth scan %d: %s", scan_id, exc, exc_info=True)
        scan.status = 'failed'
        scan.error_message = str(exc)
        scan.completed_at = timezone.now()
        scan.save()

        return {
            'scan_id': scan_id,
            'status': 'failed',
            'scan_profile': scan_profile,
            'error': str(exc),
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
    except Terminated:
        logger.info(f"Exploit task for scan {scan_id} was cancelled by user.")
        results['status'] = 'cancelled'
    
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
    except Terminated:
        logger.info("Selected exploit task was cancelled by user.")
        results['status'] = 'cancelled'
    
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
