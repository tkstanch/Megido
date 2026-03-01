from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from .models import ScanTarget, Scan, Vulnerability, ExploitMedia
from django.utils import timezone
from django.conf import settings
import os
import logging
from celery.result import AsyncResult
from scanner.tasks import async_exploit_all_vulnerabilities, async_exploit_selected_vulnerabilities, async_scan_task
from scanner.config_defaults import get_default_proof_config

logger = logging.getLogger(__name__)


@api_view(['GET', 'POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_targets(request):
    """List or create scan targets"""
    if request.method == 'GET':
        targets = ScanTarget.objects.all()[:50]
        data = [{
            'id': target.id,
            'name': target.name,
            'url': target.url,
            'created_at': target.created_at.isoformat(),
        } for target in targets]
        return Response(data, status=200)
    
    elif request.method == 'POST':
        target = ScanTarget.objects.create(
            url=request.data.get('url'),
            name=request.data.get('name', '')
        )
        return Response({'id': target.id, 'message': 'Target created'}, status=201)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def start_scan(request, target_id):
    """
    Start a vulnerability scan on a target.
    
    This endpoint creates a scan and triggers an async Celery task to execute it.
    The scan runs in the background, allowing Gunicorn to respond immediately
    without blocking workers during long-running scans.
    
    Returns immediately with scan ID and 'pending' status.
    Clients should poll /api/scans/<scan_id>/results/ for progress and results.
    """
    try:
        target = ScanTarget.objects.get(id=target_id)
        
        # Create scan with 'pending' status
        scan = Scan.objects.create(target=target, status='pending')
        
        # Trigger Celery task to run scan in background
        task = async_scan_task.delay(scan.id)
        
        # Return immediately with scan ID and task ID
        return Response({
            'id': scan.id,
            'status': 'pending',
            'message': 'Scan started. Poll /api/scans/{}/results/ for progress.'.format(scan.id),
            'task_id': task.id
        }, status=201)
            
    except ScanTarget.DoesNotExist:
        return Response({'error': 'Target not found'}, status=404)
    except Exception as e:
        # If Celery task fails to start, log and return error
        logger.error(f"Failed to start scan: {str(e)}", exc_info=True)
        return Response({'error': f'Failed to start scan: {str(e)}'}, status=500)


def perform_basic_scan(scan, url, scan_profile=None, use_async=False, crawl_first=False):
    """
    Perform basic vulnerability scanning using the plugin-based scan engine.

    This function has been refactored to use the modular plugin architecture.
    The old hardcoded checks have been moved into individual scan plugins.

    Args:
        scan: Scan model instance.
        url: Target URL string.
        scan_profile: Optional profile name (``quick``, ``standard``, ``full``,
            ``api``, ``owasp_top10``, ``stealth``).  When provided the profile
            config is merged with the base scan config.
        use_async: If True, use AsyncScanEngine for concurrent plugin execution.
        crawl_first: If True, crawl the target URL and scan all discovered pages.

    Note: This maintains backward compatibility with existing scan API and UI.
    """
    # Get SSL verification setting from environment (default to False for security testing)
    verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'

    try:
        # Build base config
        config = get_default_proof_config()
        config.update({
            'verify_ssl': verify_ssl,
            'timeout': 10,
        })

        # Merge scan profile overrides (if requested)
        if scan_profile:
            try:
                from scanner.scan_profiles import get_profile
                profile_config = get_profile(scan_profile)
                config.update(profile_config)
            except Exception as e:
                logger.warning(f"Could not load scan profile '{scan_profile}': {e}")

        # Choose engine
        if use_async:
            try:
                from scanner.async_scan_engine import AsyncScanEngine
                engine = AsyncScanEngine(
                    max_concurrent_plugins=config.get('max_concurrent_plugins', 5),
                    max_concurrent_requests=config.get('max_concurrent_requests', 10),
                )
            except Exception as e:
                logger.warning(f"AsyncScanEngine unavailable ({e}), using ScanEngine")
                from scanner.scan_engine import get_scan_engine
                engine = get_scan_engine()
        else:
            from scanner.scan_engine import get_scan_engine
            engine = get_scan_engine()

        # Optionally crawl first and scan every discovered URL
        all_findings = []
        urls_to_scan = [url]

        if crawl_first:
            try:
                from scanner.crawler import Crawler
                crawler = Crawler(
                    max_depth=config.get('crawl_depth', 2),
                    max_urls=config.get('crawl_max_urls', 50),
                    verify_ssl=verify_ssl,
                )
                crawl_result = crawler.crawl(url, config)
                if crawl_result.discovered_urls:
                    urls_to_scan = crawl_result.discovered_urls
                    logger.info(
                        f"Crawler discovered {len(urls_to_scan)} URL(s) — scanning all."
                    )
            except Exception as e:
                logger.warning(f"Crawler failed ({e}), scanning seed URL only")

        # Run the scan on each URL
        enabled_plugins = config.get('enabled_plugins')
        for target_url in urls_to_scan:
            try:
                if use_async:
                    # AsyncScanEngine: collect all findings then save in batch below
                    if enabled_plugins:
                        findings = engine.scan_with_plugins(target_url, enabled_plugins, config)
                    else:
                        findings = engine.scan(target_url, config)
                    all_findings.extend(findings)
                else:
                    # ScanEngine: iterate plugins and save findings incrementally after each plugin
                    if enabled_plugins:
                        plugin_list = [
                            engine.registry.get_plugin(pid)
                            for pid in enabled_plugins
                            if engine.registry.get_plugin(pid)
                        ]
                    else:
                        plugin_list = engine.registry.get_all_plugins()
                    for plugin in plugin_list:
                        try:
                            plugin_findings = plugin.scan(target_url, config)
                            if plugin_findings:
                                engine.save_findings_to_db(scan, plugin_findings)
                                logger.info(
                                    f"Plugin {plugin.name}: saved {len(plugin_findings)} "
                                    f"finding(s) for {target_url}"
                                )
                        except Exception as e:
                            logger.error(
                                f"Error running plugin {plugin.name} on {target_url}: {e}"
                            )
            except Exception as e:
                logger.error(f"Error scanning {target_url}: {e}")

        # For async engine path: deduplicate, correlate, then save in batch
        if use_async:
            try:
                from scanner.deduplication import deduplicate_and_correlate
                all_findings = deduplicate_and_correlate(all_findings)
            except Exception as e:
                logger.warning(f"Deduplication failed ({e}), using raw findings")

            # Save findings to database
            engine.save_findings_to_db(scan, all_findings)

        # Apply advanced features to all vulnerabilities after scanning
        try:
            from scanner.exploit_integration import apply_advanced_features_to_scan
            apply_advanced_features_to_scan(scan.id)
        except Exception as e:
            print(f"Warning: Could not apply advanced features: {e}")

    except Exception as e:
        print(f"Error during scan: {e}")
        # Re-raise exception for upstream handling
        raise


@api_view(['GET'])
@permission_classes([AllowAny])
def scan_results(request, scan_id):
    """Get results of a scan"""
    try:
        scan = Scan.objects.get(id=scan_id)
        vulnerabilities = scan.vulnerabilities.all()
        
        # Filter false positives by default unless explicitly requested
        include_false_positives = request.GET.get('include_false_positives', 'false').lower() == 'true'
        if not include_false_positives:
            vulnerabilities = vulnerabilities.exclude(false_positive_status='false_positive')
        
        # Option to filter by verified status
        verified_only = request.GET.get('verified_only', 'false').lower() == 'true'
        if verified_only:
            vulnerabilities = vulnerabilities.filter(verified=True)
        
        # Order by risk score descending by default
        vulnerabilities = vulnerabilities.order_by('-risk_score', '-discovered_at')
        
        data = {
            'scan_id': scan.id,
            'status': scan.status,
            'started_at': scan.started_at.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'warnings': scan.warnings if hasattr(scan, 'warnings') else [],
            'vulnerabilities': [{
                'id': vuln.id,
                'type': vuln.get_vulnerability_type_display(),
                'vulnerability_type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'url': vuln.url,
                'parameter': vuln.parameter,
                'description': vuln.description,
                'evidence': vuln.evidence,
                'remediation': vuln.remediation,
                'exploited': vuln.exploited,
                'exploit_status': vuln.exploit_status,
                'exploit_result': vuln.exploit_result,
                # Advanced features
                'verified': vuln.verified,
                'proof_of_impact': vuln.proof_of_impact,
                'risk_score': vuln.risk_score,
                'risk_level': vuln.risk_level,
                'confidence_score': vuln.confidence_score,
                'false_positive_status': vuln.false_positive_status,
                'compliance_violations': vuln.compliance_violations,
                'remediation_priority': vuln.remediation_priority,
                'remediation_effort': vuln.remediation_effort,
                # Discovery data
                'successful_payloads': vuln.successful_payloads,
                'repeater_data': vuln.repeater_data,
                'http_traffic': vuln.http_traffic,
                'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                # Visual proof media
                'visual_proof_path': vuln.visual_proof_path,
                'visual_proof_type': vuln.visual_proof_type,
                'visual_proof_status': vuln.visual_proof_status if hasattr(vuln, 'visual_proof_status') else 'not_attempted',
                'exploit_media': _serialize_exploit_media(vuln.exploit_media.all()),
                # Step-by-step PoC data
                'poc_steps': _parse_poc_steps(vuln.poc_steps_json),
                'poc_html_report_path': vuln.poc_html_report_path,
                'poc_step_count': vuln.poc_step_count,
            } for vuln in vulnerabilities]
        }
        return Response(data, status=200)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)


def _parse_poc_steps(poc_steps_json):
    """
    Parse poc_steps_json TextField into a Python list.

    Args:
        poc_steps_json: JSON string stored in the poc_steps_json field, or None

    Returns:
        List of step dicts, or empty list if unavailable/invalid
    """
    if not poc_steps_json:
        return []
    try:
        import json
        steps = json.loads(poc_steps_json)
        return steps if isinstance(steps, list) else []
    except (ValueError, TypeError):
        return []


def _serialize_exploit_media(media_queryset):
    """
    Serialize ExploitMedia queryset to dictionary format.
    
    Args:
        media_queryset: QuerySet of ExploitMedia objects
        
    Returns:
        List of dictionaries with media information
    """
    media_url_base = getattr(settings, 'MEDIA_URL', '/media/')
    
    return [{
        'id': media.id,
        'media_type': media.media_type,
        'title': media.title,
        'description': media.description,
        'file_url': f"{media_url_base}{media.file_path}",  # file_path already includes exploit_proofs/
        'file_name': media.file_name,
        'file_size': media.file_size,
        'mime_type': media.mime_type,
        'width': media.width,
        'height': media.height,
        'duration_seconds': media.duration_seconds,
        'frame_count': media.frame_count,
        'exploit_step': media.exploit_step,
        'payload_used': media.payload_used,
        'capture_timestamp': media.capture_timestamp.isoformat(),
        'sequence_order': media.sequence_order,
    } for media in media_queryset]


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def exploit_vulnerabilities(request, scan_id):
    """
    Trigger background exploitation of vulnerabilities from a scan.
    
    Request body should contain:
    - action: 'all' to exploit all vulnerabilities, 'selected' for specific ones
    - vulnerability_ids: (optional) list of vulnerability IDs when action='selected'
    - enable_visual_proof: (optional) boolean to enable/disable visual proof capture (default: True)
    
    Returns:
    - task_id: Celery task ID for polling status
    - message: Confirmation message
    """
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)
    
    action = request.data.get('action', 'all')
    
    # Read enable_visual_proof from request, default to True for backward compatibility
    enable_visual_proof = request.data.get('enable_visual_proof', True)
    # Convert string 'true'/'false' to boolean if needed
    if isinstance(enable_visual_proof, str):
        enable_visual_proof = enable_visual_proof.lower() == 'true'
    
    # Configuration for exploit attempts
    config = {
        'timeout': 30,
        'verify_ssl': False,
        'enable_exploitation': True,
        'enable_visual_proof': enable_visual_proof,
    }
    
    if action == 'all':
        # Submit Celery task to exploit all vulnerabilities in the scan
        task = async_exploit_all_vulnerabilities.delay(scan_id, config)
        return Response({
            'task_id': task.id,
            'message': 'Exploitation started in background',
            'status_url': f'/scanner/api/exploit_status/{task.id}/'
        }, status=202)
    
    elif action == 'selected':
        # Exploit only selected vulnerabilities
        vulnerability_ids = request.data.get('vulnerability_ids', [])
        
        if not vulnerability_ids:
            return Response({'error': 'No vulnerability IDs provided'}, status=400)
        
        # Validate that all IDs belong to this scan
        valid_ids = list(scan.vulnerabilities.filter(
            id__in=vulnerability_ids
        ).values_list('id', flat=True))
        
        if len(valid_ids) != len(vulnerability_ids):
            return Response({
                'error': 'Some vulnerability IDs do not belong to this scan'
            }, status=400)
        
        # Submit Celery task to exploit selected vulnerabilities
        task = async_exploit_selected_vulnerabilities.delay(valid_ids, config)
        return Response({
            'task_id': task.id,
            'message': 'Exploitation started in background',
            'status_url': f'/scanner/api/exploit_status/{task.id}/'
        }, status=202)
    
    else:
        return Response({'error': 'Invalid action. Use "all" or "selected"'}, status=400)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def exploit_status(request, task_id):
    """
    Check the status of a background exploitation task.
    
    Returns:
    - state: Task state (PENDING, PROGRESS, SUCCESS, FAILURE)
    - current: Current progress (if in PROGRESS state)
    - total: Total items to process (if in PROGRESS state)
    - status: Status message (if in PROGRESS state)
    - result: Final results (if SUCCESS state)
    - error: Error message (if FAILURE state)
    """
    task_result = AsyncResult(task_id)
    
    response_data = {
        'task_id': task_id,
        'state': task_result.state,
    }
    
    if task_result.state == 'PENDING':
        # Task is waiting to be executed
        response_data['status'] = 'Task is pending...'
    
    elif task_result.state == 'PROGRESS':
        # Task is in progress
        response_data.update({
            'current': task_result.info.get('current', 0),
            'total': task_result.info.get('total', 0),
            'status': task_result.info.get('status', 'Processing...')
        })
    
    elif task_result.state == 'SUCCESS':
        # Task completed successfully
        response_data['result'] = task_result.result
        response_data['status'] = 'Completed'
    
    elif task_result.state == 'FAILURE':
        # Task failed with an error
        response_data['error'] = str(task_result.info)
        response_data['status'] = 'Failed'
    
    else:
        # Any other state
        response_data['status'] = str(task_result.state)
    
    return Response(response_data, status=200)


@api_view(['GET'])
@permission_classes([AllowAny])
def vulnerability_detail(request, vuln_id):
    """
    Get detailed information about a specific vulnerability including all exploit media.
    
    Args:
        vuln_id: Vulnerability ID
        
    Returns:
        Detailed vulnerability information with all exploit media
    """
    try:
        vuln = Vulnerability.objects.get(id=vuln_id)
        
        # Get all exploit media ordered by sequence
        exploit_media = vuln.exploit_media.all().order_by('sequence_order', 'capture_timestamp')
        
        data = {
            'id': vuln.id,
            'type': vuln.get_vulnerability_type_display(),
            'vulnerability_type': vuln.vulnerability_type,
            'severity': vuln.severity,
            'url': vuln.url,
            'parameter': vuln.parameter,
            'description': vuln.description,
            'evidence': vuln.evidence,
            'remediation': vuln.remediation,
            'discovered_at': vuln.discovered_at.isoformat(),
            # Exploit information
            'exploited': vuln.exploited,
            'exploit_status': vuln.exploit_status,
            'exploit_result': vuln.exploit_result,
            'exploit_attempted_at': vuln.exploit_attempted_at.isoformat() if vuln.exploit_attempted_at else None,
            # Advanced features
            'verified': vuln.verified,
            'proof_of_impact': vuln.proof_of_impact,
            'risk_score': vuln.risk_score,
            'risk_level': vuln.risk_level,
            'confidence_score': vuln.confidence_score,
            'false_positive_status': vuln.false_positive_status,
            'false_positive_reason': vuln.false_positive_reason,
            'reviewed_by': vuln.reviewed_by,
            'reviewed_at': vuln.reviewed_at.isoformat() if vuln.reviewed_at else None,
            'compliance_violations': vuln.compliance_violations,
            'remediation_priority': vuln.remediation_priority,
            'remediation_effort': vuln.remediation_effort,
            # Legacy visual proof (single file)
            'visual_proof_path': vuln.visual_proof_path,
            'visual_proof_type': vuln.visual_proof_type,
            'visual_proof_size': vuln.visual_proof_size,
            # New multiple media support
            'exploit_media': _serialize_exploit_media(exploit_media),
            'exploit_media_count': exploit_media.count(),
        }
        return Response(data, status=200)
    except Vulnerability.DoesNotExist:
        return Response({'error': 'Vulnerability not found'}, status=404)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def apply_advanced_features(request, scan_id):
    """
    Apply advanced scanner features to all vulnerabilities in a scan.
    
    This includes:
    - Risk scoring
    - False positive detection
    - Compliance mapping
    - Remediation suggestions
    
    Returns:
    - Results of applying advanced features
    """
    from scanner.exploit_integration import apply_advanced_features_to_scan
    
    try:
        results = apply_advanced_features_to_scan(scan_id)
        return Response(results, status=200)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@login_required
def scanner_dashboard(request):
    """Dashboard view for the scanner"""
    return render(request, 'scanner/dashboard.html')
