from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db.models import Count, Q
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
import json
import logging
import os
import tempfile

from .models import SQLInjectionTask, SQLInjectionResult
from .tasks import sql_injection_task, sql_injection_task_with_selection
from .sqli_engine import SQLInjectionEngine
from .param_discovery import ParameterDiscoveryEngine
from .oob_payloads import OOBPayloadGenerator, DatabaseType as OOBDatabaseType
from response_analyser.analyse import save_vulnerability
from .client_side import (
    ClientSideScanOrchestrator,
    ScanConfiguration,
    ScanType
)
from .client_side.orchestrator import ScanResults

# Configure logging
logger = logging.getLogger(__name__)

# Maximum length for OOB payload strings stored in the database.
# Keeps stored evidence concise and prevents overly large DB entries.
_OOB_PAYLOAD_MAX_STORE_LENGTH = 200


def _get_default_data_to_exfiltrate(db_type):
    """
    Helper function to get default data expression for OOB exfiltration.
    
    Args:
        db_type: OOBDatabaseType enum value or None
        
    Returns:
        Default SQL expression to exfiltrate based on database type
    """
    # Default expressions that work across databases
    DEFAULT_EXFIL_EXPRESSIONS = {
        OOBDatabaseType.MSSQL: '@@version',
        OOBDatabaseType.ORACLE: 'user',
        OOBDatabaseType.MYSQL: '@@version'
    }
    
    if db_type is None:
        # If no specific DB type, use generic expression
        return 'user'
    
    return DEFAULT_EXFIL_EXPRESSIONS.get(db_type, 'user')


def _db_type_to_oob_db_type(db_type_str: str):
    """
    Map a free-form database type string (as stored in SQLInjectionResult.database_type)
    to an OOBDatabaseType enum value, or None if unrecognised.

    Args:
        db_type_str: String such as 'mysql', 'mssql', 'oracle', 'unknown', etc.

    Returns:
        OOBDatabaseType enum member, or None.
    """
    mapping = {
        'mysql': OOBDatabaseType.MYSQL,
        'mariadb': OOBDatabaseType.MYSQL,
        'mssql': OOBDatabaseType.MSSQL,
        'sqlserver': OOBDatabaseType.MSSQL,
        'oracle': OOBDatabaseType.ORACLE,
    }
    return mapping.get((db_type_str or '').lower().strip())


def dashboard(request):
    """
    Dashboard view showing SQL injection attack tasks and statistics.
    """
    tasks = SQLInjectionTask.objects.all()
    
    # Filter by status
    status_filter = request.GET.get('status')
    if status_filter:
        tasks = tasks.filter(status=status_filter)
    
    # Get statistics
    total_tasks = SQLInjectionTask.objects.count()
    pending_tasks = SQLInjectionTask.objects.filter(status='pending').count()
    running_tasks = SQLInjectionTask.objects.filter(status='running').count()
    completed_tasks = SQLInjectionTask.objects.filter(status='completed').count()
    failed_tasks = SQLInjectionTask.objects.filter(status='failed').count()
    
    total_vulns = SQLInjectionResult.objects.count()
    exploitable_vulns = SQLInjectionResult.objects.filter(is_exploitable=True).count()
    
    # Get recent results
    recent_results = SQLInjectionResult.objects.select_related('task').order_by('-detected_at')[:10]
    
    # Union-based PoC results with stored HTML evidence
    union_poc_results = (
        SQLInjectionResult.objects
        .select_related('task')
        .filter(injection_type='union_based')
        .order_by('-detected_at')[:20]
    )

    # Results with OOB findings generated
    oob_results = (
        SQLInjectionResult.objects
        .select_related('task')
        .exclude(oob_findings__isnull=True)
        .order_by('-detected_at')[:20]
    )

    # Injection type statistics
    injection_stats = SQLInjectionResult.objects.values('injection_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    context = {
        'tasks': tasks[:20],  # Limit for performance
        'total_tasks': total_tasks,
        'pending_tasks': pending_tasks,
        'running_tasks': running_tasks,
        'completed_tasks': completed_tasks,
        'failed_tasks': failed_tasks,
        'total_vulns': total_vulns,
        'exploitable_vulns': exploitable_vulns,
        'recent_results': recent_results,
        'union_poc_results': union_poc_results,
        'oob_results': oob_results,
        'injection_stats': injection_stats,
        'status_choices': SQLInjectionTask.STATUS_CHOICES,
    }
    
    return render(request, 'sql_attacker/dashboard.html', context)


def task_create(request):
    """
    Form view for creating a new SQL injection attack task.
    """
    if request.method == 'POST':
        # Parse form data
        target_url = request.POST.get('target_url')
        http_method = request.POST.get('http_method', 'GET')
        
        # Parse JSON fields
        get_params = request.POST.get('get_params', '{}')
        post_params = request.POST.get('post_params', '{}')
        cookies = request.POST.get('cookies', '{}')
        headers = request.POST.get('headers', '{}')
        
        try:
            get_params = json.loads(get_params) if get_params else {}
            post_params = json.loads(post_params) if post_params else {}
            cookies = json.loads(cookies) if cookies else {}
            headers = json.loads(headers) if headers else {}
        except json.JSONDecodeError:
            return render(request, 'sql_attacker/task_create.html', {
                'error': 'Invalid JSON format in parameters'
            })
        
        # Create task
        task = SQLInjectionTask.objects.create(
            target_url=target_url,
            http_method=http_method,
            get_params=get_params,
            post_params=post_params,
            cookies=cookies,
            headers=headers,
            enable_error_based=request.POST.get('enable_error_based') == 'on',
            enable_time_based=request.POST.get('enable_time_based') == 'on',
            enable_exploitation=request.POST.get('enable_exploitation') == 'on',
            auto_discover_params=request.POST.get('auto_discover_params', 'on') == 'on',
            require_confirmation=request.POST.get('require_confirmation') == 'on',  # NEW
            use_random_delays=request.POST.get('use_random_delays') == 'on',
            min_delay=float(request.POST.get('min_delay', 0.5)),
            max_delay=float(request.POST.get('max_delay', 2.0)),
            randomize_user_agent=request.POST.get('randomize_user_agent') == 'on',
            use_payload_obfuscation=request.POST.get('use_payload_obfuscation') == 'on',
            # NEW: Enhanced stealth options
            randomize_headers=request.POST.get('randomize_headers', 'on') == 'on',
            enable_jitter=request.POST.get('enable_jitter', 'on') == 'on',
            max_requests_per_minute=int(request.POST.get('max_requests_per_minute', 20)),
            max_retries=int(request.POST.get('max_retries', 3)),
            # OOB configuration (enabled by default)
            enable_oob=request.POST.get('enable_oob', 'on') == 'on',
            oob_attacker_host=request.POST.get('oob_attacker_host', '').strip(),
            oob_max_payloads=int(request.POST.get('oob_max_payloads', 5)),
            oob_max_retries=int(request.POST.get('oob_max_retries', 2)),
            oob_exfil_expression=request.POST.get('oob_exfil_expression', '').strip(),
        )
        
        # Execute task in background if requested
        if request.POST.get('execute_now') == 'on':
            sql_injection_task.delay(task.id)
        
        return redirect('sql_attacker:task_detail', pk=task.id)
    
    return render(request, 'sql_attacker/task_create.html', {
        'method_choices': SQLInjectionTask.METHOD_CHOICES,
    })


def task_detail(request, pk):
    """
    Detail view for a specific SQL injection attack task.
    """
    task = get_object_or_404(SQLInjectionTask, pk=pk)
    results = task.results.all()
    
    context = {
        'task': task,
        'results': results,
    }
    
    return render(request, 'sql_attacker/task_detail.html', context)


def task_list(request):
    """
    List view for all SQL injection attack tasks.
    """
    tasks = SQLInjectionTask.objects.all()
    
    # Apply filters
    status_filter = request.GET.get('status')
    if status_filter:
        tasks = tasks.filter(status=status_filter)
    
    search = request.GET.get('search')
    if search:
        tasks = tasks.filter(target_url__icontains=search)
    
    context = {
        'tasks': tasks[:100],  # Limit for performance
        'status_choices': SQLInjectionTask.STATUS_CHOICES,
    }
    
    return render(request, 'sql_attacker/task_list.html', context)


def result_detail(request, pk):
    """
    Detail view for a specific SQL injection result.
    """
    result = get_object_or_404(SQLInjectionResult, pk=pk)
    
    context = {
        'result': result,
    }
    
    return render(request, 'sql_attacker/result_detail.html', context)


def execute_task(task_id):
    """
    Execute SQL injection attack task in background.
    This function is called in a separate thread.
    """
    try:
        task = SQLInjectionTask.objects.get(id=task_id)
        task.status = 'running'
        task.started_at = timezone.now()
        task.save()
        
        # Configure engine with advanced features enabled
        config = {
            'use_random_delays': task.use_random_delays,
            'min_delay': task.min_delay,
            'max_delay': task.max_delay,
            'randomize_user_agent': task.randomize_user_agent,
            'use_payload_obfuscation': task.use_payload_obfuscation,
            'verify_ssl': False,  # For security testing
            'enable_advanced_payloads': True,  # Enable advanced payloads
            'enable_false_positive_reduction': True,  # Enable FP reduction
            'enable_impact_demonstration': True,  # Enable impact demo
            'enable_stealth': True,  # NEW: Enable stealth engine
            'max_requests_per_minute': task.max_requests_per_minute,  # NEW
            'enable_jitter': task.enable_jitter,  # NEW
            'randomize_headers': task.randomize_headers,  # NEW
            'max_retries': task.max_retries,  # NEW
        }
        
        engine = SQLInjectionEngine(config)
        
        # Prepare request parameters
        params = task.get_params_dict()
        data = task.get_post_dict()
        cookies = task.get_cookies_dict()
        headers = task.get_headers_dict()
        
        # Perform automatic parameter discovery if enabled
        discovered_params_list = []
        if task.auto_discover_params:
            try:
                logger.info(f"Starting parameter discovery for {task.target_url}")
                discovery_engine = ParameterDiscoveryEngine(
                    timeout=30, 
                    verify_ssl=False
                )
                
                merged_params, discovered_params_list = discovery_engine.discover_parameters(
                    url=task.target_url,
                    method=task.http_method,
                    headers=headers
                )
                
                # Store discovered parameters in task
                task.discovered_params = [p.to_dict() for p in discovered_params_list]
                task.save()
                
                # NEW: Check if confirmation is required
                if task.require_confirmation and discovered_params_list:
                    logger.info(f"Pausing for confirmation - discovered {len(discovered_params_list)} parameters")
                    task.status = 'awaiting_confirmation'
                    task.awaiting_confirmation = True
                    task.save()
                    return  # Exit and wait for user confirmation
                
                # Merge discovered parameters with manual parameters
                # Discovered GET params
                if merged_params.get('GET'):
                    for param_name, param_value in merged_params['GET'].items():
                        if param_name not in params:
                            params[param_name] = param_value
                
                # Discovered POST params
                if merged_params.get('POST'):
                    for param_name, param_value in merged_params['POST'].items():
                        if param_name not in data:
                            data[param_name] = param_value
                
                logger.info(f"Discovered {len(discovered_params_list)} parameters. "
                          f"Total GET params: {len(params)}, Total POST params: {len(data)}")
                
            except Exception as e:
                logger.error(f"Parameter discovery failed: {e}", exc_info=True)
                # Continue with manual parameters only
        
        # Merged parameters dict for evidence capture.
        # POST (data) keys take precedence over GET (params) if names collide.
        merged_params = {**params, **data}

        # Run attack with comprehensive evidence collection
        evidence_result = engine.execute_attack_with_evidence(
            task=task,
            params_to_test=merged_params,
            enable_visual_capture=True,
        )
        findings = evidence_result.get('_raw_findings', [])
        visual_evidence = evidence_result.get('visual_evidence', {})
        all_injection_points = evidence_result.get('all_injection_points', [])
        successful_payloads = evidence_result.get('successful_payloads', {})
        extracted_sensitive_data = evidence_result.get('extracted_sensitive_data', {})

        # Store results
        vulnerabilities_count = 0
        oob_payloads_generated = 0  # rate-limit counter across all findings
        for finding in findings:
            exploitation = finding.pop('exploitation', {})
            impact_analysis = finding.pop('impact_analysis', {})
            
            # Determine parameter source
            param_name = finding.get('vulnerable_parameter', 'unknown')
            param_method = finding.get('parameter_type', 'GET')
            parameter_source = 'manual'  # Default
            
            # Check if this param was discovered
            for discovered_param in discovered_params_list:
                if (discovered_param.name == param_name and 
                    discovered_param.method == param_method):
                    parameter_source = discovered_param.source
                    break
            
            # Determine severity from impact analysis or default
            severity = finding.get('severity', impact_analysis.get('severity', 'critical'))
            risk_score = finding.get('risk_score', impact_analysis.get('risk_score', 50))
            confidence_score = finding.get('confidence_score', 0.7)

            # Build visual evidence data for this result
            screenshots_data = visual_evidence.get('screenshots', [])
            gif_path = visual_evidence.get('gif')
            timeline_data = visual_evidence.get('timeline', [])
            
            create_kwargs = dict(
                task=task,
                injection_type=finding.get('injection_type', 'error_based'),
                vulnerable_parameter=param_name,
                parameter_type=param_method,
                parameter_source=parameter_source,
                test_payload=finding.get('test_payload', ''),
                detection_evidence=finding.get('detection_evidence', ''),
                request_data=finding.get('request_data', {}),
                response_data=finding.get('response_data', {}),
                is_exploitable=exploitation.get('is_exploitable', False) or impact_analysis.get('exploitable', False),
                database_type=finding.get('database_type', 'unknown'),
                database_version=exploitation.get('database_version', '') or impact_analysis.get('extracted_info', {}).get('database_version', ''),
                current_database=exploitation.get('current_database', '') or impact_analysis.get('extracted_info', {}).get('current_database', ''),
                current_user=exploitation.get('current_user', '') or impact_analysis.get('extracted_info', {}).get('database_user', ''),
                extracted_tables=exploitation.get('extracted_tables', []) or impact_analysis.get('extracted_info', {}).get('schema', {}).get('tables', []),
                extracted_data=exploitation.get('extracted_data', {}) or impact_analysis.get('extracted_info', {}).get('sample_data', []),
                severity=severity,
                confidence_score=confidence_score,
                risk_score=risk_score,
                impact_analysis=impact_analysis,
                proof_of_concept=impact_analysis.get('proof_of_concept', []),
                # New visual evidence and comprehensive data fields
                screenshots=screenshots_data or None,
                evidence_timeline=timeline_data or None,
                all_injection_points=all_injection_points or None,
                successful_payloads=successful_payloads or None,
                extracted_sensitive_data=extracted_sensitive_data or None,
            )
            if gif_path:
                create_kwargs['gif_evidence'] = gif_path

            result = SQLInjectionResult.objects.create(**create_kwargs)
            vulnerabilities_count += 1

            # Generate OOB payloads for this finding if OOB is enabled.
            # Payloads are stored as evidence; they are NOT automatically
            # injected – a listener must be set up by the tester first.
            if task.enable_oob and oob_payloads_generated < task.oob_max_payloads:
                try:
                    oob_db_type = _db_type_to_oob_db_type(finding.get('database_type', ''))
                    exfil_expr = (
                        task.oob_exfil_expression.strip()
                        or _get_default_data_to_exfiltrate(oob_db_type)
                    )
                    oob_host = task.oob_attacker_host.strip() or 'ATTACKER_HOST_PLACEHOLDER'
                    oob_gen = OOBPayloadGenerator(attacker_host=oob_host, attacker_port=80)
                    raw_payloads = oob_gen.generate_all_payloads(oob_db_type, exfil_expr)
                    slots_remaining = task.oob_max_payloads - oob_payloads_generated
                    oob_findings_list = []
                    for _db, pl_list in raw_payloads.items():
                        for pl in pl_list[:slots_remaining]:
                            oob_findings_list.append({
                                'technique': pl.technique.value,
                                # Truncate payload to avoid storing excessive data
                                'payload': pl.payload[:_OOB_PAYLOAD_MAX_STORE_LENGTH],
                                'listener_type': pl.listener_type,
                                'requires_privileges': pl.requires_privileges,
                                'privilege_level': pl.privilege_level,
                                'description': pl.description[:_OOB_PAYLOAD_MAX_STORE_LENGTH],
                            })
                            oob_payloads_generated += 1
                            if oob_payloads_generated >= task.oob_max_payloads:
                                break
                        if oob_payloads_generated >= task.oob_max_payloads:
                            break
                    if oob_findings_list:
                        result.oob_findings = oob_findings_list
                        result.save(update_fields=['oob_findings'])
                except Exception as oob_exc:
                    logger.warning(
                        "OOB payload generation failed for result %s: %s", result.id, oob_exc
                    )

            # Generate union-based PoC HTML evidence if applicable
            if (
                result.injection_type == 'union_based'
                and result.is_exploitable
                and result.extracted_data
            ):
                try:
                    from .union_sql_injection import UnionSQLInjectionAttacker
                    db_info = {}
                    if result.database_version:
                        db_info['Database Version'] = result.database_version
                    if result.current_database:
                        db_info['Current Database'] = result.current_database
                    if result.current_user:
                        db_info['Database User'] = result.current_user
                    extracted = result.extracted_data
                    if isinstance(extracted, list) and extracted and isinstance(extracted[0], dict):
                        table_name = (
                            result.extracted_tables[0]
                            if isinstance(result.extracted_tables, list) and result.extracted_tables
                            else 'Unknown'
                        )
                        poc_html = UnionSQLInjectionAttacker.generate_html_evidence_table(
                            extracted_data=extracted,
                            table_name=table_name,
                            db_info=db_info if db_info else None,
                        )
                        result.union_poc_html = poc_html
                        result.save(update_fields=['union_poc_html'])
                except Exception as exc:
                    logger.warning("Could not generate union PoC HTML for result %s: %s", result.id, exc)

            # Forward to response_analyser
            try:
                forward_to_response_analyser(task, result)
            except Exception as e:
                logger.error(f"Error forwarding to response_analyser: {e}", exc_info=True)
        
        # Update task status
        task.status = 'completed'
        task.completed_at = timezone.now()
        task.vulnerabilities_found = vulnerabilities_count
        task.save()
        
    except Exception as e:
        # Handle errors
        logger.error(f"Task {task_id} failed: {e}", exc_info=True)
        task.status = 'failed'
        task.error_message = str(e)
        task.completed_at = timezone.now()
        task.save()


def forward_to_response_analyser(task, result):
    """
    Forward SQL injection findings to response_analyser app.
    Uses the save_vulnerability function from response_analyser.analyse module.
    """
    # Create a mock response object for response_analyser
    class MockResponse:
        def __init__(self, response_data):
            self.status_code = response_data.get('status_code', 200)
            self.headers = {}
            self.text = response_data.get('body_snippet', '')
    
    response_data = result.response_data or {}
    mock_response = MockResponse(response_data)
    
    # Prepare request details
    request_data = result.request_data or {}
    
    # Build notes with all extracted information
    notes = f"""SQL Injection detected via sql_attacker app.

Injection Type: {result.get_injection_type_display()}
Vulnerable Parameter: {result.vulnerable_parameter} ({result.parameter_type})
Test Payload: {result.test_payload}
Detection Evidence: {result.detection_evidence}

Database Type: {result.database_type}
"""
    
    if result.is_exploitable:
        notes += "\nExploitation Results:\n"
        if result.database_version:
            notes += f"- Database Version: {result.database_version}\n"
        if result.current_database:
            notes += f"- Current Database: {result.current_database}\n"
        if result.current_user:
            notes += f"- Current User: {result.current_user}\n"
        if result.extracted_tables:
            notes += f"- Extracted Tables: {', '.join(result.extracted_tables)}\n"
    
    # Save to response_analyser
    save_vulnerability(
        attack_type='sqli',
        target_url=task.target_url,
        payload=result.test_payload,
        response=mock_response,
        severity='critical',
        request_method=task.http_method,
        request_headers=task.get_headers_dict(),
        request_params=request_data,
        notes=notes
    )


def confirm_parameters(request, task_id):
    """
    View to confirm discovered parameters and continue or manually select parameters.
    """
    task = get_object_or_404(SQLInjectionTask, id=task_id)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'continue_automated':
            # User chose to continue with all discovered parameters
            task.awaiting_confirmation = False
            task.status = 'pending'  # Reset to pending so it can be executed
            task.save()
            
            # Re-execute the task in background
            sql_injection_task.delay(task.id)
            
            return redirect('sql_attacker:task_detail', pk=task.id)
            
        elif action == 'manual_selection':
            # User chose to manually select parameters
            selected_param_names = request.POST.getlist('selected_params')
            
            # Filter discovered params to only include selected ones
            if task.discovered_params:
                selected_params = [
                    p for p in task.discovered_params 
                    if p['name'] in selected_param_names
                ]
                task.selected_params = selected_params
            else:
                task.selected_params = []
            
            task.awaiting_confirmation = False
            task.status = 'pending'
            task.save()
            
            # Re-execute with selected parameters only
            sql_injection_task_with_selection.delay(task.id)
            
            return redirect('sql_attacker:task_detail', pk=task.id)
    
    # GET request - show confirmation page
    context = {
        'task': task,
        'discovered_params': task.discovered_params or [],
        'param_count': len(task.discovered_params) if task.discovered_params else 0,
    }
    
    return render(request, 'sql_attacker/confirm_parameters.html', context)


def execute_task_with_selection(task_id):
    """
    Execute task with manually selected parameters only.
    """
    try:
        task = SQLInjectionTask.objects.get(id=task_id)
        task.status = 'running'
        task.started_at = timezone.now()
        task.save()
        
        # Use selected parameters instead of all discovered parameters
        if task.selected_params:
            # Reconstruct discovered_params_list from selected_params
            from .param_discovery import DiscoveredParameter
            discovered_params_list = [
                DiscoveredParameter(
                    name=p['name'],
                    value=p.get('value', ''),
                    source=p.get('source', 'manual'),
                    method=p.get('method', 'GET'),
                    field_type=p.get('field_type', 'text')
                )
                for p in task.selected_params
            ]
        else:
            discovered_params_list = []
        
        # Continue with normal execution using selected parameters
        # (This would call the same logic as execute_task but with filtered params)
        # For now, just call execute_task which will use the stored selected_params
        execute_task(task_id)
        
    except Exception as e:
        logger.error(f"Error executing task with selection {task_id}: {e}", exc_info=True)
        task = SQLInjectionTask.objects.get(id=task_id)
        task.status = 'failed'
        task.error_message = str(e)
        task.completed_at = timezone.now()
        task.save()


# REST API Views

@api_view(['GET', 'POST'])
def api_tasks(request):
    """
    REST API endpoint for listing and creating SQL injection tasks.
    
    GET: List all tasks
    POST: Create a new task
    """
    if request.method == 'GET':
        tasks = SQLInjectionTask.objects.all()[:50]
        data = [{
            'id': task.id,
            'target_url': task.target_url,
            'http_method': task.http_method,
            'status': task.status,
            'vulnerabilities_found': task.vulnerabilities_found,
            'created_at': task.created_at.isoformat(),
            'started_at': task.started_at.isoformat() if task.started_at else None,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
        } for task in tasks]
        return Response(data)
    
    elif request.method == 'POST':
        try:
            task = SQLInjectionTask.objects.create(
                target_url=request.data.get('target_url'),
                http_method=request.data.get('http_method', 'GET'),
                get_params=request.data.get('get_params', {}),
                post_params=request.data.get('post_params', {}),
                cookies=request.data.get('cookies', {}),
                headers=request.data.get('headers', {}),
                enable_error_based=request.data.get('enable_error_based', True),
                enable_time_based=request.data.get('enable_time_based', True),
                enable_exploitation=request.data.get('enable_exploitation', True),
                auto_discover_params=request.data.get('auto_discover_params', True),
                use_random_delays=request.data.get('use_random_delays', False),
                min_delay=request.data.get('min_delay', 0.5),
                max_delay=request.data.get('max_delay', 2.0),
                randomize_user_agent=request.data.get('randomize_user_agent', True),
                use_payload_obfuscation=request.data.get('use_payload_obfuscation', False),
            )
            
            # Execute immediately if requested
            if request.data.get('execute_now', False):
                sql_injection_task.delay(task.id)
            
            return Response({
                'id': task.id,
                'status': task.status,
                'message': 'Task created successfully'
            }, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def api_task_detail(request, pk):
    """
    REST API endpoint for retrieving task details and results.
    """
    try:
        task = SQLInjectionTask.objects.get(pk=pk)
        results = task.results.all()
        
        data = {
            'id': task.id,
            'target_url': task.target_url,
            'http_method': task.http_method,
            'status': task.status,
            'get_params': task.get_params,
            'post_params': task.post_params,
            'cookies': task.cookies,
            'headers': task.headers,
            'enable_error_based': task.enable_error_based,
            'enable_time_based': task.enable_time_based,
            'enable_exploitation': task.enable_exploitation,
            'auto_discover_params': task.auto_discover_params,
            'discovered_params': task.discovered_params,
            'use_random_delays': task.use_random_delays,
            'randomize_user_agent': task.randomize_user_agent,
            'use_payload_obfuscation': task.use_payload_obfuscation,
            'vulnerabilities_found': task.vulnerabilities_found,
            'created_at': task.created_at.isoformat(),
            'started_at': task.started_at.isoformat() if task.started_at else None,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'error_message': task.error_message,
            'results': [{
                'id': result.id,
                'injection_type': result.injection_type,
                'vulnerable_parameter': result.vulnerable_parameter,
                'parameter_type': result.parameter_type,
                'parameter_source': result.parameter_source,
                'injection_location': result.injection_location,
                'test_payload': result.test_payload,
                'detection_evidence': result.detection_evidence,
                'evidence_packet': result.evidence_packet,
                'confidence_score': result.confidence_score,
                'confidence_rationale': result.confidence_rationale,
                'reproduction_steps': result.reproduction_steps,
                'is_exploitable': result.is_exploitable,
                'database_type': result.database_type,
                'database_version': result.database_version,
                'current_database': result.current_database,
                'current_user': result.current_user,
                'extracted_tables': result.extracted_tables,
                'severity': result.severity,
                'detected_at': result.detected_at.isoformat(),
            } for result in results]
        }
        
        return Response(data)
    
    except SQLInjectionTask.DoesNotExist:
        return Response({
            'error': 'Task not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def api_task_status(request, pk):
    """
    REST API endpoint for retrieving task status with per-SQLi-type breakdown.
    
    Returns structured status information including which SQLi types were tested,
    which ones found vulnerabilities, and proof-of-concept details.
    
    Response format:
    {
        "status": "completed|running|failed|pending",
        "results": [
            {
                "type": "Error-Based",
                "tested": true,
                "vulnerable": false,
                "count": 0,
                "proof": null
            },
            {
                "type": "Time-Based",
                "tested": true,
                "vulnerable": true,
                "count": 2,
                "proof": {
                    "payload": "' AND SLEEP(5)--",
                    "parameter": "id",
                    "evidence": "Response delayed by 5.2 seconds"
                }
            }
        ]
    }
    """
    # Maximum length for truncating payload and evidence text in API responses
    MAX_TEXT_DISPLAY_LENGTH = 200
    
    try:
        task = SQLInjectionTask.objects.get(pk=pk)
        
        # Define all SQLi types that could be tested
        sqli_types = [
            ('error_based', 'Error-Based'),
            ('time_based', 'Time-Based'),
            ('union_based', 'UNION-Based'),
            ('boolean_based', 'Boolean-Based'),
            ('stacked_queries', 'Stacked Queries'),
        ]
        
        results_breakdown = []
        
        for injection_type_key, injection_type_display in sqli_types:
            # Check if this type was enabled for testing
            tested = False
            if injection_type_key == 'error_based':
                tested = task.enable_error_based
            elif injection_type_key == 'time_based':
                tested = task.enable_time_based
            elif injection_type_key in ['union_based', 'boolean_based', 'stacked_queries']:
                # These are tested when exploitation is enabled
                tested = task.enable_exploitation
            
            # Get results for this injection type
            type_results = task.results.filter(injection_type=injection_type_key)
            vulnerable = type_results.exists()
            count = type_results.count()
            
            # Get proof of concept from first result if available
            proof = None
            if vulnerable:
                first_result = type_results.first()
                proof = {
                    'payload': first_result.test_payload[:MAX_TEXT_DISPLAY_LENGTH],
                    'parameter': first_result.vulnerable_parameter,
                    'parameter_type': first_result.parameter_type,
                    'evidence': first_result.detection_evidence[:MAX_TEXT_DISPLAY_LENGTH],
                    'database_type': first_result.database_type,
                    'is_exploitable': first_result.is_exploitable,
                }
                
                # Add exploitation details if available
                if first_result.is_exploitable:
                    proof['database_version'] = first_result.database_version
                    proof['current_user'] = first_result.current_user
                    proof['current_database'] = first_result.current_database
                    
                    # Add sample extracted data if available
                    if first_result.extracted_tables:
                        proof['sample_tables'] = first_result.extracted_tables[:3] if isinstance(first_result.extracted_tables, list) else None
            
            results_breakdown.append({
                'type': injection_type_display,
                'tested': tested,
                'vulnerable': vulnerable,
                'count': count,
                'proof': proof
            })
        
        response = Response({
            'status': task.status,
            'started_at': task.started_at.isoformat() if task.started_at else None,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'vulnerabilities_found': task.vulnerabilities_found,
            'error_message': task.error_message,
            'results': results_breakdown
        })

        # Prevent stale cached responses
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'

        return response
    
    except SQLInjectionTask.DoesNotExist:
        return Response({
            'error': 'Task not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def api_task_execute(request, pk):
    """
    REST API endpoint for executing a task.
    """
    try:
        task = SQLInjectionTask.objects.get(pk=pk)
        
        if task.status == 'running':
            return Response({
                'error': 'Task is already running'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Execute in background
        sql_injection_task.delay(task.id)
        
        return Response({
            'id': task.id,
            'status': 'running',
            'message': 'Task execution started'
        })
    
    except SQLInjectionTask.DoesNotExist:
        return Response({
            'error': 'Task not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def api_results(request):
    """
    REST API endpoint for listing all results.
    """
    results = SQLInjectionResult.objects.select_related('task').all()[:50]
    
    data = [{
        'id': result.id,
        'task_id': result.task.id,
        'target_url': result.task.target_url,
        'injection_type': result.injection_type,
        'vulnerable_parameter': result.vulnerable_parameter,
        'parameter_type': result.parameter_type,
        'parameter_source': result.parameter_source,
        'test_payload': result.test_payload,
        'is_exploitable': result.is_exploitable,
        'database_type': result.database_type,
        'severity': result.severity,
        'detected_at': result.detected_at.isoformat(),
    } for result in results]
    
    return Response(data)


@api_view(['GET'])
def api_union_poc_evidence(request, result_id):
    """
    Return the union-based SQL injection proof-of-concept HTML evidence for a result.

    This endpoint delivers captured visual evidence (an HTML evidence table) for
    a specific union-based SQL injection result.  The evidence is non-destructive:
    it was produced using SELECT/UNION payloads only – no data was modified or
    deleted.

    Response:
    {
        "result_id": 42,
        "html_evidence": "<div class='poc-evidence-card'>...</div>",
        "is_exploitable": true,
        "injection_type": "union_based",
        "target_url": "https://example.com/page",
        "vulnerable_parameter": "id"
    }
    """
    try:
        result = SQLInjectionResult.objects.select_related('task').get(
            pk=result_id, injection_type='union_based'
        )

        html = result.union_poc_html or ""

        # Generate dynamically if not pre-stored but data is available
        if not html and result.extracted_data:
            try:
                from .union_sql_injection import UnionSQLInjectionAttacker
                db_info = {}
                if result.database_version:
                    db_info['Database Version'] = result.database_version
                if result.current_database:
                    db_info['Current Database'] = result.current_database
                if result.current_user:
                    db_info['Database User'] = result.current_user
                extracted = result.extracted_data
                if isinstance(extracted, list) and extracted and isinstance(extracted[0], dict):
                    table_name = (
                        result.extracted_tables[0]
                        if isinstance(result.extracted_tables, list) and result.extracted_tables
                        else 'Unknown'
                    )
                    html = UnionSQLInjectionAttacker.generate_html_evidence_table(
                        extracted_data=extracted,
                        table_name=table_name,
                        db_info=db_info if db_info else None,
                    )
            except Exception as exc:
                logger.warning("Dynamic PoC HTML generation failed: %s", exc)

        return Response({
            'result_id': result_id,
            'html_evidence': html,
            'is_exploitable': result.is_exploitable,
            'injection_type': result.injection_type,
            'target_url': result.task.target_url,
            'vulnerable_parameter': result.vulnerable_parameter,
        })

    except SQLInjectionResult.DoesNotExist:
        return Response(
            {'error': 'Result not found or not a union-based finding'},
            status=status.HTTP_404_NOT_FOUND,
        )


@api_view(['POST'])
def api_generate_oob_payloads(request):
    """
    REST API endpoint for generating Out-of-Band SQL injection payloads.
    
    Request body:
    {
        "attacker_host": "attacker.com",  // Required
        "attacker_port": 80,               // Optional, default: 80
        "db_type": "mssql",                // Optional: mssql, oracle, mysql, or null for all
        "data_to_exfiltrate": "@@version"  // Optional, default: varies by DB
    }
    
    Response:
    {
        "mssql": [
            {
                "technique": "mssql_openrowset_http",
                "payload": "...",
                "description": "...",
                "requires_privileges": true,
                "privilege_level": "...",
                "listener_type": "http",
                "example_listener_setup": "..."
            },
            ...
        ],
        "oracle": [...],
        "mysql": [...]
    }
    """
    try:
        # Parse request parameters
        attacker_host = request.data.get('attacker_host')
        if not attacker_host:
            return Response({
                'error': 'attacker_host is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        attacker_port = request.data.get('attacker_port', 80)
        db_type_str = request.data.get('db_type', None)
        data_to_exfiltrate = request.data.get('data_to_exfiltrate', None)
        
        # Convert db_type string to enum
        db_type = None
        if db_type_str:
            try:
                db_type = OOBDatabaseType[db_type_str.upper()]
            except KeyError:
                return Response({
                    'error': f'Invalid db_type. Must be one of: mssql, oracle, mysql'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Initialize payload generator
        generator = OOBPayloadGenerator(attacker_host, attacker_port)
        
        # Set default data to exfiltrate based on DB type if not provided
        if data_to_exfiltrate is None:
            data_to_exfiltrate = _get_default_data_to_exfiltrate(db_type)
        
        # Generate payloads
        all_payloads = generator.generate_all_payloads(db_type, data_to_exfiltrate)
        
        # Convert to serializable format
        response_data = {}
        for db, payloads in all_payloads.items():
            response_data[db] = [{
                'technique': payload.technique.value,
                'payload': payload.payload,
                'description': payload.description,
                'requires_privileges': payload.requires_privileges,
                'privilege_level': payload.privilege_level,
                'listener_type': payload.listener_type,
                'example_listener_setup': payload.example_listener_setup
            } for payload in payloads]
        
        return Response(response_data, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.exception("Error generating OOB payloads")
        return Response({
            'error': f'Failed to generate payloads: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def api_oob_listener_guide(request):
    """
    REST API endpoint for getting listener setup guides.
    
    Query parameters:
    - listener_type: http, smb, dns, or ldap
    
    Response:
    {
        "listener_type": "http",
        "setup_guide": "..."
    }
    """
    try:
        listener_type = request.query_params.get('listener_type', 'http')
        
        if listener_type not in ['http', 'smb', 'dns', 'ldap']:
            return Response({
                'error': 'Invalid listener_type. Must be one of: http, smb, dns, ldap'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        generator = OOBPayloadGenerator()
        guide = generator.get_listener_setup_guide(listener_type)
        
        return Response({
            'listener_type': listener_type,
            'setup_guide': guide
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.exception("Error retrieving listener guide")
        return Response({
            'error': f'Failed to retrieve guide: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============================================================================
# Client-Side Scanning Views
# ============================================================================


def client_side_dashboard(request):
    """
    Dashboard view for client-side security scanning.
    """
    context = {
        'scan_types': [
            {'value': ScanType.BROWSER_AUTOMATION.value, 'label': 'Browser Automation (HTML5 Storage)'},
            {'value': ScanType.STATIC_JAVASCRIPT.value, 'label': 'Static JavaScript Analysis'},
            {'value': ScanType.HPP_DETECTION.value, 'label': 'HTTP Parameter Pollution'},
            {'value': ScanType.PRIVACY_ANALYSIS.value, 'label': 'Privacy & Storage Analysis'},
            {'value': ScanType.ALL.value, 'label': 'All Scans'},
        ]
    }
    
    return render(request, 'sql_attacker/client_side_dashboard.html', context)


@api_view(['POST'])
def api_client_side_scan(request):
    """
    REST API endpoint for running client-side security scans.
    
    POST data:
    {
        "scan_types": ["browser_automation", "static_javascript", ...],
        "target_url": "https://example.com",
        "javascript_code": "optional JS code string",
        "javascript_files": ["optional", "file", "paths"],
        "use_playwright": true,
        "headless": true,
        "timeout": 30000,
        "verify_ssl": true,
        "follow_redirects": true,
        "scan_flash_lso": false,
        "form_selector": "optional CSS selector",
        "test_params": {"optional": "params"}
    }
    
    Response:
    {
        "scan_id": "cs_20240101_120000",
        "status": "completed",
        "summary": {...},
        "findings": {...}
    }
    """
    try:
        data = request.data
        
        # Create scan configuration
        config = ScanConfiguration(
            scan_types=data.get('scan_types', [ScanType.ALL.value]),
            target_url=data.get('target_url'),
            javascript_code=data.get('javascript_code'),
            javascript_files=data.get('javascript_files'),
            use_playwright=data.get('use_playwright', True),
            headless=data.get('headless', True),
            timeout=data.get('timeout', 30000),
            verify_ssl=data.get('verify_ssl', True),
            follow_redirects=data.get('follow_redirects', True),
            scan_flash_lso=data.get('scan_flash_lso', False),
            form_selector=data.get('form_selector'),
            test_params=data.get('test_params')
        )
        
        # Execute scan
        orchestrator = ClientSideScanOrchestrator()
        results = orchestrator.scan(config)
        
        return Response(results.to_dict(), status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.exception("Error during client-side scan")
        return Response({
            'error': f'Scan failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def api_client_side_export(request):
    """
    REST API endpoint for exporting client-side scan results.
    
    POST data:
    {
        "scan_results": {...},  # Full scan results object
        "format": "json" or "html",
        "output_file": "optional file path"
    }
    
    Response:
    {
        "file_path": "/path/to/exported/file",
        "status": "success"
    }
    """
    try:
        data = request.data
        scan_results_data = data.get('scan_results')
        export_format = data.get('format', 'json')
        output_file = data.get('output_file')
        
        if not scan_results_data:
            return Response({
                'error': 'scan_results is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Reconstruct ScanResults object from data
        # For simplicity, we'll just save the data directly
        # In production, you'd reconstruct the full object
        
        if not output_file:
            # Generate temporary file
            if export_format == 'html':
                fd, output_file = tempfile.mkstemp(suffix='.html', prefix='client_scan_')
            else:
                fd, output_file = tempfile.mkstemp(suffix='.json', prefix='client_scan_')
            os.close(fd)
        
        if export_format == 'json':
            with open(output_file, 'w') as f:
                json.dump(scan_results_data, f, indent=2)
        elif export_format == 'html':
            # Generate HTML report
            # This is a simplified version - you'd use the orchestrator's method
            html = f"""
<!DOCTYPE html>
<html>
<head><title>Client-Side Scan Report</title></head>
<body>
    <h1>Client-Side Security Scan Report</h1>
    <pre>{json.dumps(scan_results_data, indent=2)}</pre>
</body>
</html>
"""
            with open(output_file, 'w') as f:
                f.write(html)
        else:
            return Response({
                'error': f'Invalid format: {export_format}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'file_path': output_file,
            'status': 'success'
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.exception("Error exporting client-side scan results")
        return Response({
            'error': f'Export failed: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
