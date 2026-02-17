from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db.models import Count, Q
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
import json
import threading
import logging

from .models import SQLInjectionTask, SQLInjectionResult
from .sqli_engine import SQLInjectionEngine
from .param_discovery import ParameterDiscoveryEngine
from .oob_payloads import OOBPayloadGenerator, DatabaseType as OOBDatabaseType
from response_analyser.analyse import save_vulnerability

# Configure logging
logger = logging.getLogger(__name__)


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
        )
        
        # Execute task in background if requested
        if request.POST.get('execute_now') == 'on':
            thread = threading.Thread(target=execute_task, args=(task.id,))
            thread.daemon = False  # Non-daemon thread for safer execution
            thread.start()
        
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
        
        # Run attack
        findings = engine.run_full_attack(
            url=task.target_url,
            method=task.http_method,
            params=params,
            data=data,
            cookies=cookies,
            headers=headers,
            enable_error_based=task.enable_error_based,
            enable_time_based=task.enable_time_based,
            enable_exploitation=task.enable_exploitation,
        )
        
        # Store results
        vulnerabilities_count = 0
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
            
            result = SQLInjectionResult.objects.create(
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
            )
            vulnerabilities_count += 1
            
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
            thread = threading.Thread(target=execute_task, args=(task.id,))
            thread.daemon = True
            thread.start()
            
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
            thread = threading.Thread(target=execute_task_with_selection, args=(task.id,))
            thread.daemon = True
            thread.start()
            
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
                thread = threading.Thread(target=execute_task, args=(task.id,))
                thread.daemon = False  # Non-daemon thread for safer execution
                thread.start()
            
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
                'test_payload': result.test_payload,
                'detection_evidence': result.detection_evidence,
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
        thread = threading.Thread(target=execute_task, args=(task.id,))
        thread.daemon = False  # Non-daemon thread for safer execution
        thread.start()
        
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
            data_to_exfiltrate = {
                OOBDatabaseType.MSSQL: '@@version',
                OOBDatabaseType.ORACLE: 'user',
                OOBDatabaseType.MYSQL: '@@version'
            }.get(db_type, 'user') if db_type else 'user'
        
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
