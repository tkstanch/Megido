from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from .models import ScanTarget, Scan, Vulnerability
from django.utils import timezone
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import os
from celery.result import AsyncResult
from scanner.tasks import async_exploit_all_vulnerabilities, async_exploit_selected_vulnerabilities


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
        return Response(data)
    
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
    """Start a vulnerability scan on a target"""
    try:
        target = ScanTarget.objects.get(id=target_id)
        scan = Scan.objects.create(target=target, status='running')
        
        # Run basic vulnerability checks
        try:
            perform_basic_scan(scan, target.url)
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
            return Response({'id': scan.id, 'message': 'Scan completed'})
        except Exception as e:
            scan.status = 'failed'
            scan.save()
            return Response({'error': str(e)}, status=500)
            
    except ScanTarget.DoesNotExist:
        return Response({'error': 'Target not found'}, status=404)


def perform_basic_scan(scan, url):
    """Perform basic vulnerability scanning"""
    # Get SSL verification setting from environment (default to False for security testing)
    verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
    
    try:
        # Test for common XSS payloads
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
        ]
        
        response = requests.get(url, timeout=10, verify=verify_ssl)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for forms (potential XSS/SQLI targets)
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            target_url = urljoin(url, action)
            
            # Test for XSS in form
            inputs = form.find_all('input')
            if inputs:
                Vulnerability.objects.create(
                    scan=scan,
                    vulnerability_type='xss',
                    severity='medium',
                    url=target_url,
                    description=f'Form found with {len(inputs)} input fields - potential XSS target',
                    evidence=f'Form action: {action}',
                    remediation='Implement input validation and output encoding'
                )
        
        # Check for insecure headers
        headers = response.headers
        if 'X-Frame-Options' not in headers:
            Vulnerability.objects.create(
                scan=scan,
                vulnerability_type='other',
                severity='low',
                url=url,
                description='Missing X-Frame-Options header',
                evidence='X-Frame-Options header not found',
                remediation='Add X-Frame-Options: DENY or SAMEORIGIN header'
            )
        
        if 'X-Content-Type-Options' not in headers:
            Vulnerability.objects.create(
                scan=scan,
                vulnerability_type='other',
                severity='low',
                url=url,
                description='Missing X-Content-Type-Options header',
                evidence='X-Content-Type-Options header not found',
                remediation='Add X-Content-Type-Options: nosniff header'
            )
        
        # Check for SSL/TLS
        if urlparse(url).scheme == 'http':
            Vulnerability.objects.create(
                scan=scan,
                vulnerability_type='info_disclosure',
                severity='medium',
                url=url,
                description='Site uses insecure HTTP protocol',
                evidence='URL scheme is http:// instead of https://',
                remediation='Implement HTTPS with valid SSL/TLS certificate'
            )
            
    except Exception as e:
        print(f"Error during scan: {e}")


@api_view(['GET'])
@permission_classes([AllowAny])
def scan_results(request, scan_id):
    """Get results of a scan"""
    try:
        scan = Scan.objects.get(id=scan_id)
        vulnerabilities = scan.vulnerabilities.all()
        
        data = {
            'scan_id': scan.id,
            'status': scan.status,
            'started_at': scan.started_at.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'vulnerabilities': [{
                'id': vuln.id,
                'type': vuln.get_vulnerability_type_display(),
                'vulnerability_type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'url': vuln.url,
                'description': vuln.description,
                'evidence': vuln.evidence,
                'remediation': vuln.remediation,
                'exploited': vuln.exploited,
                'exploit_status': vuln.exploit_status,
                'exploit_result': vuln.exploit_result,
            } for vuln in vulnerabilities]
        }
        return Response(data)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def exploit_vulnerabilities(request, scan_id):
    """
    Trigger background exploitation of vulnerabilities from a scan.
    
    Request body should contain:
    - action: 'all' to exploit all vulnerabilities, 'selected' for specific ones
    - vulnerability_ids: (optional) list of vulnerability IDs when action='selected'
    
    Returns:
    - task_id: Celery task ID for polling status
    - message: Confirmation message
    """
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)
    
    action = request.data.get('action', 'all')
    
    # Configuration for exploit attempts
    config = {
        'timeout': 30,
        'verify_ssl': False,
        'enable_exploitation': True,
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
    
    return Response(response_data)


@login_required
def scanner_dashboard(request):
    """Dashboard view for the scanner"""
    return render(request, 'scanner/dashboard.html')
