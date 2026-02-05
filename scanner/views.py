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
                'severity': vuln.severity,
                'url': vuln.url,
                'description': vuln.description,
                'evidence': vuln.evidence,
                'remediation': vuln.remediation,
            } for vuln in vulnerabilities]
        }
        return Response(data)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=404)


@login_required
def scanner_dashboard(request):
    """Dashboard view for the scanner"""
    return render(request, 'scanner/dashboard.html')
