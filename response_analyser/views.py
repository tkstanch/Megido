from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.clickjacking import xframe_options_exempt
from django.db.models import Count, Q
from .models import Vulnerability
import json


def vulnerability_list(request):
    """
    List all vulnerabilities with filtering and grouping options.
    """
    vulnerabilities = Vulnerability.objects.all()
    
    # Apply filters from query parameters
    attack_type = request.GET.get('attack_type')
    if attack_type:
        vulnerabilities = vulnerabilities.filter(attack_type=attack_type)
    
    severity = request.GET.get('severity')
    if severity:
        vulnerabilities = vulnerabilities.filter(severity=severity)
    
    is_confirmed = request.GET.get('is_confirmed')
    if is_confirmed:
        vulnerabilities = vulnerabilities.filter(is_confirmed=is_confirmed.lower() == 'true')
    
    false_positive = request.GET.get('false_positive')
    if false_positive:
        vulnerabilities = vulnerabilities.filter(false_positive=false_positive.lower() == 'true')
    
    search = request.GET.get('search')
    if search:
        vulnerabilities = vulnerabilities.filter(
            Q(target_url__icontains=search) |
            Q(payload__icontains=search) |
            Q(notes__icontains=search)
        )
    
    # Get statistics for grouping
    attack_type_stats = Vulnerability.objects.values('attack_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    endpoint_stats = Vulnerability.objects.exclude(endpoint='').values('endpoint').annotate(
        count=Count('id')
    ).order_by('-count')[:20]  # Top 20 endpoints
    
    severity_stats = Vulnerability.objects.values('severity').annotate(
        count=Count('id')
    ).order_by('-count')
    
    context = {
        'vulnerabilities': vulnerabilities[:100],  # Limit to 100 for performance
        'attack_type_stats': attack_type_stats,
        'endpoint_stats': endpoint_stats,
        'severity_stats': severity_stats,
        'total_count': vulnerabilities.count(),
        'attack_types': Vulnerability.ATTACK_TYPES,
        'severities': Vulnerability.SEVERITY_LEVELS,
    }
    
    return render(request, 'response_analyser/vulnerability_list.html', context)


def vulnerability_detail(request, pk):
    """
    Display detailed information about a specific vulnerability.
    """
    vulnerability = get_object_or_404(Vulnerability, pk=pk)
    
    context = {
        'vulnerability': vulnerability,
    }
    
    return render(request, 'response_analyser/vulnerability_detail.html', context)


@xframe_options_exempt
def render_evidence_html(request, pk):
    """
    Render the captured HTML evidence in a sandboxed iframe.
    This endpoint serves the raw HTML for inspection.
    """
    vulnerability = get_object_or_404(Vulnerability, pk=pk)
    
    if not vulnerability.evidence_html:
        return HttpResponse('<html><body><h1>No HTML evidence available</h1></body></html>')
    
    # Return the raw HTML with security headers
    response = HttpResponse(vulnerability.evidence_html, content_type='text/html')
    # Add security headers to prevent XSS in the iframe
    response['X-Content-Type-Options'] = 'nosniff'
    response['X-Frame-Options'] = 'SAMEORIGIN'
    response['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
    
    return response


def dashboard(request):
    """
    Dashboard view showing vulnerability statistics and summaries.
    """
    total_vulns = Vulnerability.objects.count()
    confirmed_vulns = Vulnerability.objects.filter(is_confirmed=True).count()
    false_positives = Vulnerability.objects.filter(false_positive=True).count()
    to_review = total_vulns - confirmed_vulns - false_positives
    
    # Group by attack type
    by_attack_type = Vulnerability.objects.values('attack_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Group by severity
    by_severity = Vulnerability.objects.values('severity').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Recent vulnerabilities
    recent_vulns = Vulnerability.objects.filter(
        false_positive=False
    ).order_by('-detected_at')[:10]
    
    context = {
        'total_vulns': total_vulns,
        'confirmed_vulns': confirmed_vulns,
        'false_positives': false_positives,
        'to_review': to_review,
        'by_attack_type': by_attack_type,
        'by_severity': by_severity,
        'recent_vulns': recent_vulns,
    }
    
    return render(request, 'response_analyser/dashboard.html', context)


def download_poc(request, pk):
    """
    Download Proof of Concept for a vulnerability.
    Returns PoC data as a downloadable file (text or JSON format).
    """
    vulnerability = get_object_or_404(Vulnerability, pk=pk)
    
    if not vulnerability.proof_of_impact:
        return HttpResponse('No Proof of Concept available for this vulnerability.', status=404)
    
    # Determine format from query parameter (default: text)
    format_type = request.GET.get('format', 'text')
    
    if format_type == 'json':
        # Return as JSON format
        poc_data = {
            'vulnerability_id': vulnerability.id,
            'attack_type': vulnerability.get_attack_type_display(),
            'severity': vulnerability.severity,
            'target_url': vulnerability.target_url,
            'detected_at': vulnerability.detected_at.isoformat(),
            'proof_of_impact': vulnerability.proof_of_impact,
            'payload': vulnerability.payload,
            'endpoint': vulnerability.endpoint,
        }
        
        response = JsonResponse(poc_data, json_dumps_params={'indent': 2})
        response['Content-Disposition'] = f'attachment; filename="poc_vuln_{pk}.json"'
        return response
    else:
        # Return as plain text format
        poc_text = f"""Proof of Concept - Vulnerability #{vulnerability.id}
{'=' * 80}

Attack Type: {vulnerability.get_attack_type_display()}
Severity: {vulnerability.severity.upper()}
Target URL: {vulnerability.target_url}
Endpoint: {vulnerability.endpoint or 'N/A'}
Detected: {vulnerability.detected_at.strftime('%Y-%m-%d %H:%M:%S')}

{'=' * 80}
PROOF OF IMPACT
{'=' * 80}

{vulnerability.proof_of_impact}

{'=' * 80}
PAYLOAD
{'=' * 80}

{vulnerability.payload}

{'=' * 80}
Generated by Megido Security Platform
"""
        
        response = HttpResponse(poc_text, content_type='text/plain; charset=utf-8')
        response['Content-Disposition'] = f'attachment; filename="poc_vuln_{pk}.txt"'
        return response
