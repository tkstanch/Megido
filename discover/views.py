from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
import json
import threading
import logging
from .utils import (
    collect_wayback_urls, 
    collect_shodan_data, 
    collect_hunter_emails,
    group_results,
    extract_domain
)
from .dorks import generate_dorks_for_target
from .models import Scan, SensitiveFinding
from .sensitive_scanner import scan_discovered_urls

# Configure logging
logger = logging.getLogger(__name__)


def run_sensitive_scan_async(scan_id: int, urls: list):
    """
    Run sensitive information scan in background thread.
    
    Args:
        scan_id: The ID of the scan to update
        urls: List of URLs to scan
    """
    try:
        logger.info(f"Starting background sensitive scan for scan {scan_id}")
        
        # Get scan results
        results = scan_discovered_urls(urls, max_urls=50)
        
        # Map finding types to severity levels
        severity_map = {
            'AWS Access Key': 'critical',
            'GitHub Personal Access Token': 'critical',
            'GitHub OAuth Token': 'critical',
            'Slack Token': 'high',
            'Slack Webhook': 'high',
            'Stripe API Key': 'critical',
            'Google API Key': 'high',
            'Generic Secret': 'high',
            'Generic API Key': 'high',
            'Bearer Token': 'medium',
            'Private Key': 'critical',
            'SSH Private Key': 'critical',
            'PGP Private Key': 'critical',
            'MySQL Connection String': 'critical',
            'PostgreSQL Connection String': 'critical',
            'MongoDB Connection String': 'critical',
            'Password Field': 'high',
            'Username/Password Combo': 'critical',
            'Email Address': 'low',
            'Private IP Address': 'medium',
            'JWT Token': 'high',
            'Credit Card Number': 'critical',
            'Social Security Number': 'critical',
        }
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Save findings to database
        high_risk_count = 0
        for finding in results.get('all_findings', []):
            severity = severity_map.get(finding['type'], 'medium')
            
            if severity in ['critical', 'high']:
                high_risk_count += 1
            
            SensitiveFinding.objects.create(
                scan=scan,
                url=finding['url'],
                finding_type=finding['type'],
                value=finding['value'],
                context=finding.get('context', ''),
                severity=severity,
                position=finding.get('position'),
            )
        
        # Update scan record
        scan.sensitive_scan_completed = True
        scan.sensitive_scan_date = timezone.now()
        scan.total_findings = results['total_findings']
        scan.high_risk_findings = high_risk_count
        scan.save()
        
        logger.info(f"Completed sensitive scan for scan {scan_id}: {results['total_findings']} findings")
        
    except Exception as e:
        logger.error(f"Error in background sensitive scan for scan {scan_id}: {e}", exc_info=True)
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.sensitive_scan_completed = True
            scan.sensitive_scan_date = timezone.now()
            scan.save()
        except Exception:
            pass


def discover_home(request):
    """
    Display the main Discover page with input form.
    """
    return render(request, 'discover/start.html', {
        'title': 'Discover - OSINT & Information Gathering'
    })


@require_http_methods(["POST"])
def start_scan(request):
    """
    Start an OSINT scan for the target.
    """
    target = request.POST.get('target', '').strip()
    enable_sensitive_scan = request.POST.get('enable_sensitive_scan', 'true').lower() == 'true'
    
    if not target:
        return JsonResponse({'error': 'Target is required'}, status=400)
    
    # Clean target
    target = extract_domain(target)
    
    # Collect data from all sources
    wayback_results = collect_wayback_urls(target)
    shodan_results = collect_shodan_data(target)
    hunter_results = collect_hunter_emails(target)
    dork_queries = generate_dorks_for_target(target)
    
    # Group results
    grouped_results = group_results(
        wayback_results,
        shodan_results,
        hunter_results,
        dork_queries
    )
    
    # Save scan to database
    scan = Scan(
        target=target,
        wayback_urls=json.dumps(wayback_results.get('urls', [])),
        shodan_data=json.dumps(shodan_results.get('data', {})),
        hunter_data=json.dumps(hunter_results.get('emails', [])),
        dork_queries=json.dumps(dork_queries),
        total_urls=len(wayback_results.get('urls', [])),
        total_emails=len(hunter_results.get('emails', []))
    )
    scan.save()
    
    # Start background sensitive scan if enabled
    sensitive_scan_started = False
    if enable_sensitive_scan:
        urls = wayback_results.get('urls', [])
        if urls:
            # Extract just the original URLs for scanning
            url_list = [url.get('original') if isinstance(url, dict) else url for url in urls]
            
            # Start background thread
            # Note: Using daemon thread here is acceptable for this security testing tool
            # as it allows the main process to exit without waiting for scans to complete.
            # For production systems, consider using a task queue (Celery, Django Q, etc.)
            thread = threading.Thread(
                target=run_sensitive_scan_async,
                args=(scan.id, url_list),
                daemon=True
            )
            thread.start()
            sensitive_scan_started = True
            logger.info(f"Started background sensitive scan for scan {scan.id}")
    
    return JsonResponse({
        'success': True,
        'scan_id': scan.id,
        'redirect_url': f'/discover/report/{scan.id}/',
        'sensitive_scan_started': sensitive_scan_started
    })


def view_report(request, scan_id):
    """
    Display the scan report with grouped results.
    """
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return render(request, 'discover/report.html', {
            'error': 'Scan not found',
            'title': 'Scan Report - Not Found'
        })
    
    # Parse JSON data
    try:
        wayback_urls = json.loads(scan.wayback_urls) if scan.wayback_urls else []
    except json.JSONDecodeError:
        wayback_urls = []
    
    try:
        shodan_data = json.loads(scan.shodan_data) if scan.shodan_data else {}
    except json.JSONDecodeError:
        shodan_data = {}
    
    try:
        hunter_emails = json.loads(scan.hunter_data) if scan.hunter_data else []
    except json.JSONDecodeError:
        hunter_emails = []
    
    try:
        dork_queries = json.loads(scan.dork_queries) if scan.dork_queries else {}
    except json.JSONDecodeError:
        dork_queries = {}
    
    # Reconstruct grouped results
    wayback_results = {
        'success': len(wayback_urls) > 0,
        'urls': wayback_urls,
        'error': None if len(wayback_urls) > 0 else 'No URLs found',
        'guidance': (
            "📚 Historical URLs from Wayback Machine can reveal:\n"
            "• Forgotten/removed pages that may still be accessible\n"
            "• Old endpoints that might still work but lack security updates\n"
            "• Exposed sensitive information from past versions\n"
            "• Changes in site structure and functionality over time\n"
            "• Backup files or development artifacts that were removed"
        )
    }
    
    shodan_results = {
        'success': bool(shodan_data),
        'data': shodan_data,
        'error': None if bool(shodan_data) else 'No data available or API key not configured',
        'guidance': (
            "🔍 Shodan data reveals:\n"
            "• Open ports and services running on the target\n"
            "• Banners and version information (useful for CVE research)\n"
            "• SSL/TLS certificate details\n"
            "• Geographic location of servers\n"
            "• Related hosts and domains\n"
            "• Historical service data"
        )
    }
    
    hunter_results = {
        'success': len(hunter_emails) > 0,
        'emails': hunter_emails,
        'error': None if len(hunter_emails) > 0 else 'No emails found or API key not configured',
        'guidance': (
            "📧 Email addresses can be used for:\n"
            "• Social engineering and phishing campaigns (ethical testing only)\n"
            "• Identifying key personnel and organizational structure\n"
            "• Password reset enumeration testing\n"
            "• Correlating with data breaches (HaveIBeenPwned)\n"
            "• Building contact lists for security disclosures\n"
            "• Understanding email format patterns"
        )
    }
    
    grouped_results = group_results(
        wayback_results,
        shodan_results,
        hunter_results,
        dork_queries
    )
    
    # Get sensitive findings (ordered and limited for performance)
    sensitive_findings = scan.sensitive_findings.order_by('-discovered_at')[:100]
    
    # Calculate findings by severity using aggregation (single query)
    from django.db.models import Count, Q
    severity_counts = scan.sensitive_findings.aggregate(
        critical=Count('id', filter=Q(severity='critical')),
        high=Count('id', filter=Q(severity='high')),
        medium=Count('id', filter=Q(severity='medium')),
        low=Count('id', filter=Q(severity='low')),
    )
    
    findings_by_severity = {
        'critical': severity_counts['critical'],
        'high': severity_counts['high'],
        'medium': severity_counts['medium'],
        'low': severity_counts['low'],
    }
    
    # Sensitive scan status
    sensitive_scan_status = {
        'completed': scan.sensitive_scan_completed,
        'date': scan.sensitive_scan_date,
        'total_findings': scan.total_findings,
        'high_risk_findings': scan.high_risk_findings,
    }
    
    context = {
        'title': f'Scan Report - {scan.target}',
        'scan': scan,
        'results': grouped_results,
        'sensitive_findings': sensitive_findings,
        'findings_by_severity': findings_by_severity,
        'sensitive_scan_status': sensitive_scan_status,
    }
    
    return render(request, 'discover/report.html', context)


def scan_history(request):
    """
    Display list of all scans.
    """
    scans = Scan.objects.all().order_by('-scan_date')[:50]  # Last 50 scans
    
    return render(request, 'discover/history.html', {
        'title': 'Scan History',
        'scans': scans
    })


def scan_status(request, scan_id):
    """
    API endpoint to check scan progress.
    Returns JSON with scan status and statistics.
    """
    try:
        scan = Scan.objects.get(id=scan_id)
        
        return JsonResponse({
            'success': True,
            'scan_completed': scan.sensitive_scan_completed,
            'total_findings': scan.total_findings,
            'high_risk_findings': scan.high_risk_findings,
            'scan_date': scan.sensitive_scan_date.isoformat() if scan.sensitive_scan_date else None,
        })
    except Scan.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Scan not found'
        }, status=404)
