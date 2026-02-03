from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import json
from .utils import (
    collect_wayback_urls, 
    collect_shodan_data, 
    collect_hunter_emails,
    group_results,
    extract_domain
)
from .dorks import generate_dorks_for_target
from .models import Scan


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
    
    return JsonResponse({
        'success': True,
        'scan_id': scan.id,
        'redirect_url': f'/discover/report/{scan.id}/'
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
    
    context = {
        'title': f'Scan Report - {scan.target}',
        'scan': scan,
        'results': grouped_results
    }
    
    return render(request, 'discover/report.html', context)


def scan_history(request):
    """
    Display list of all scans.
    """
    scans = Scan.objects.all()[:50]  # Last 50 scans
    
    return render(request, 'discover/history.html', {
        'title': 'Scan History',
        'scans': scans
    })
