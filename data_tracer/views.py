from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json

from .models import (
    ScanTarget, ScanResult, PortScan, ServiceDetection,
    OSFingerprint, PacketCapture, StealthConfiguration, ScanLog,
    VulnerabilityFinding, NetworkTopology, TrafficFlow, ThreatIntelligence,
    CloudAsset, APIEndpoint, WirelessNetwork, CredentialFinding,
    ScanReport, ScanSchedule, ScanComparison,
)
from .engine import (
    HostDiscovery, PortScanner, ServiceDetector,
    OSFingerprinter, PacketAnalyzer, StealthManager,
    VulnerabilityScanner, NetworkMapper, TrafficAnalyzer,
    WirelessAnalyzer, ThreatIntelligenceEngine, CloudScanner,
    APIScanner, ReportGenerator, CredentialScanner,
)


def data_tracer_home(request):
    """Home page for Data Tracer app."""
    context = {
        'app_name': 'Data Tracer',
        'description': 'Network scanning and analysis tool with Nmap-like capabilities'
    }
    return render(request, 'data_tracer/home.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def create_scan(request):
    """Create a new scan target."""
    if request.method == 'POST':
        target = request.POST.get('target')
        scan_type = request.POST.get('scan_type', 'comprehensive')
        stealth_mode = request.POST.get('stealth_mode') == 'on'
        notes = request.POST.get('notes', '')
        
        scan_target = ScanTarget.objects.create(
            target=target,
            created_by=request.user,
            scan_type=scan_type,
            stealth_mode=stealth_mode,
            notes=notes,
            status='pending'
        )
        
        return redirect('data_tracer:scan_detail', scan_id=scan_target.id)
    
    return render(request, 'data_tracer/create_scan.html')


@login_required
def scan_list(request):
    """List all scans for the current user."""
    scans = ScanTarget.objects.filter(created_by=request.user)
    context = {
        'scans': scans
    }
    return render(request, 'data_tracer/scan_list.html', context)


@login_required
def scan_detail(request, scan_id):
    """View details of a specific scan."""
    scan_target = get_object_or_404(ScanTarget, id=scan_id, created_by=request.user)
    results = scan_target.results.all()
    
    context = {
        'scan_target': scan_target,
        'results': results
    }
    return render(request, 'data_tracer/scan_detail.html', context)


@login_required
@require_http_methods(["POST"])
def execute_scan(request, scan_id):
    """Execute a scan."""
    scan_target = get_object_or_404(ScanTarget, id=scan_id, created_by=request.user)
    
    # Update status
    scan_target.status = 'running'
    scan_target.save()
    
    # Create scan result
    scan_result = ScanResult.objects.create(
        scan_target=scan_target,
        started_at=timezone.now()
    )
    
    try:
        # Initialize stealth configuration if needed
        stealth_config = {}
        if scan_target.stealth_mode:
            stealth_manager = StealthManager(timing_template=2)  # Polite mode
            stealth_config = stealth_manager.get_stealth_config()
        
        # Step 1: Host Discovery
        log_scan_event(scan_result, 'info', 'Starting host discovery')
        host_discovery = HostDiscovery(stealth_config)
        discovered_hosts = host_discovery.discover_hosts(scan_target.target, method='combined')
        
        if discovered_hosts:
            scan_result.host_discovered = True
            log_scan_event(scan_result, 'info', f'Discovered {len(discovered_hosts)} host(s)')
            
            # Step 2: Port Scanning
            log_scan_event(scan_result, 'info', 'Starting port scan')
            port_scanner = PortScanner(stealth_config)
            
            # Use appropriate scan type based on stealth mode
            scan_type = 'syn' if scan_target.stealth_mode else 'connect'
            port_results = port_scanner.scan_ports(scan_target.target, scan_type=scan_type)
            
            # Save port scan results
            open_ports = []
            for port_result in port_results:
                if port_result['state'] in ['open', 'open|filtered']:
                    port_scan = PortScan.objects.create(
                        scan_result=scan_result,
                        port=port_result['port'],
                        protocol=port_result['protocol'],
                        state=port_result['state'],
                        scan_type=scan_type,
                        service_name=port_result.get('banner', '')[:100] if port_result.get('banner') else ''
                    )
                    open_ports.append(port_result['port'])
            
            scan_result.open_ports_count = len(open_ports)
            log_scan_event(scan_result, 'info', f'Found {len(open_ports)} open port(s)')
            
            # Step 3: Service Detection
            if open_ports:
                log_scan_event(scan_result, 'info', 'Starting service detection')
                service_detector = ServiceDetector()
                
                for port in open_ports[:10]:  # Limit to first 10 ports
                    service_info = service_detector.detect_service(scan_target.target, port)
                    
                    port_scan = PortScan.objects.filter(
                        scan_result=scan_result,
                        port=port
                    ).first()
                    
                    if port_scan and service_info['service_name'] != 'unknown':
                        ServiceDetection.objects.create(
                            port_scan=port_scan,
                            service_name=service_info['service_name'],
                            service_version=service_info.get('service_version', ''),
                            product=service_info.get('product', ''),
                            confidence=service_info.get('confidence', 0)
                        )
            
            # Step 4: OS Fingerprinting
            log_scan_event(scan_result, 'info', 'Starting OS fingerprinting')
            os_fingerprinter = OSFingerprinter()
            os_results = os_fingerprinter.fingerprint_os(
                scan_target.target,
                open_ports=open_ports
            )
            
            for os_result in os_results[:3]:  # Top 3 matches
                OSFingerprint.objects.create(
                    scan_result=scan_result,
                    os_name=os_result['os_name'],
                    os_family=os_result.get('os_family', ''),
                    accuracy=os_result['accuracy'],
                    fingerprint_method=os_result['method']
                )
        else:
            log_scan_event(scan_result, 'warning', 'No hosts discovered')
        
        # Complete scan
        scan_result.completed_at = timezone.now()
        scan_result.duration_seconds = (scan_result.completed_at - scan_result.started_at).total_seconds()
        scan_result.summary = generate_scan_summary(scan_result)
        scan_result.save()
        
        scan_target.status = 'completed'
        scan_target.save()
        
        log_scan_event(scan_result, 'info', 'Scan completed successfully')
        
    except Exception as e:
        scan_target.status = 'failed'
        scan_target.save()
        log_scan_event(scan_result, 'error', f'Scan failed: {str(e)}')
    
    return redirect('data_tracer:result_detail', result_id=scan_result.id)


@login_required
def result_detail(request, result_id):
    """View detailed scan results."""
    scan_result = get_object_or_404(ScanResult, id=result_id)
    
    # Get related data
    port_scans = scan_result.port_scans.all()
    os_fingerprints = scan_result.os_fingerprints.all()
    logs = scan_result.logs.all()
    
    context = {
        'scan_result': scan_result,
        'port_scans': port_scans,
        'os_fingerprints': os_fingerprints,
        'logs': logs
    }
    return render(request, 'data_tracer/result_detail.html', context)


@login_required
def packet_analysis(request, result_id):
    """View packet capture analysis."""
    scan_result = get_object_or_404(ScanResult, id=result_id)
    packets = scan_result.packet_captures.all()
    
    # Aggregate packet statistics
    analyzer = PacketAnalyzer()
    packet_dicts = [
        {
            'packet_type': p.packet_type,
            'relevance': p.relevance,
            'source_port': p.source_port,
            'destination_port': p.destination_port,
            'source_ip': p.source_ip,
            'destination_ip': p.destination_ip,
        }
        for p in packets
    ]
    
    aggregated = analyzer.aggregate_analysis(packet_dicts) if packet_dicts else {}
    
    context = {
        'scan_result': scan_result,
        'packets': packets,
        'aggregated': aggregated
    }
    return render(request, 'data_tracer/packet_analysis.html', context)


@login_required
def stealth_config(request):
    """Manage stealth configurations."""
    if request.method == 'POST':
        name = request.POST.get('name')
        timing_template = int(request.POST.get('timing_template', 3))
        
        stealth_manager = StealthManager(timing_template)
        config = stealth_manager.get_stealth_config()
        
        StealthConfiguration.objects.create(
            name=name,
            description=config['timing_name'],
            timing_template=timing_template,
            scan_delay=config['scan_delay'],
            max_scan_delay=config['max_scan_delay'],
            min_rate=config['min_rate'],
            max_rate=config['max_rate'],
            max_retries=config['max_retries'],
            host_timeout=config['host_timeout'],
            randomize_hosts=config['randomize_hosts']
        )
        
        return redirect('data_tracer:stealth_config')
    
    configs = StealthConfiguration.objects.all()
    context = {
        'configs': configs
    }
    return render(request, 'data_tracer/stealth_config.html', context)


# Helper functions

def log_scan_event(scan_result, level, message, details=None):
    """Log a scan event."""
    ScanLog.objects.create(
        scan_result=scan_result,
        level=level,
        message=message,
        details=details or {}
    )


def generate_scan_summary(scan_result):
    """Generate a summary of scan results."""
    summary_parts = []
    
    if scan_result.host_discovered:
        summary_parts.append(f"Host is up")
    else:
        summary_parts.append(f"Host appears to be down")
    
    if scan_result.open_ports_count > 0:
        summary_parts.append(f"{scan_result.open_ports_count} open port(s) discovered")
    
    services = ServiceDetection.objects.filter(
        port_scan__scan_result=scan_result
    ).count()
    if services > 0:
        summary_parts.append(f"{services} service(s) identified")
    
    os_matches = scan_result.os_fingerprints.count()
    if os_matches > 0:
        top_os = scan_result.os_fingerprints.first()
        summary_parts.append(f"OS detected: {top_os.os_name} ({top_os.accuracy}% confidence)")
    
    return ". ".join(summary_parts)


# =====================================================================
# New views for enhanced engine modules
# =====================================================================


@login_required
def vulnerability_dashboard(request):
    """Vulnerability scan dashboard with severity breakdown."""
    recent_scans = ScanTarget.objects.filter(created_by=request.user)
    findings = VulnerabilityFinding.objects.filter(
        scan_result__scan_target__created_by=request.user
    ).order_by('-cvss_score')[:50]

    severity_counts = {
        'critical': findings.filter(severity='critical').count(),
        'high': findings.filter(severity='high').count(),
        'medium': findings.filter(severity='medium').count(),
        'low': findings.filter(severity='low').count(),
        'info': findings.filter(severity='info').count(),
    }

    context = {
        'findings': findings,
        'severity_counts': severity_counts,
        'recent_scans': recent_scans[:5],
    }
    return render(request, 'data_tracer/vulnerability_dashboard.html', context)


@login_required
def network_topology(request, result_id):
    """Network topology interactive visualization page."""
    scan_result = get_object_or_404(ScanResult, id=result_id)
    nodes = scan_result.topology_nodes.all()

    # Build graph data for D3.js
    graph_data = {
        'nodes': [
            {
                'id': str(n.ip_address),
                'label': n.hostname or str(n.ip_address),
                'type': n.node_type,
                'vendor': n.vendor,
                'ip': str(n.ip_address),
            }
            for n in nodes
        ],
        'links': [],
    }

    # Build simple tree from nodes (first node = gateway)
    if len(graph_data['nodes']) > 1:
        gateway = graph_data['nodes'][0]['id']
        for node in graph_data['nodes'][1:]:
            graph_data['links'].append({
                'source': gateway,
                'target': node['id'],
                'type': 'network',
            })

    context = {
        'scan_result': scan_result,
        'nodes': nodes,
        'graph_data_json': json.dumps(graph_data),
    }
    return render(request, 'data_tracer/network_topology.html', context)


@login_required
def traffic_analysis_dashboard(request):
    """Traffic analysis real-time monitoring dashboard."""
    recent_flows = TrafficFlow.objects.filter(
        scan_result__scan_target__created_by=request.user
    ).order_by('-byte_count')[:50]

    protocol_stats = {}
    for flow in recent_flows:
        proto = flow.application_protocol or 'unknown'
        if proto not in protocol_stats:
            protocol_stats[proto] = {'count': 0, 'bytes': 0}
        protocol_stats[proto]['count'] += 1
        protocol_stats[proto]['bytes'] += flow.byte_count

    context = {
        'recent_flows': recent_flows,
        'protocol_stats': protocol_stats,
    }
    return render(request, 'data_tracer/traffic_analysis.html', context)


@login_required
def threat_intelligence_dashboard(request):
    """Threat intelligence correlation results page."""
    ioc_matches = ThreatIntelligence.objects.filter(
        scan_result__scan_target__created_by=request.user
    ).order_by('-threat_score')[:50]

    context = {
        'ioc_matches': ioc_matches,
        'total_matches': ioc_matches.count(),
        'high_risk': ioc_matches.filter(severity__in=['critical', 'high']).count(),
    }
    return render(request, 'data_tracer/threat_intelligence.html', context)


@login_required
def cloud_security_dashboard(request):
    """Cloud security posture dashboard."""
    cloud_assets = CloudAsset.objects.filter(
        scan_result__scan_target__created_by=request.user
    ).order_by('-risk_score')[:50]

    provider_stats = {}
    for asset in cloud_assets:
        if asset.provider not in provider_stats:
            provider_stats[asset.provider] = {'count': 0, 'public': 0}
        provider_stats[asset.provider]['count'] += 1
        if asset.is_public:
            provider_stats[asset.provider]['public'] += 1

    context = {
        'cloud_assets': cloud_assets,
        'provider_stats': provider_stats,
    }
    return render(request, 'data_tracer/cloud_security.html', context)


@login_required
def api_security_dashboard(request):
    """API security testing interface."""
    api_endpoints = APIEndpoint.objects.filter(
        scan_result__scan_target__created_by=request.user
    ).order_by('-discovered_at')[:50]

    context = {
        'api_endpoints': api_endpoints,
        'total_endpoints': api_endpoints.count(),
    }
    return render(request, 'data_tracer/api_security.html', context)


@login_required
def wireless_networks_dashboard(request):
    """Wireless network discovery page."""
    networks = WirelessNetwork.objects.filter(
        scan_result__scan_target__created_by=request.user
    ).order_by('-discovered_at')[:50]

    risk_counts = {
        'critical': networks.filter(risk_level='critical').count(),
        'high': networks.filter(risk_level='high').count(),
        'medium': networks.filter(risk_level='medium').count(),
        'low': networks.filter(risk_level='low').count(),
    }

    context = {
        'networks': networks,
        'risk_counts': risk_counts,
        'rogue_count': networks.filter(is_rogue=True).count(),
    }
    return render(request, 'data_tracer/wireless_networks.html', context)


@login_required
def credential_scan_dashboard(request):
    """Credential scan results page."""
    credential_findings = CredentialFinding.objects.filter(
        scan_result__scan_target__created_by=request.user
    ).order_by('-discovered_at')[:50]

    context = {
        'credential_findings': credential_findings,
        'critical_count': credential_findings.filter(severity='critical').count(),
        'high_count': credential_findings.filter(severity='high').count(),
    }
    return render(request, 'data_tracer/credential_scan.html', context)


@login_required
def generate_report(request, result_id):
    """Report generation and download page."""
    scan_result = get_object_or_404(ScanResult, id=result_id)
    format_choice = request.GET.get('format', 'html')

    # Collect all findings from scan
    scan_data = {
        'target': scan_result.scan_target.target,
        'findings': [],
        'cve_findings': list(
            scan_result.vulnerability_findings.values(
                'cve_id', 'cvss_score', 'severity', 'title', 'description', 'remediation'
            )[:20]
        ),
    }

    # Generate report
    generator = ReportGenerator()
    executive_summary = generator.generate_executive_summary(scan_data)
    technical_report = generator.generate_technical_report(scan_data)

    if format_choice in ['json', 'csv', 'markdown', 'text']:
        exported = generator.export_report(technical_report, format_choice)
        content_types = {
            'json': 'application/json',
            'csv': 'text/csv',
            'markdown': 'text/markdown',
            'text': 'text/plain',
        }
        response = HttpResponse(exported, content_type=content_types.get(format_choice, 'text/plain'))
        response['Content-Disposition'] = f'attachment; filename="scan_report_{result_id}.{format_choice}"'
        return response

    context = {
        'scan_result': scan_result,
        'executive_summary': executive_summary,
        'technical_report': technical_report,
        'format': format_choice,
    }
    return render(request, 'data_tracer/report.html', context)


@login_required
def scan_schedule_list(request):
    """Scan scheduling and automation page."""
    if request.method == 'POST':
        name = request.POST.get('name', '')
        target = request.POST.get('target', '')
        frequency = request.POST.get('frequency', 'once')

        if name and target:
            ScanSchedule.objects.create(
                name=name,
                target=target,
                frequency=frequency,
                created_by=request.user,
            )
        return redirect('data_tracer:scan_schedule')

    schedules = ScanSchedule.objects.filter(created_by=request.user)
    context = {'schedules': schedules}
    return render(request, 'data_tracer/scan_schedule.html', context)


@login_required
def scan_comparison(request):
    """Scan comparison/diff page."""
    comparisons = ScanComparison.objects.filter(
        baseline_scan__scan_target__created_by=request.user
    ).order_by('-compared_at')[:20]

    user_scans = ScanResult.objects.filter(
        scan_target__created_by=request.user
    ).order_by('-started_at')[:20]

    context = {
        'comparisons': comparisons,
        'user_scans': user_scans,
    }
    return render(request, 'data_tracer/scan_comparison.html', context)


# =====================================================================
# REST API endpoints for automation and CI/CD integration
# =====================================================================


@login_required
@require_http_methods(["GET"])
def api_scan_list(request):
    """REST API: List all scans."""
    scans = ScanTarget.objects.filter(created_by=request.user).values(
        'id', 'target', 'status', 'scan_type', 'created_at'
    )
    return JsonResponse({'scans': list(scans)}, safe=False)


@login_required
@require_http_methods(["POST"])
def api_create_scan(request):
    """REST API: Create a new scan."""
    try:
        data = json.loads(request.body)
        target = data.get('target')
        if not target:
            return JsonResponse({'error': 'target is required'}, status=400)

        scan = ScanTarget.objects.create(
            target=target,
            created_by=request.user,
            scan_type=data.get('scan_type', 'comprehensive'),
            stealth_mode=data.get('stealth_mode', False),
            notes=data.get('notes', ''),
        )
        return JsonResponse({
            'id': str(scan.id),
            'target': scan.target,
            'status': scan.status,
        }, status=201)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)


@login_required
@require_http_methods(["GET"])
def api_scan_result(request, result_id):
    """REST API: Get scan result details."""
    scan_result = get_object_or_404(ScanResult, id=result_id)

    data = {
        'id': str(scan_result.id),
        'target': scan_result.scan_target.target,
        'started_at': scan_result.started_at.isoformat() if scan_result.started_at else None,
        'completed_at': scan_result.completed_at.isoformat() if scan_result.completed_at else None,
        'duration_seconds': scan_result.duration_seconds,
        'host_discovered': scan_result.host_discovered,
        'open_ports_count': scan_result.open_ports_count,
        'summary': scan_result.summary,
        'port_scans': list(scan_result.port_scans.values('port', 'protocol', 'state', 'service_name')),
        'os_fingerprints': list(scan_result.os_fingerprints.values('os_name', 'os_family', 'accuracy')),
        'vulnerability_findings': list(
            scan_result.vulnerability_findings.values(
                'cve_id', 'cvss_score', 'severity', 'title'
            )
        ),
    }
    return JsonResponse(data)


@login_required
@require_http_methods(["POST"])
def api_vulnerability_scan(request):
    """REST API: Run vulnerability scan against a target."""
    try:
        data = json.loads(request.body)
        target = data.get('target')
        port = int(data.get('port', 80))
        service = data.get('service', '')
        version = data.get('version', '')

        if not target:
            return JsonResponse({'error': 'target is required'}, status=400)

        scanner = VulnerabilityScanner()
        results = scanner.scan_target(target, port, service, version)

        return JsonResponse({
            'target': target,
            'port': port,
            'cve_count': len(results.get('cve_findings', [])),
            'risk_score': results.get('risk_score', 0),
            'results': results,
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def api_threat_intel_check(request):
    """REST API: Check indicators against threat intelligence."""
    try:
        data = json.loads(request.body)
        engine = ThreatIntelligenceEngine()
        matches = engine.scan_iocs(data)

        return JsonResponse({
            'total_iocs_checked': sum(len(v) for v in data.values() if isinstance(v, list)),
            'matches_found': len(matches),
            'matches': matches,
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
