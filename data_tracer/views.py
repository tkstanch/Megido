from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
import json

from .models import (
    ScanTarget, ScanResult, PortScan, ServiceDetection,
    OSFingerprint, PacketCapture, StealthConfiguration, ScanLog
)
from .engine import (
    HostDiscovery, PortScanner, ServiceDetector,
    OSFingerprinter, PacketAnalyzer, StealthManager
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
