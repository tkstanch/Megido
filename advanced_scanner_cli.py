#!/usr/bin/env python3
"""
Advanced Multi-Engine Scanner CLI

Command-line interface for the multi-engine vulnerability scanner.
Provides advanced features including scan management, result analysis, and reporting.

Usage:
    python advanced_scanner_cli.py list-engines
    python advanced_scanner_cli.py scan /path/to/target
    python advanced_scanner_cli.py scan /path/to/target --engines bandit semgrep
    python advanced_scanner_cli.py scan /path/to/target --categories sast secrets
    python advanced_scanner_cli.py list-scans
    python advanced_scanner_cli.py show-scan <scan_id>
    python advanced_scanner_cli.py export-report <scan_id> --format html
"""

import os
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
import django
django.setup()

from scanner.engine_plugins import get_engine_registry, EngineOrchestrator
from scanner.engine_plugins.engine_service import EngineService
from scanner.models import EngineScan


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    """Print CLI banner"""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     Megido Advanced Multi-Engine Vulnerability Scanner       ║
║                  Command-Line Interface                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
    print(banner)


def list_engines(args):
    """List all available engines"""
    print_banner()
    print(f"\n{Colors.HEADER}Available Scanner Engines{Colors.ENDC}\n")
    
    registry = get_engine_registry()
    engines = registry.list_engines()
    
    # Group by category
    by_category = {}
    for engine in engines:
        cat = engine['category']
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(engine)
    
    for category, cat_engines in sorted(by_category.items()):
        print(f"{Colors.BOLD}{category.upper()}{Colors.ENDC}")
        for engine in cat_engines:
            status_icon = f"{Colors.GREEN}✓{Colors.ENDC}" if engine['available'] else f"{Colors.RED}✗{Colors.ENDC}"
            print(f"  {status_icon} {Colors.CYAN}{engine['name']}{Colors.ENDC}")
            print(f"      ID: {engine['engine_id']}")
            print(f"      Version: {engine['version']}")
            print(f"      Status: {'Available' if engine['available'] else 'Not installed'}")
            print()


def run_scan(args):
    """Run a new scan"""
    print_banner()
    
    target = args.target
    if not os.path.exists(target):
        print(f"{Colors.RED}Error: Target path does not exist: {target}{Colors.ENDC}")
        return 1
    
    print(f"\n{Colors.HEADER}Starting Multi-Engine Scan{Colors.ENDC}")
    print(f"Target: {Colors.CYAN}{target}{Colors.ENDC}")
    
    # Initialize service
    service = EngineService()
    
    # Create scan
    print(f"\n{Colors.YELLOW}Creating scan...{Colors.ENDC}")
    scan = service.create_scan(
        target_path=target,
        target_type='path',
        engine_ids=args.engines if args.engines else None,
        categories=args.categories if args.categories else None,
        parallel=not args.sequential,
        max_workers=args.workers,
        created_by='cli'
    )
    
    print(f"{Colors.GREEN}✓{Colors.ENDC} Scan created with ID: {Colors.BOLD}{scan.id}{Colors.ENDC}")
    
    # Execute scan
    print(f"\n{Colors.YELLOW}Executing scan...{Colors.ENDC}")
    try:
        result = service.execute_scan(scan)
        
        # Display results
        print(f"\n{Colors.GREEN}✓ Scan completed successfully!{Colors.ENDC}\n")
        
        summary = result['summary']
        print(f"{Colors.HEADER}Scan Summary{Colors.ENDC}")
        print(f"  Execution Time: {summary['execution_time']:.2f}s")
        print(f"  Engines Run: {summary['total_engines']}")
        print(f"  Successful: {Colors.GREEN}{summary['successful_engines']}{Colors.ENDC}")
        print(f"  Failed: {Colors.RED}{summary['failed_engines']}{Colors.ENDC}")
        print(f"  Total Findings: {Colors.BOLD}{summary['total_findings']}{Colors.ENDC}")
        
        if summary['findings_by_severity']:
            print(f"\n  Findings by Severity:")
            severity_colors = {
                'critical': Colors.RED,
                'high': Colors.RED,
                'medium': Colors.YELLOW,
                'low': Colors.BLUE,
                'info': Colors.CYAN,
            }
            for sev, count in sorted(summary['findings_by_severity'].items()):
                color = severity_colors.get(sev, Colors.ENDC)
                print(f"    {color}{sev.upper()}: {count}{Colors.ENDC}")
        
        print(f"\n{Colors.CYAN}View detailed results with:{Colors.ENDC}")
        print(f"  python {sys.argv[0]} show-scan {scan.id}")
        
        return 0
    
    except Exception as e:
        print(f"\n{Colors.RED}✗ Scan failed: {e}{Colors.ENDC}")
        return 1


def list_scans(args):
    """List recent scans"""
    print_banner()
    print(f"\n{Colors.HEADER}Recent Scans{Colors.ENDC}\n")
    
    service = EngineService()
    history = service.get_scan_history(limit=args.limit)
    
    if not history:
        print("No scans found.")
        return
    
    for scan in history:
        status_colors = {
            'completed': Colors.GREEN,
            'failed': Colors.RED,
            'running': Colors.YELLOW,
            'pending': Colors.CYAN,
        }
        color = status_colors.get(scan['status'], Colors.ENDC)
        
        print(f"  {Colors.BOLD}ID {scan['id']}{Colors.ENDC} - {color}{scan['status'].upper()}{Colors.ENDC}")
        print(f"    Target: {scan['target_path']}")
        print(f"    Started: {scan['started_at']}")
        print(f"    Findings: {scan['total_findings']}")
        print(f"    Engines: {scan['successful_engines']} successful")
        print()


def show_scan(args):
    """Show detailed scan results"""
    print_banner()
    
    scan_id = args.scan_id
    service = EngineService()
    
    # Get summary
    print(f"\n{Colors.HEADER}Scan Details - ID {scan_id}{Colors.ENDC}\n")
    summary = service.get_scan_summary(scan_id)
    
    if 'error' in summary:
        print(f"{Colors.RED}Error: {summary['error']}{Colors.ENDC}")
        return 1
    
    # Display summary
    print(f"{Colors.BOLD}Target:{Colors.ENDC} {summary['target_path']}")
    print(f"{Colors.BOLD}Status:{Colors.ENDC} {summary['status']}")
    print(f"{Colors.BOLD}Started:{Colors.ENDC} {summary['started_at']}")
    if summary['completed_at']:
        print(f"{Colors.BOLD}Completed:{Colors.ENDC} {summary['completed_at']}")
    print(f"{Colors.BOLD}Execution Time:{Colors.ENDC} {summary['execution_time']:.2f}s")
    print(f"{Colors.BOLD}Total Findings:{Colors.ENDC} {summary['total_findings']}")
    
    # Get findings
    print(f"\n{Colors.HEADER}Findings{Colors.ENDC}\n")
    
    severity_filter = args.severity if args.severity else None
    findings = service.get_scan_findings(
        scan_id=scan_id,
        severity=severity_filter,
        exclude_duplicates=not args.include_duplicates
    )
    
    if not findings:
        print("No findings.")
        return
    
    # Group by severity
    by_severity = {}
    for finding in findings:
        sev = finding['severity']
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(finding)
    
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    for sev in severity_order:
        if sev not in by_severity:
            continue
        
        sev_findings = by_severity[sev]
        severity_colors = {
            'critical': Colors.RED,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.BLUE,
            'info': Colors.CYAN,
        }
        color = severity_colors.get(sev, Colors.ENDC)
        
        print(f"{color}{Colors.BOLD}{sev.upper()} ({len(sev_findings)} findings){Colors.ENDC}")
        
        for i, finding in enumerate(sev_findings[:args.max_findings], 1):
            print(f"\n  {i}. {Colors.BOLD}{finding['title']}{Colors.ENDC}")
            print(f"     Engine: {finding['engine_name']}")
            if finding['file_path']:
                location = finding['file_path']
                if finding['line_number']:
                    location += f":{finding['line_number']}"
                print(f"     Location: {location}")
            if finding['cwe_id']:
                print(f"     CWE: {finding['cwe_id']}")
            if args.verbose and finding['description']:
                print(f"     Description: {finding['description'][:200]}...")
        
        if len(sev_findings) > args.max_findings:
            print(f"\n  ... and {len(sev_findings) - args.max_findings} more {sev} findings")
        print()


def export_report(args):
    """Export scan report"""
    print_banner()
    
    scan_id = args.scan_id
    format_type = args.format
    output_file = args.output
    
    print(f"\n{Colors.YELLOW}Exporting scan {scan_id} to {format_type.upper()}...{Colors.ENDC}")
    
    service = EngineService()
    summary = service.get_scan_summary(scan_id)
    findings = service.get_scan_findings(scan_id, exclude_duplicates=True)
    
    if format_type == 'json':
        data = {
            'summary': summary,
            'findings': findings
        }
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    elif format_type == 'html':
        # Generate HTML report
        html = generate_html_report(summary, findings)
        with open(output_file, 'w') as f:
            f.write(html)
    
    elif format_type == 'csv':
        # Generate CSV report
        import csv
        with open(output_file, 'w', newline='') as f:
            if findings:
                writer = csv.DictWriter(f, fieldnames=findings[0].keys())
                writer.writeheader()
                writer.writerows(findings)
    
    print(f"{Colors.GREEN}✓ Report exported to: {output_file}{Colors.ENDC}")


def generate_html_report(summary, findings):
    """Generate HTML report"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Megido Scan Report - {summary['id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ background: #f9f9f9; padding: 15px; margin: 20px 0; border-left: 4px solid #4CAF50; }}
        .finding {{ background: white; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-left: 4px solid #ff9800; }}
        .critical {{ border-left-color: #f44336; }}
        .high {{ border-left-color: #ff5722; }}
        .medium {{ border-left-color: #ff9800; }}
        .low {{ border-left-color: #2196F3; }}
        .info {{ border-left-color: #9E9E9E; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #f44336; }}
        .badge-high {{ background: #ff5722; }}
        .badge-medium {{ background: #ff9800; }}
        .badge-low {{ background: #2196F3; }}
        .badge-info {{ background: #9E9E9E; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Megido Multi-Engine Scan Report</h1>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Scan ID:</strong> {summary['id']}</p>
            <p><strong>Target:</strong> {summary['target_path']}</p>
            <p><strong>Status:</strong> {summary['status']}</p>
            <p><strong>Execution Time:</strong> {summary['execution_time']:.2f}s</p>
            <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
            <p><strong>Engines Run:</strong> {summary['successful_engines']}/{summary['total_engines_run']}</p>
        </div>
        
        <h2>Findings ({len(findings)})</h2>
    """
    
    for finding in findings:
        sev = finding['severity']
        html += f"""
        <div class="finding {sev}">
            <h3><span class="badge badge-{sev}">{sev.upper()}</span> {finding['title']}</h3>
            <p><strong>Engine:</strong> {finding['engine_name']}</p>
            <p><strong>Description:</strong> {finding['description']}</p>
            {'<p><strong>File:</strong> ' + finding['file_path'] + '</p>' if finding.get('file_path') else ''}
            {'<p><strong>CWE:</strong> ' + finding['cwe_id'] + '</p>' if finding.get('cwe_id') else ''}
            {'<p><strong>Remediation:</strong> ' + finding['remediation'] + '</p>' if finding.get('remediation') else ''}
        </div>
        """
    
    html += """
    </div>
</body>
</html>
    """
    
    return html


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Multi-Engine Vulnerability Scanner CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # list-engines command
    list_engines_parser = subparsers.add_parser('list-engines', help='List all available scanner engines')
    list_engines_parser.set_defaults(func=list_engines)
    
    # scan command
    scan_parser = subparsers.add_parser('scan', help='Run a new vulnerability scan')
    scan_parser.add_argument('target', help='Target path to scan')
    scan_parser.add_argument('--engines', nargs='+', help='Specific engines to run')
    scan_parser.add_argument('--categories', nargs='+', help='Engine categories to run (sast, dast, sca, secrets)')
    scan_parser.add_argument('--sequential', action='store_true', help='Run engines sequentially instead of parallel')
    scan_parser.add_argument('--workers', type=int, default=4, help='Max parallel workers (default: 4)')
    scan_parser.set_defaults(func=run_scan)
    
    # list-scans command
    list_scans_parser = subparsers.add_parser('list-scans', help='List recent scans')
    list_scans_parser.add_argument('--limit', type=int, default=10, help='Number of scans to show (default: 10)')
    list_scans_parser.set_defaults(func=list_scans)
    
    # show-scan command
    show_scan_parser = subparsers.add_parser('show-scan', help='Show detailed scan results')
    show_scan_parser.add_argument('scan_id', type=int, help='Scan ID to show')
    show_scan_parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'info'], help='Filter by severity')
    show_scan_parser.add_argument('--include-duplicates', action='store_true', help='Include duplicate findings')
    show_scan_parser.add_argument('--max-findings', type=int, default=10, help='Max findings per severity (default: 10)')
    show_scan_parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    show_scan_parser.set_defaults(func=show_scan)
    
    # export-report command
    export_parser = subparsers.add_parser('export-report', help='Export scan report')
    export_parser.add_argument('scan_id', type=int, help='Scan ID to export')
    export_parser.add_argument('--format', choices=['json', 'html', 'csv'], default='html', help='Report format')
    export_parser.add_argument('--output', default='scan_report.html', help='Output filename')
    export_parser.set_defaults(func=export_report)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Interrupted by user{Colors.ENDC}")
        return 1
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

def generate_dashboard(args):
    """Generate interactive dashboard"""
    print_banner()
    
    scan_id = args.scan_id
    output_file = args.output
    
    print(f"\n{Colors.YELLOW}Generating interactive dashboard for scan {scan_id}...{Colors.ENDC}")
    
    service = EngineService()
    
    # Get scan data
    summary = service.get_scan_summary(scan_id)
    if 'error' in summary:
        print(f"{Colors.RED}Error: {summary['error']}{Colors.ENDC}")
        return 1
    
    findings = service.get_scan_findings(scan_id, exclude_duplicates=True)
    
    # Get historical data if requested
    historical = None
    if args.include_trends:
        historical = service.get_scan_history(limit=10)
    
    # Generate dashboard
    from scanner.engine_plugins.dashboard_generator import DashboardGenerator
    
    generator = DashboardGenerator()
    html = generator.generate_dashboard(summary, findings, historical)
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"{Colors.GREEN}✓ Interactive dashboard generated: {output_file}{Colors.ENDC}")
    print(f"\n{Colors.CYAN}Open in browser to view interactive charts and visualizations!{Colors.ENDC}")
    
    return 0


def prioritize_findings(args):
    """Prioritize findings using ML"""
    print_banner()
    
    scan_id = args.scan_id
    
    print(f"\n{Colors.YELLOW}Prioritizing findings for scan {scan_id} using ML...{Colors.ENDC}")
    
    service = EngineService()
    findings = service.get_scan_findings(scan_id, exclude_duplicates=True)
    
    if not findings:
        print("No findings to prioritize.")
        return 0
    
    # Apply ML prioritization
    from scanner.engine_plugins.ml_prioritizer import VulnerabilityPrioritizer
    
    prioritizer = VulnerabilityPrioritizer()
    prioritized = prioritizer.prioritize_batch(findings)
    
    print(f"\n{Colors.HEADER}Prioritized Findings (Top 20){Colors.ENDC}\n")
    
    for i, finding in enumerate(prioritized[:20], 1):
        priority_level = finding['priority_level']
        priority_score = finding['priority_score']
        
        # Color based on priority
        if priority_level == 'critical':
            color = Colors.RED
        elif priority_level == 'high':
            color = Colors.YELLOW
        else:
            color = Colors.BLUE
        
        print(f"{i}. {color}[{priority_level.upper()} - {priority_score:.0f}]{Colors.ENDC} {finding['title']}")
        print(f"   Engine: {finding['engine_name']}")
        print(f"   Reasoning: {finding.get('priority_reasoning', 'N/A')}")
        print()
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(prioritized, f, indent=2, default=str)
        print(f"{Colors.GREEN}✓ Prioritized findings saved to: {args.output}{Colors.ENDC}")
    
    return 0


# Add the new commands to the parser in main()
# Modify the existing main() function to add these commands

