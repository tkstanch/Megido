"""
Data export/import utilities for the Discover app.
"""
import json
import csv
from io import StringIO, BytesIO
from datetime import datetime
from django.http import HttpResponse
from django.core.serializers import serialize
from django.db.models import Q
import logging

from .models import Scan, SensitiveFinding, UserActivity

logger = logging.getLogger(__name__)


def export_scan_to_json(scan):
    """
    Export a single scan to JSON format.
    
    Args:
        scan: Scan object
        
    Returns:
        Dict with scan data
    """
    try:
        # Parse JSON fields
        wayback_urls = json.loads(scan.wayback_urls) if scan.wayback_urls else []
        shodan_data = json.loads(scan.shodan_data) if scan.shodan_data else {}
        hunter_data = json.loads(scan.hunter_data) if scan.hunter_data else []
        dork_queries = json.loads(scan.dork_queries) if scan.dork_queries else {}
        dork_results = json.loads(scan.dork_results) if scan.dork_results else {}
    except json.JSONDecodeError:
        wayback_urls = []
        shodan_data = {}
        hunter_data = []
        dork_queries = {}
        dork_results = {}
    
    # Get findings
    findings = []
    for finding in scan.sensitive_findings.all():
        findings.append({
            'type': finding.finding_type,
            'severity': finding.severity,
            'url': finding.url,
            'value': finding.value,
            'context': finding.context,
            'verified': finding.verified,
            'false_positive': finding.false_positive,
            'discovered_at': finding.discovered_at.isoformat(),
        })
    
    return {
        'id': scan.id,
        'target': scan.target,
        'scan_date': scan.scan_date.isoformat(),
        'user': scan.user.username if scan.user else None,
        'wayback_urls': wayback_urls,
        'shodan_data': shodan_data,
        'hunter_data': hunter_data,
        'dork_queries': dork_queries,
        'dork_results': dork_results,
        'total_urls': scan.total_urls,
        'total_emails': scan.total_emails,
        'scan_duration_seconds': scan.scan_duration_seconds,
        'sensitive_scan_completed': scan.sensitive_scan_completed,
        'total_findings': scan.total_findings,
        'high_risk_findings': scan.high_risk_findings,
        'findings': findings,
    }


def export_scans_to_json_file(scans, filename='scans_export.json'):
    """
    Export multiple scans to a JSON file response.
    
    Args:
        scans: QuerySet of Scan objects
        filename: Output filename
        
    Returns:
        HttpResponse with JSON file
    """
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_scans': scans.count(),
        'scans': [export_scan_to_json(scan) for scan in scans]
    }
    
    response = HttpResponse(
        json.dumps(export_data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response


def export_findings_to_csv(findings, filename='findings_export.csv'):
    """
    Export findings to CSV format.
    
    Args:
        findings: QuerySet of SensitiveFinding objects
        filename: Output filename
        
    Returns:
        HttpResponse with CSV file
    """
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Scan Target', 'Finding Type', 'Severity', 'URL', 
        'Value', 'Context', 'Verified', 'False Positive', 
        'Discovered At'
    ])
    
    # Write data
    for finding in findings:
        writer.writerow([
            finding.id,
            finding.scan.target,
            finding.finding_type,
            finding.severity,
            finding.url,
            finding.value[:100],  # Truncate value
            finding.context[:200],  # Truncate context
            finding.verified,
            finding.false_positive,
            finding.discovered_at.isoformat(),
        ])
    
    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response


def export_findings_to_json(findings, filename='findings_export.json'):
    """
    Export findings to JSON format.
    
    Args:
        findings: QuerySet of SensitiveFinding objects
        filename: Output filename
        
    Returns:
        HttpResponse with JSON file
    """
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_findings': findings.count(),
        'findings': []
    }
    
    for finding in findings:
        export_data['findings'].append({
            'id': finding.id,
            'scan_id': finding.scan.id,
            'scan_target': finding.scan.target,
            'finding_type': finding.finding_type,
            'severity': finding.severity,
            'url': finding.url,
            'value': finding.value,
            'context': finding.context,
            'verified': finding.verified,
            'false_positive': finding.false_positive,
            'discovered_at': finding.discovered_at.isoformat(),
        })
    
    response = HttpResponse(
        json.dumps(export_data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response


def export_to_sarif(findings, filename='findings.sarif'):
    """
    Export findings to SARIF (Static Analysis Results Interchange Format).
    
    This is a standard format used by many security tools and can be
    imported into GitHub Security, GitLab, etc.
    
    Args:
        findings: QuerySet of SensitiveFinding objects
        filename: Output filename
        
    Returns:
        HttpResponse with SARIF JSON file
    """
    # Map severity to SARIF levels
    severity_map = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note',
    }
    
    # Build SARIF structure
    sarif = {
        'version': '2.1.0',
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'Megido Discover',
                    'version': '1.0.0',
                    'informationUri': 'https://github.com/tkstanch/Megido',
                    'rules': []
                }
            },
            'results': []
        }]
    }
    
    # Create rules (unique finding types)
    finding_types = set(findings.values_list('finding_type', flat=True))
    for finding_type in finding_types:
        sarif['runs'][0]['tool']['driver']['rules'].append({
            'id': finding_type.replace(' ', '_').lower(),
            'name': finding_type,
            'shortDescription': {
                'text': f'{finding_type} detected'
            },
            'fullDescription': {
                'text': f'Sensitive information of type "{finding_type}" was detected'
            }
        })
    
    # Add results
    for finding in findings:
        rule_id = finding.finding_type.replace(' ', '_').lower()
        sarif['runs'][0]['results'].append({
            'ruleId': rule_id,
            'level': severity_map.get(finding.severity, 'warning'),
            'message': {
                'text': f'{finding.finding_type}: {finding.value[:100]}'
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': finding.url
                    }
                }
            }],
            'properties': {
                'severity': finding.severity,
                'verified': finding.verified,
                'false_positive': finding.false_positive,
                'discovered_at': finding.discovered_at.isoformat(),
            }
        })
    
    response = HttpResponse(
        json.dumps(sarif, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response


def import_scan_from_json(json_data, user=None):
    """
    Import a scan from JSON data.
    
    Args:
        json_data: Dict with scan data
        user: User object to assign the scan to
        
    Returns:
        Scan object
    """
    # Create scan
    scan = Scan.objects.create(
        target=json_data['target'],
        user=user,
        wayback_urls=json.dumps(json_data.get('wayback_urls', [])),
        shodan_data=json.dumps(json_data.get('shodan_data', {})),
        hunter_data=json.dumps(json_data.get('hunter_data', [])),
        dork_queries=json.dumps(json_data.get('dork_queries', {})),
        dork_results=json.dumps(json_data.get('dork_results', {})),
        total_urls=json_data.get('total_urls', 0),
        total_emails=json_data.get('total_emails', 0),
        scan_duration_seconds=json_data.get('scan_duration_seconds', 0),
        sensitive_scan_completed=json_data.get('sensitive_scan_completed', False),
        total_findings=json_data.get('total_findings', 0),
        high_risk_findings=json_data.get('high_risk_findings', 0),
    )
    
    # Create findings
    for finding_data in json_data.get('findings', []):
        SensitiveFinding.objects.create(
            scan=scan,
            url=finding_data['url'],
            finding_type=finding_data['type'],
            value=finding_data['value'],
            context=finding_data.get('context', ''),
            severity=finding_data['severity'],
            verified=finding_data.get('verified', False),
            false_positive=finding_data.get('false_positive', False),
        )
    
    return scan
