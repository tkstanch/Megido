"""
Response Analysis Module

This module provides utility functions to automatically analyze HTTP responses
from attack routines and detect vulnerabilities. It integrates with the Vulnerability
model to store positive findings with full evidence.

Example usage in your attack logic:
    
    import requests
    from response_analyser.analyse import analyze_xss_response, analyze_sqli_response
    
    # After making an attack request
    response = requests.get(target_url, params={'input': xss_payload})
    
    # Analyze the response for XSS
    analyze_xss_response(
        target_url=target_url,
        payload=xss_payload,
        response=response,
        request_method='GET',
        request_params={'input': xss_payload}
    )
"""

from urllib.parse import urlparse
import json
from .models import Vulnerability


def extract_endpoint(url):
    """
    Extract normalized endpoint from URL for grouping.
    Example: https://example.com/api/users/123 -> /api/users/{id}
    """
    parsed = urlparse(url)
    path = parsed.path
    
    # Simple normalization: replace numeric IDs with {id}
    import re
    path = re.sub(r'/\d+', '/{id}', path)
    
    return path


def analyze_xss_response(target_url, payload, response, request_method='GET', 
                         request_headers=None, request_params=None, notes=''):
    """
    Analyze HTTP response for XSS vulnerabilities.
    
    Checks if the payload is reflected in the response without proper encoding.
    
    Args:
        target_url: The target URL that was tested
        payload: The XSS payload that was sent
        response: The HTTP response object (from requests library)
        request_method: HTTP method used (GET, POST, etc.)
        request_headers: Dict of request headers
        request_params: Dict or string of request parameters/body
        notes: Additional notes about the test
    
    Returns:
        Vulnerability object if XSS detected, None otherwise
    """
    # Check if payload is reflected without encoding
    if payload in response.text:
        # Create vulnerability record
        vuln = Vulnerability.objects.create(
            attack_type='xss',
            severity='high',
            target_url=target_url,
            payload=payload,
            request_method=request_method,
            request_headers=json.dumps(dict(request_headers or {})),
            request_body=json.dumps(request_params) if request_params else '',
            response_status_code=response.status_code,
            response_headers=json.dumps(dict(response.headers)),
            response_body=response.text[:10000],  # Limit size
            evidence_html=response.text[:50000],  # Store more for HTML view
            endpoint=extract_endpoint(target_url),
            notes=notes or f'Payload reflected without encoding: {payload[:100]}'
        )
        return vuln
    
    return None


def analyze_sqli_response(target_url, payload, response, baseline_response=None,
                          request_method='GET', request_headers=None, 
                          request_params=None, notes=''):
    """
    Analyze HTTP response for SQL injection vulnerabilities.
    
    Detects SQL errors or behavior changes that indicate SQL injection.
    
    Args:
        target_url: The target URL that was tested
        payload: The SQLi payload that was sent
        response: The HTTP response object
        baseline_response: Optional baseline response for comparison
        request_method: HTTP method used
        request_headers: Dict of request headers
        request_params: Dict or string of request parameters/body
        notes: Additional notes
    
    Returns:
        Vulnerability object if SQLi detected, None otherwise
    """
    sql_errors = [
        'SQL syntax',
        'mysql_fetch',
        'PostgreSQL.*ERROR',
        'Warning.*mysql_',
        'ORA-[0-9]+',
        'SQLite.*error',
        'Microsoft OLE DB Provider for SQL Server',
        'Unclosed quotation mark',
        'SQLSTATE',
    ]
    
    # Check for SQL error messages
    import re
    for error_pattern in sql_errors:
        if re.search(error_pattern, response.text, re.IGNORECASE):
            vuln = Vulnerability.objects.create(
                attack_type='sqli',
                severity='critical',
                target_url=target_url,
                payload=payload,
                request_method=request_method,
                request_headers=json.dumps(dict(request_headers or {})),
                request_body=json.dumps(request_params) if request_params else '',
                response_status_code=response.status_code,
                response_headers=json.dumps(dict(response.headers)),
                response_body=response.text[:10000],
                evidence_html=response.text[:50000],
                endpoint=extract_endpoint(target_url),
                notes=notes or f'SQL error detected: {error_pattern}'
            )
            return vuln
    
    # Check for significant response differences (time-based or boolean-based)
    if baseline_response:
        size_diff = abs(len(response.text) - len(baseline_response.text))
        if size_diff > 100:  # Significant difference
            vuln = Vulnerability.objects.create(
                attack_type='sqli',
                severity='high',
                target_url=target_url,
                payload=payload,
                request_method=request_method,
                request_headers=json.dumps(dict(request_headers or {})),
                request_body=json.dumps(request_params) if request_params else '',
                response_status_code=response.status_code,
                response_headers=json.dumps(dict(response.headers)),
                response_body=response.text[:10000],
                evidence_html=response.text[:50000],
                endpoint=extract_endpoint(target_url),
                notes=notes or f'Significant response difference detected: {size_diff} bytes'
            )
            return vuln
    
    return None


def analyze_command_injection_response(target_url, payload, response, 
                                       request_method='GET', request_headers=None,
                                       request_params=None, notes=''):
    """
    Analyze HTTP response for command injection vulnerabilities.
    
    Args:
        target_url: The target URL that was tested
        payload: The command injection payload
        response: The HTTP response object
        request_method: HTTP method used
        request_headers: Dict of request headers
        request_params: Dict or string of request parameters/body
        notes: Additional notes
    
    Returns:
        Vulnerability object if command injection detected, None otherwise
    """
    # Common command injection indicators
    indicators = [
        'root:',  # Unix passwd file
        'bin/bash',  # Shell path
        'Windows IP Configuration',  # ipconfig output
        'Volume Serial Number',  # Windows dir output
        'total ',  # ls -la output
        'uid=',  # id command output
    ]
    
    for indicator in indicators:
        if indicator in response.text:
            vuln = Vulnerability.objects.create(
                attack_type='command_injection',
                severity='critical',
                target_url=target_url,
                payload=payload,
                request_method=request_method,
                request_headers=json.dumps(dict(request_headers or {})),
                request_body=json.dumps(request_params) if request_params else '',
                response_status_code=response.status_code,
                response_headers=json.dumps(dict(response.headers)),
                response_body=response.text[:10000],
                evidence_html=response.text[:50000],
                endpoint=extract_endpoint(target_url),
                notes=notes or f'Command injection indicator detected: {indicator}'
            )
            return vuln
    
    return None


def save_vulnerability(attack_type, target_url, payload, response,
                      severity='medium', request_method='GET',
                      request_headers=None, request_params=None, notes=''):
    """
    Generic function to save any vulnerability finding.
    
    Use this when you've confirmed a vulnerability through your custom logic.
    
    Args:
        attack_type: Type of attack (use Vulnerability.ATTACK_TYPES choices)
        target_url: The target URL
        payload: The payload used
        response: The HTTP response object
        severity: Severity level (critical, high, medium, low, info)
        request_method: HTTP method
        request_headers: Request headers dict
        request_params: Request parameters/body
        notes: Additional analysis notes
    
    Returns:
        Created Vulnerability object
    """
    vuln = Vulnerability.objects.create(
        attack_type=attack_type,
        severity=severity,
        target_url=target_url,
        payload=payload,
        request_method=request_method,
        request_headers=json.dumps(dict(request_headers or {})),
        request_body=json.dumps(request_params) if request_params else '',
        response_status_code=response.status_code,
        response_headers=json.dumps(dict(response.headers)),
        response_body=response.text[:10000],
        evidence_html=response.text[:50000],
        endpoint=extract_endpoint(target_url),
        notes=notes
    )
    return vuln


# Example integration with attack routines
def example_attack_integration():
    """
    Example showing how to integrate response analysis into your attack routines.
    
    This is a demonstration - adapt it to your actual attack code.
    """
    import requests
    
    target_url = "https://example.com/search"
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
    ]
    
    for payload in xss_payloads:
        try:
            # Make the attack request
            response = requests.get(
                target_url,
                params={'q': payload},
                timeout=10
            )
            
            # Analyze the response
            vuln = analyze_xss_response(
                target_url=target_url,
                payload=payload,
                response=response,
                request_method='GET',
                request_params={'q': payload},
                notes='Automated XSS scan'
            )
            
            if vuln:
                print(f"[+] XSS vulnerability found: {vuln.id}")
            else:
                print(f"[-] No vulnerability detected with payload: {payload[:50]}")
                
        except Exception as e:
            print(f"[!] Error testing payload: {e}")
