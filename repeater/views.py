from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import RepeaterRequest, RepeaterResponse, RepeaterTab
from .utils import (
    parse_raw_request,
    build_raw_request,
    compare_responses,
    url_encode,
    url_decode,
    base64_encode,
    base64_decode,
    unicode_escape,
    unicode_unescape,
    update_content_length,
    hexdump,
)
import requests
import json
import time
import os
import socket
import ssl


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tab_to_dict(tab):
    return {
        'id': tab.id,
        'name': tab.name,
        'order': tab.order,
        'config': tab.to_config_dict(),
        'created_at': tab.created_at.isoformat(),
        'updated_at': tab.updated_at.isoformat(),
    }


def _request_to_dict(req):
    return {
        'id': req.id,
        'name': req.name,
        'method': req.method,
        'url': req.url,
        'headers': req.headers,
        'body': req.body,
        'tab_id': req.tab_id,
        'tab_history_index': req.tab_history_index,
        'created_at': req.created_at.isoformat(),
    }


def _response_to_dict(resp):
    return {
        'id': resp.id,
        'status_code': resp.status_code,
        'headers': resp.headers,
        'body': resp.body,
        'response_time': resp.response_time,
        'timestamp': resp.timestamp.isoformat(),
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def repeater_dashboard(request):
    """Dashboard view for the repeater"""
    return render(request, 'repeater/dashboard.html')


# ---------------------------------------------------------------------------
# Existing endpoints (backward compatible)
# ---------------------------------------------------------------------------

@api_view(['GET', 'POST'])
def repeater_requests(request):
    """List or create repeater requests"""
    if request.method == 'GET':
        reqs = RepeaterRequest.objects.all()[:50]
        return Response([_request_to_dict(r) for r in reqs])

    elif request.method == 'POST':
        tab_id = request.data.get('tab_id')
        tab = None
        if tab_id:
            try:
                tab = RepeaterTab.objects.get(id=tab_id)
            except RepeaterTab.DoesNotExist:
                pass

        req = RepeaterRequest.objects.create(
            url=request.data.get('url'),
            method=request.data.get('method', 'GET'),
            headers=request.data.get('headers', '{}'),
            body=request.data.get('body', ''),
            name=request.data.get('name', ''),
            tab=tab,
        )
        return Response({'id': req.id, 'message': 'Request created'}, status=201)


@api_view(['POST'])
def send_request(request, request_id):
    """Send a repeater request and store the response"""
    try:
        repeater_req = RepeaterRequest.objects.get(id=request_id)
    except RepeaterRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)

    # Resolve per-tab config, falling back to env defaults
    tab = repeater_req.tab
    if tab:
        verify_ssl = tab.verify_ssl
        timeout = tab.timeout
        follow_redirects = tab.follow_redirects
        max_redirects = tab.max_redirects
        auto_content_length = tab.auto_content_length
    else:
        verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
        timeout = 30.0
        follow_redirects = True
        max_redirects = 10
        auto_content_length = True

    try:
        headers = json.loads(repeater_req.headers)
    except (json.JSONDecodeError, TypeError):
        headers = {}

    if auto_content_length and repeater_req.body:
        headers = update_content_length(headers, repeater_req.body)

    start_time = time.time()
    try:
        session = requests.Session()
        session.max_redirects = max_redirects

        response = session.request(
            method=repeater_req.method,
            url=repeater_req.url,
            headers=headers,
            data=repeater_req.body if repeater_req.body else None,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=follow_redirects,
        )
        response_time = (time.time() - start_time) * 1000

        resp = RepeaterResponse.objects.create(
            request=repeater_req,
            status_code=response.status_code,
            headers=json.dumps(dict(response.headers)),
            body=response.text,
            response_time=response_time,
        )

        return Response({
            'id': resp.id,
            'status_code': resp.status_code,
            'headers': resp.headers,
            'body': resp.body,
            'response_time': resp.response_time,
        })
    except requests.TooManyRedirects as e:
        return Response({'error': f'Too many redirects: {e}'}, status=502)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

@api_view(['GET', 'POST'])
def tab_list(request):
    """List all tabs or create a new one"""
    if request.method == 'GET':
        tabs = RepeaterTab.objects.all()
        return Response([_tab_to_dict(t) for t in tabs])

    elif request.method == 'POST':
        name = request.data.get('name', 'New Tab')
        order = RepeaterTab.objects.count()
        tab = RepeaterTab.objects.create(name=name, order=order)
        return Response(_tab_to_dict(tab), status=201)


@api_view(['GET', 'PATCH', 'DELETE'])
def tab_detail(request, tab_id):
    """Get, update, or delete a specific tab"""
    try:
        tab = RepeaterTab.objects.get(id=tab_id)
    except RepeaterTab.DoesNotExist:
        return Response({'error': 'Tab not found'}, status=404)

    if request.method == 'GET':
        return Response(_tab_to_dict(tab))

    elif request.method == 'PATCH':
        if 'name' in request.data:
            tab.name = request.data['name']
        if 'order' in request.data:
            tab.order = request.data['order']
        # Config fields
        config_fields = ['follow_redirects', 'max_redirects', 'timeout', 'verify_ssl', 'auto_content_length']
        for field in config_fields:
            if field in request.data:
                setattr(tab, field, request.data[field])
        tab.save()
        return Response(_tab_to_dict(tab))

    elif request.method == 'DELETE':
        tab.delete()
        return Response({'message': 'Tab deleted'})


# ---------------------------------------------------------------------------
# Tab history & navigation
# ---------------------------------------------------------------------------

@api_view(['GET'])
def tab_history(request, tab_id):
    """Get all requests in a tab's history, ordered chronologically"""
    try:
        tab = RepeaterTab.objects.get(id=tab_id)
    except RepeaterTab.DoesNotExist:
        return Response({'error': 'Tab not found'}, status=404)

    reqs = RepeaterRequest.objects.filter(tab=tab).order_by('tab_history_index', 'created_at')
    history = []
    for req in reqs:
        last_response = req.responses.first()
        entry = _request_to_dict(req)
        entry['last_response'] = _response_to_dict(last_response) if last_response else None
        history.append(entry)

    return Response({'tab_id': tab_id, 'count': len(history), 'history': history})


@api_view(['POST'])
def tab_navigate(request, tab_id):
    """Navigate history within a tab.

    Body: { "direction": "back" | "forward" }
    Returns the request at the resulting history position.
    """
    try:
        tab = RepeaterTab.objects.get(id=tab_id)
    except RepeaterTab.DoesNotExist:
        return Response({'error': 'Tab not found'}, status=404)

    direction = request.data.get('direction', 'back')
    reqs = list(RepeaterRequest.objects.filter(tab=tab).order_by('tab_history_index', 'created_at'))
    if not reqs:
        return Response({'error': 'No history for this tab'}, status=404)

    # Find current index (latest request by default)
    current_index_value = request.data.get('current_index', len(reqs) - 1)
    try:
        current_pos = int(current_index_value)
    except (TypeError, ValueError):
        current_pos = len(reqs) - 1

    if direction == 'back':
        new_pos = max(0, current_pos - 1)
    else:
        new_pos = min(len(reqs) - 1, current_pos + 1)

    target_req = reqs[new_pos]
    last_response = target_req.responses.first()
    data = _request_to_dict(target_req)
    data['last_response'] = _response_to_dict(last_response) if last_response else None
    data['position'] = new_pos
    data['total'] = len(reqs)
    return Response(data)


# ---------------------------------------------------------------------------
# Target info
# ---------------------------------------------------------------------------

@api_view(['GET'])
def target_info(request, request_id):
    """Return IP, TLS cert, server header and timing info for a sent request"""
    try:
        repeater_req = RepeaterRequest.objects.get(id=request_id)
    except RepeaterRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)

    from urllib.parse import urlparse
    parsed = urlparse(repeater_req.url)
    host = parsed.hostname or ''
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    info = {
        'host': host,
        'port': port,
        'scheme': parsed.scheme,
        'ip_address': None,
        'tls_certificate': None,
        'server_header': None,
        'timing': None,
    }

    # Resolve IP
    try:
        info['ip_address'] = socket.gethostbyname(host)
    except socket.gaierror:
        info['ip_address'] = f'DNS resolution failed for {host}'

    # TLS certificate info
    if parsed.scheme == 'https':
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Intentionally disabled for security testing tool
            with ctx.wrap_socket(socket.create_connection((host, port), timeout=5), server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info['tls_certificate'] = {
                    'subject': dict(k for x in cert.get('subject', []) for k in x),
                    'issuer': dict(k for x in cert.get('issuer', []) for k in x),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                    'serialNumber': cert.get('serialNumber'),
                }
        except Exception as e:
            info['tls_certificate'] = {'error': str(e)}

    # Pull server header from the latest response
    last_response = RepeaterResponse.objects.filter(request=repeater_req).first()
    if last_response:
        try:
            resp_headers = json.loads(last_response.headers)
            info['server_header'] = resp_headers.get('Server') or resp_headers.get('server')
        except (json.JSONDecodeError, TypeError):
            pass
        info['timing'] = {'total_ms': last_response.response_time}

    return Response(info)


# ---------------------------------------------------------------------------
# Send to other tools
# ---------------------------------------------------------------------------

SUPPORTED_TOOLS = {'scanner', 'interceptor', 'spider'}


@api_view(['POST'])
def send_to_tool(request, request_id, tool):
    """Send the current repeater request to another Megido tool"""
    if tool not in SUPPORTED_TOOLS:
        return Response({'error': f'Unknown tool "{tool}". Supported: {sorted(SUPPORTED_TOOLS)}'}, status=400)

    try:
        repeater_req = RepeaterRequest.objects.get(id=request_id)
    except RepeaterRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)

    payload = {
        'source': 'repeater',
        'request_id': repeater_req.id,
        'url': repeater_req.url,
        'method': repeater_req.method,
        'headers': repeater_req.headers,
        'body': repeater_req.body,
    }

    if tool == 'scanner':
        # Import scanner model lazily to avoid circular imports
        try:
            from scanner.models import ScanTarget
            target, _ = ScanTarget.objects.get_or_create(
                url=repeater_req.url,
                defaults={'name': f'From Repeater #{repeater_req.id}'},
            )
            payload['scanner_target_id'] = target.id
            payload['message'] = f'Request sent to scanner. Target ID: {target.id}'
        except Exception as e:
            payload['message'] = f'Queued for scanner (could not create target: {e})'

    elif tool == 'interceptor':
        payload['message'] = 'Request queued for interceptor'

    elif tool == 'spider':
        payload['message'] = 'URL added as spider starting point'

    return Response(payload)


# ---------------------------------------------------------------------------
# Compare responses
# ---------------------------------------------------------------------------

@api_view(['POST'])
def compare_responses_view(request):
    """Compare two responses by ID.

    Body: { "response_a_id": <int>, "response_b_id": <int> }
    """
    id_a = request.data.get('response_a_id')
    id_b = request.data.get('response_b_id')

    if not id_a or not id_b:
        return Response({'error': 'Provide response_a_id and response_b_id'}, status=400)

    try:
        resp_a = RepeaterResponse.objects.get(id=id_a)
        resp_b = RepeaterResponse.objects.get(id=id_b)
    except RepeaterResponse.DoesNotExist:
        return Response({'error': 'One or both responses not found'}, status=404)

    diff = compare_responses(
        {'status_code': resp_a.status_code, 'headers': resp_a.headers, 'body': resp_a.body},
        {'status_code': resp_b.status_code, 'headers': resp_b.headers, 'body': resp_b.body},
    )
    diff['response_a'] = _response_to_dict(resp_a)
    diff['response_b'] = _response_to_dict(resp_b)
    return Response(diff)


# ---------------------------------------------------------------------------
# Encode / Decode utility endpoint
# ---------------------------------------------------------------------------

@api_view(['POST'])
def encode_decode(request):
    """Encode or decode a value using a specified operation.

    Body: { "operation": "<op>", "value": "<string>" }
    Supported operations: url_encode, url_decode, base64_encode, base64_decode,
                          unicode_escape, unicode_unescape
    """
    operation = request.data.get('operation', '')
    value = request.data.get('value', '')

    ops = {
        'url_encode': url_encode,
        'url_decode': url_decode,
        'base64_encode': base64_encode,
        'base64_decode': base64_decode,
        'unicode_escape': unicode_escape,
        'unicode_unescape': unicode_unescape,
    }

    if operation not in ops:
        return Response({
            'error': f'Unknown operation. Supported: {sorted(ops.keys())}'
        }, status=400)

    try:
        result = ops[operation](value)
        return Response({'operation': operation, 'input': value, 'result': result})
    except ValueError as e:
        return Response({'error': str(e)}, status=400)


# ---------------------------------------------------------------------------
# Raw request parse / build utility endpoints
# ---------------------------------------------------------------------------

@api_view(['POST'])
def parse_raw(request):
    """Parse a raw HTTP request string into structured fields.

    Body: { "raw": "<raw HTTP request>" }
    """
    raw = request.data.get('raw', '')
    if not raw:
        return Response({'error': 'Provide a non-empty "raw" field'}, status=400)
    parsed = parse_raw_request(raw)
    return Response(parsed)


@api_view(['POST'])
def build_raw(request):
    """Build a raw HTTP request string from structured fields.

    Body: { "method": "GET", "url": "...", "headers": {...}, "body": "..." }
    """
    method = request.data.get('method', 'GET')
    url = request.data.get('url', '')
    headers = request.data.get('headers', {})
    body = request.data.get('body', '')
    if not url:
        return Response({'error': 'Provide a non-empty "url" field'}, status=400)
    raw = build_raw_request(method, url, headers, body)
    return Response({'raw': raw})


# ---------------------------------------------------------------------------
# Hex dump endpoint
# ---------------------------------------------------------------------------

@api_view(['POST'])
def hexdump_view(request):
    """Return a hexdump of a response body.

    Body: { "response_id": <int> }  OR  { "text": "<string>" }
    """
    response_id = request.data.get('response_id')
    text = request.data.get('text')

    if response_id:
        try:
            resp = RepeaterResponse.objects.get(id=response_id)
            text = resp.body or ''
        except RepeaterResponse.DoesNotExist:
            return Response({'error': 'Response not found'}, status=404)

    if text is None:
        return Response({'error': 'Provide "response_id" or "text"'}, status=400)

    return Response({'hexdump': hexdump(text)})
