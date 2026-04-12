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
from urllib.parse import urlparse, parse_qs, quote
from bypasser.technique_parser import TechniqueParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def apply_bypass_techniques(text, techniques):
    """Apply selected bypass encoding techniques sequentially to text.

    Args:
        text: The input string to transform.
        techniques: A list of technique names (matching TechniqueParser.TRANSFORMATIONS keys).

    Returns:
        A dict with 'original', 'transformed', and 'techniques_applied'.
    """
    transformations = TechniqueParser.TRANSFORMATIONS
    result = text
    applied = []
    for technique in techniques:
        fn = transformations.get(technique)
        if fn is not None:
            result = fn(result)
            applied.append(technique)
    return {
        'original': text,
        'transformed': result,
        'techniques_applied': applied,
    }

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
        'scan_id': req.scan_id,
        'source': req.source,
        'analysis_advice': req.analysis_advice,
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
        qs = RepeaterRequest.objects.all()
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        reqs = qs[:50]
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


@api_view(['GET'])
def repeater_request_detail(request, request_id):
    """Return details of a single RepeaterRequest."""
    try:
        req = RepeaterRequest.objects.get(id=request_id)
    except RepeaterRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)
    return Response(_request_to_dict(req))


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

    # Resolve bypass mode from POST body (optional, backward compatible)
    bypass_mode = request.data.get('bypass_mode')
    bypass_info = None
    url = repeater_req.url
    body = repeater_req.body

    if bypass_mode and bypass_mode.get('enabled'):
        techniques = bypass_mode.get('techniques', [])
        apply_to = bypass_mode.get('apply_to', [])

        if techniques:
            # Apply to URL query parameter values
            if 'url' in apply_to:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                # Build query string manually so the already-transformed values
                # are not re-encoded by urlencode().
                parts = []
                for key, values in params.items():
                    for v in values:
                        transformed = apply_bypass_techniques(v, techniques)['transformed']
                        parts.append(f"{quote(key, safe='')}={transformed}")
                new_query = '&'.join(parts)
                url = parsed._replace(query=new_query).geturl()

            # Apply to header values
            if 'headers' in apply_to:
                headers = {
                    k: apply_bypass_techniques(v, techniques)['transformed']
                    for k, v in headers.items()
                }

            # Apply to body
            if 'body' in apply_to and body:
                body = apply_bypass_techniques(body, techniques)['transformed']

            bypass_info = {
                'techniques_applied': techniques,
                'apply_to': apply_to,
            }

    if auto_content_length and body:
        headers = update_content_length(headers, body)

    start_time = time.time()
    try:
        session = requests.Session()
        session.max_redirects = max_redirects

        response = session.request(
            method=repeater_req.method,
            url=url,
            headers=headers,
            data=body if body else None,
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

        result = {
            'id': resp.id,
            'status_code': resp.status_code,
            'headers': resp.headers,
            'body': resp.body,
            'response_time': resp.response_time,
        }
        if bypass_info:
            result['bypass_info'] = bypass_info
        return Response(result)
    except requests.TooManyRedirects as e:
        return Response({'error': f'Too many redirects: {e}'}, status=502)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
def bypass_techniques(request):
    """Return available bypass encoding techniques with names and descriptions."""
    techniques = TechniqueParser.get_available_transformations()
    return Response([
        {'name': name, 'description': description}
        for name, description in techniques.items()
    ])


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

# Headers that are safe to mark as injectable (avoid breaking the request).
# Keep in sync with the client-side injectableHeaders set in dashboard.html.
_INJECTABLE_HEADERS = {'User-Agent', 'Referer', 'X-Forwarded-For', 'Accept', 'Cookie'}


def parse_injection_points(repeater_request):
    """Parse a RepeaterRequest and return a list of injection point dicts.

    Each dict is compatible with AutoInjector._inject_payload():
    {
        'url': <full URL>,
        'parameter_name': <param name>,
        'parameter_type': 'GET' | 'POST' | 'json' | 'header' | 'cookie',
        'original_value': <current value>,
        'form_action': <base URL without query string>,
        'form_method': <HTTP method>,
    }
    """
    injection_points = []
    url = repeater_request.url
    method = (repeater_request.method or 'GET').upper()

    parsed_url = urlparse(url)
    base_url = parsed_url._replace(query='', fragment='').geturl()

    # ── URL query parameters → GET injection points ──────────────────────────
    qs_params = parse_qs(parsed_url.query, keep_blank_values=True)
    for param_name, values in qs_params.items():
        injection_points.append({
            'url': url,
            'parameter_name': param_name,
            'parameter_type': 'GET',
            'original_value': values[0] if values else '',
            'form_action': base_url,
            'form_method': 'GET',
        })

    # ── Request body ─────────────────────────────────────────────────────────
    body = repeater_request.body or ''
    if body:
        # Determine content type from headers
        try:
            hdrs = json.loads(repeater_request.headers or '{}')
        except (json.JSONDecodeError, TypeError):
            hdrs = {}

        content_type = ''
        for k, v in hdrs.items():
            if k.lower() == 'content-type':
                content_type = str(v).lower()
                break

        if 'application/json' in content_type:
            # JSON body → each top-level key becomes a JSON injection point
            try:
                body_data = json.loads(body)
                if isinstance(body_data, dict):
                    for param_name, param_value in body_data.items():
                        injection_points.append({
                            'url': url,
                            'parameter_name': param_name,
                            'parameter_type': 'json',
                            'original_value': str(param_value) if param_value is not None else '',
                            'form_action': base_url,
                            'form_method': method,
                        })
            except (json.JSONDecodeError, ValueError):
                pass
        else:
            # Assume form-encoded body
            body_params = parse_qs(body, keep_blank_values=True)
            for param_name, values in body_params.items():
                injection_points.append({
                    'url': url,
                    'parameter_name': param_name,
                    'parameter_type': 'POST',
                    'original_value': values[0] if values else '',
                    'form_action': base_url,
                    'form_method': method,
                })

    # ── Injectable headers ────────────────────────────────────────────────────
    try:
        hdrs = json.loads(repeater_request.headers or '{}')
    except (json.JSONDecodeError, TypeError):
        hdrs = {}

    for header_name, header_value in hdrs.items():
        if header_name in _INJECTABLE_HEADERS:
            injection_points.append({
                'url': url,
                'parameter_name': header_name,
                'parameter_type': 'header',
                'original_value': str(header_value),
                'form_action': base_url,
                'form_method': method,
            })

    return injection_points


SUPPORTED_TOOLS = {'scanner', 'interceptor', 'spider', 'manipulator'}


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

    elif tool == 'manipulator':
        try:
            from manipulator.models import AttackCampaign, DiscoveredInjectionPoint
            campaign = AttackCampaign.objects.create(
                name=f'Repeater Injection - Request #{repeater_req.id}',
                target_url=repeater_req.url,
                mode='manual',
                status='pending',
            )
            injection_points = parse_injection_points(repeater_req)
            for ip in injection_points:
                DiscoveredInjectionPoint.objects.create(
                    campaign=campaign,
                    url=ip['url'],
                    parameter_name=ip['parameter_name'],
                    parameter_type=ip['parameter_type'],
                    original_value=ip['original_value'],
                    form_action=ip['form_action'],
                    form_method=ip['form_method'],
                )
            campaign.total_injection_points = len(injection_points)
            campaign.save(update_fields=['total_injection_points'])
            payload['campaign_id'] = campaign.id
            payload['injection_points_found'] = len(injection_points)
            payload['message'] = (
                f'Campaign #{campaign.id} created with {len(injection_points)} '
                f'injection point(s). Open Manipulator to run payloads.'
            )
        except Exception as e:
            payload['message'] = f'Could not create manipulator campaign: {e}'

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



# ---------------------------------------------------------------------------
# Inject Manipulator payloads into a Repeater request
# ---------------------------------------------------------------------------

@api_view(['POST'])
def inject_payloads(request, request_id):
    """Run Manipulator payloads against all injection points in a RepeaterRequest.

    Body (all optional):
      vulnerability_type  – e.g. "XSS", "SQLi"  (filter payloads)
      payload_ids         – list of specific Payload IDs
      max_payloads        – int (limit number of payloads tested)

    Returns:
      campaign_id, total_tested, successful_exploits, results list
    """
    try:
        repeater_req = RepeaterRequest.objects.get(id=request_id)
    except RepeaterRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)

    # ── Parse injection points ────────────────────────────────────────────────
    injection_points = parse_injection_points(repeater_req)
    if not injection_points:
        return Response({'error': 'No injectable parameters found in this request'}, status=400)

    # ── Fetch payloads ────────────────────────────────────────────────────────
    try:
        from manipulator.models import AttackCampaign, DiscoveredInjectionPoint, InjectionResult, Payload
    except ImportError as e:
        return Response({'error': f'Manipulator module not available: {e}'}, status=500)

    vuln_type = request.data.get('vulnerability_type', '')
    payload_ids = request.data.get('payload_ids', [])
    max_payloads = request.data.get('max_payloads')

    payload_qs = Payload.objects.all()
    if vuln_type:
        payload_qs = payload_qs.filter(vulnerability__name__icontains=vuln_type)
    if payload_ids:
        payload_qs = payload_qs.filter(id__in=payload_ids)
    if max_payloads:
        try:
            payload_qs = payload_qs[:int(max_payloads)]
        except (TypeError, ValueError):
            pass

    payloads = list(payload_qs)
    if not payloads:
        return Response({'error': 'No payloads found matching the given filters'}, status=400)

    payload_texts = [p.payload_text for p in payloads]
    payload_map = {p.payload_text: p for p in payloads}

    # ── Create campaign ───────────────────────────────────────────────────────
    campaign = AttackCampaign.objects.create(
        name=f'Repeater Injection - Request #{repeater_req.id}',
        target_url=repeater_req.url,
        mode='manual',
        status='injecting',
    )

    # Create DiscoveredInjectionPoint records and keep mapping to dicts
    db_injection_points = []
    for ip in injection_points:
        dip = DiscoveredInjectionPoint.objects.create(
            campaign=campaign,
            url=ip['url'],
            parameter_name=ip['parameter_name'],
            parameter_type=ip['parameter_type'],
            original_value=ip['original_value'],
            form_action=ip['form_action'],
            form_method=ip['form_method'],
        )
        db_injection_points.append((dip, ip))

    campaign.total_injection_points = len(db_injection_points)
    campaign.save(update_fields=['total_injection_points'])

    # ── Run injection ─────────────────────────────────────────────────────────
    try:
        from manipulator.auto_injector import AutoInjector
        injector = AutoInjector(concurrency=5, timeout=15)
        summary = injector.run_campaign(injection_points, payload_texts)
    except Exception as e:
        campaign.status = 'failed'
        campaign.save(update_fields=['status'])
        return Response({'error': f'Injection engine error: {e}'}, status=500)

    # ── Persist results ───────────────────────────────────────────────────────
    # Build lookup: injection point dict → db model
    ip_lookup = {}
    for dip, ip_dict in db_injection_points:
        key = (ip_dict['parameter_name'], ip_dict['parameter_type'])
        ip_lookup[key] = dip

    total_tested = 0
    successful_exploits = 0
    results_out = []

    for raw_result in summary.get('results', []):
        ip_dict = raw_result.get('injection_point', {})
        key = (ip_dict.get('parameter_name', ''), ip_dict.get('parameter_type', ''))
        dip = ip_lookup.get(key)
        if dip is None:
            continue

        payload_text = raw_result.get('payload_text', '')
        # payload FK is nullable; matched_payload may be None if the payload text
        # was not found in payload_map (e.g. crafted by the injector itself).
        matched_payload = payload_map.get(payload_text)

        inj_result = InjectionResult.objects.create(
            campaign=campaign,
            injection_point=dip,
            payload=matched_payload,
            payload_text=payload_text,
            request_method=raw_result.get('request_method', repeater_req.method),
            request_url=raw_result.get('request_url', repeater_req.url),
            request_headers=raw_result.get('request_headers', {}),
            request_body=raw_result.get('request_body', ''),
            response_status=raw_result.get('response_status'),
            response_headers=raw_result.get('response_headers', {}),
            response_body=raw_result.get('response_body', ''),
            response_time_ms=raw_result.get('response_time_ms'),
            is_successful=raw_result.get('is_successful', False),
            vulnerability_type=raw_result.get('vulnerability_type', ''),
            detection_method=raw_result.get('detection_method', ''),
            confidence=raw_result.get('confidence', 0.0),
            evidence=raw_result.get('evidence', ''),
            poc_curl_command=raw_result.get('poc_curl_command', ''),
            poc_python_script=raw_result.get('poc_python_script', ''),
            poc_report=raw_result.get('poc_report', ''),
            severity=raw_result.get('severity', 'info'),
        )

        total_tested += 1
        if inj_result.is_successful:
            successful_exploits += 1

        results_out.append({
            'id': inj_result.id,
            'parameter_name': dip.parameter_name,
            'parameter_type': dip.parameter_type,
            'payload_text': payload_text,
            'is_successful': inj_result.is_successful,
            'vulnerability_type': inj_result.vulnerability_type,
            'confidence': inj_result.confidence,
            'severity': inj_result.severity,
            'response_status': inj_result.response_status,
            'evidence': inj_result.evidence,
        })

    # ── Update campaign totals ────────────────────────────────────────────────
    campaign.total_payloads_tested = total_tested
    campaign.successful_exploits = successful_exploits
    campaign.total_requests_sent = summary.get('total_requests', 0)
    campaign.status = 'completed'
    campaign.save(update_fields=[
        'total_payloads_tested', 'successful_exploits',
        'total_requests_sent', 'status',
    ])

    return Response({
        'campaign_id': campaign.id,
        'total_injection_points': len(db_injection_points),
        'total_payloads_tested': total_tested,
        'successful_exploits': successful_exploits,
        'results': results_out,
    })


# ---------------------------------------------------------------------------
# Scanner captures
# ---------------------------------------------------------------------------

@api_view(['GET'])
def scan_requests(request, scan_id):
    """Return all Repeater requests captured for a specific scan."""
    reqs = RepeaterRequest.objects.filter(scan_id=scan_id).order_by('created_at')
    return Response([_request_to_dict(r) for r in reqs])


# ---------------------------------------------------------------------------
# Scanner → Repeater integration
# ---------------------------------------------------------------------------

@api_view(['POST'])
def from_scanner(request):
    """
    Receive a vulnerability finding from the Scanner and create a RepeaterRequest.

    Accepts a POST body with the following fields:
        vuln_id        (int, optional)   – Scanner Vulnerability primary key
        url            (str, required)   – Target URL
        method         (str)             – HTTP method (default: GET)
        headers        (dict|str)        – Request headers (default: {})
        body           (str)             – Request body (default: "")
        name           (str)             – Human-readable label for the tab
        scan_id        (int, optional)   – Associated Scan primary key
        parameter      (str, optional)   – Vulnerable parameter name
        payload        (str, optional)   – Payload that triggered the finding
        vulnerability_type (str, opt)    – Vulnerability type code
        tab_id         (int, optional)   – Existing RepeaterTab to attach to

    Response (201):
        id             – RepeaterRequest primary key
        url            – Repeater dashboard URL with pre-selected request
        message        – Confirmation string
    """
    url = request.data.get('url', '')
    if not url:
        return Response({'error': 'url is required'}, status=400)

    method = (request.data.get('method') or 'GET').upper()
    body = request.data.get('body', '') or ''
    scan_id = request.data.get('scan_id')
    vuln_id = request.data.get('vuln_id')
    parameter = request.data.get('parameter', '')
    payload = request.data.get('payload', '')
    vuln_type = request.data.get('vulnerability_type', '')

    # Normalise headers to a JSON string
    raw_headers = request.data.get('headers', {})
    if isinstance(raw_headers, dict):
        headers_str = json.dumps(raw_headers)
    elif isinstance(raw_headers, str):
        headers_str = raw_headers
    else:
        headers_str = '{}'

    # Build a descriptive tab name
    name = request.data.get('name', '')
    if not name:
        label = vuln_type.upper() if vuln_type else 'Scanner'
        name = f'[{label}] {url}'[:255]

    # Resolve the associated Scan object
    scan = None
    if scan_id:
        try:
            from scanner.models import Scan as _Scan
            scan = _Scan.objects.get(id=scan_id)
        except Exception:
            pass

    # Optionally resolve the RepeaterTab
    tab = None
    tab_id = request.data.get('tab_id')
    if tab_id:
        try:
            tab = RepeaterTab.objects.get(id=tab_id)
        except RepeaterTab.DoesNotExist:
            pass

    # If parameter + payload are supplied, embed them in the body for convenience
    if not body and parameter and payload:
        body = f'{parameter}={payload}'

    repeater_req = RepeaterRequest.objects.create(
        url=url,
        method=method,
        headers=headers_str,
        body=body,
        name=name,
        source='scanner',
        scan=scan,
        tab=tab,
    )

    repeater_url = f'/repeater/?request_id={repeater_req.id}'
    if scan_id:
        repeater_url += f'&scan_id={scan_id}'

    return Response({
        'id': repeater_req.id,
        'vuln_id': vuln_id,
        'scan_id': scan_id,
        'url': repeater_url,
        'message': f'Scanner finding imported into Repeater as "{name}"',
    }, status=201)


# ---------------------------------------------------------------------------
# Interceptor → Repeater integration
# ---------------------------------------------------------------------------

@api_view(['POST'])
def from_interceptor(request):
    """
    Receive an intercepted request from the Interceptor and create a RepeaterRequest.
    Optionally includes auto-generated vulnerability test payloads.

    POST /repeater/api/from-interceptor/

    Request body:
        request_id     (int, required)  – InterceptedRequest primary key
        url            (str, required)  – Target URL
        method         (str)            – HTTP method (default: GET)
        headers        (dict|str)       – Request headers
        body           (str)            – Request body
        name           (str)            – Human-readable label for the tab
        mode           (str)            – 'manual' or 'automatic'
        locations      (list[str])      – Injection points when mode='automatic'
        vuln_ids       (list[str])      – Vulnerability sub-ids when mode='automatic'
        payloads       (list[dict])     – Pre-generated payloads from interceptor

    Response (201):
        id             – RepeaterRequest primary key
        url            – Repeater dashboard URL with pre-selected request
        message        – Confirmation string
    """
    url = request.data.get('url', '')
    if not url:
        return Response({'error': 'url is required'}, status=400)

    method = (request.data.get('method') or 'GET').upper()
    body = request.data.get('body', '') or ''
    request_id = request.data.get('request_id')
    mode = (request.data.get('mode') or 'manual').lower()
    payloads = request.data.get('payloads', [])

    # Normalize headers to a JSON string
    raw_headers = request.data.get('headers', {})
    if isinstance(raw_headers, dict):
        headers_str = json.dumps(raw_headers)
    elif isinstance(raw_headers, str):
        headers_str = raw_headers
    else:
        headers_str = '{}'

    # Build descriptive tab name
    name = request.data.get('name', '')
    if not name:
        name = f'[Interceptor] {url}'[:255]

    # Optionally resolve the RepeaterTab
    tab = None
    tab_id = request.data.get('tab_id')
    if tab_id:
        try:
            tab = RepeaterTab.objects.get(id=tab_id)
        except RepeaterTab.DoesNotExist:
            pass

    repeater_req = RepeaterRequest.objects.create(
        url=url,
        method=method,
        headers=headers_str,
        body=body,
        name=name,
        source='interceptor',
        tab=tab,
    )

    repeater_url = f'/repeater/?request_id={repeater_req.id}'
    if request_id:
        repeater_url += f'&interceptor_id={request_id}'

    payload_count = len(payloads) if isinstance(payloads, list) else 0

    return Response({
        'id': repeater_req.id,
        'interceptor_request_id': request_id,
        'url': repeater_url,
        'mode': mode,
        'payload_count': payload_count,
        'payloads': payloads,
        'message': (
            f'Intercepted request imported into Repeater as "{name}" '
            f'with {payload_count} auto-generated payload(s).'
            if mode == 'automatic'
            else f'Intercepted request imported into Repeater as "{name}" for manual editing.'
        ),
    }, status=201)
