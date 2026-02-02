from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
from django.db import models
from .models import (
    BypasserTarget, BypasserSession, CharacterProbe,
    EncodingAttempt, BypassResult
)
from .encoding import EncodingTechniques, SpecialCharacters, detect_blocking
import requests
import os
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def validate_target_url(url):
    """
    Validate target URL to prevent testing internal/private networks.
    
    Security Note: This is a security testing tool. Users are responsible
    for ensuring they have authorization to test the target URL.
    This validation helps prevent accidental testing of internal infrastructure.
    """
    try:
        parsed = urlparse(url)
        
        # Ensure scheme is http or https
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS protocols are allowed"
        
        # Block common internal/private network ranges
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL: missing hostname"
        
        # Check for localhost and common internal domains
        internal_patterns = [
            'localhost', '127.0.0.1', '0.0.0.0',
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '169.254.',
            'metadata.google.internal', 'instance-data'
        ]
        
        hostname_lower = hostname.lower()
        for pattern in internal_patterns:
            if hostname_lower.startswith(pattern) or hostname_lower == pattern.rstrip('.'):
                # Allow if explicitly enabled for testing
                if os.environ.get('MEGIDO_ALLOW_INTERNAL_TESTING', 'False') == 'True':
                    logger.warning(f"Testing internal URL {url} - MEGIDO_ALLOW_INTERNAL_TESTING is enabled")
                    return True, "Internal testing allowed"
                return False, f"Testing internal/private networks is not allowed: {hostname}"
        
        return True, "URL validation passed"
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


def bypasser_dashboard(request):
    """Dashboard view for the bypasser"""
    return render(request, 'bypasser/dashboard.html')


@api_view(['GET', 'POST'])
def bypasser_targets(request):
    """List or create bypasser targets"""
    if request.method == 'GET':
        targets = BypasserTarget.objects.all()[:50]
        data = [{
            'id': target.id,
            'name': target.name,
            'url': target.url,
            'http_method': target.http_method,
            'test_parameter': target.test_parameter,
            'created_at': target.created_at.isoformat(),
        } for target in targets]
        return Response(data)
    
    elif request.method == 'POST':
        url = request.data.get('url')
        
        # Validate URL
        is_valid, message = validate_target_url(url)
        if not is_valid:
            return Response({
                'error': f'Invalid target URL: {message}',
                'note': 'For security testing of internal networks, set MEGIDO_ALLOW_INTERNAL_TESTING=True'
            }, status=400)
        
        target = BypasserTarget.objects.create(
            url=url,
            name=request.data.get('name', ''),
            description=request.data.get('description', ''),
            http_method=request.data.get('http_method', 'GET'),
            test_parameter=request.data.get('test_parameter', 'test')
        )
        return Response({
            'id': target.id,
            'message': 'Bypasser target created'
        }, status=201)


@api_view(['POST'])
def start_character_probe(request, target_id):
    """Start character probing session on a target"""
    try:
        target = BypasserTarget.objects.get(id=target_id)
        session = BypasserSession.objects.create(
            target=target,
            status='running'
        )
        
        try:
            # Run character probing
            perform_character_probing(session, target)
            
            session.status = 'completed'
            session.completed_at = timezone.now()
            session.save()
            
            return Response({
                'id': session.id,
                'message': 'Character probing completed',
                'stats': {
                    'characters_tested': session.characters_tested,
                    'characters_blocked': session.characters_blocked,
                    'characters_allowed': session.characters_allowed,
                }
            })
        except Exception as e:
            session.status = 'failed'
            session.error_message = str(e)
            session.save()
            return Response({'error': str(e)}, status=500)
            
    except BypasserTarget.DoesNotExist:
        return Response({'error': 'Target not found'}, status=404)


def perform_character_probing(session, target):
    """
    Perform character probing on the target.
    
    Security Note: This function makes HTTP requests to user-provided URLs.
    URL validation is performed in start_character_probe() before calling this function.
    """
    # Validate URL before making requests
    is_valid, message = validate_target_url(target.url)
    if not is_valid:
        raise ValueError(f"URL validation failed: {message}")
    
    # Get SSL verification setting
    verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
    
    # Get baseline response (no special characters)
    baseline_response = None
    baseline_status = None
    
    try:
        if target.http_method == 'GET':
            params = {target.test_parameter: 'baseline'}
            baseline_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
        else:
            data = {target.test_parameter: 'baseline'}
            baseline_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
        
        baseline_response = baseline_req.text
        baseline_status = baseline_req.status_code
    except Exception as e:
        session.error_message = f"Failed to get baseline: {str(e)}"
        raise
    
    # Test each special character
    special_chars = SpecialCharacters.get_common_special_chars()
    
    for char, code, name in special_chars:
        try:
            # Test the character
            test_value = f"test{char}value"
            
            if target.http_method == 'GET':
                params = {target.test_parameter: test_value}
                test_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
            else:
                data = {target.test_parameter: test_value}
                test_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
            
            test_response = test_req.text
            test_status = test_req.status_code
            
            # Detect if blocked
            is_blocked, reason = detect_blocking(
                baseline_response, test_response,
                baseline_status, test_status
            )
            
            # Check for reflection
            reflection_found = char in test_response or test_value in test_response
            
            # Determine status
            if is_blocked:
                status = 'blocked'
                session.characters_blocked += 1
            else:
                status = 'allowed'
                session.characters_allowed += 1
            
            # Create character probe record
            CharacterProbe.objects.create(
                session=session,
                character=char,
                character_code=code,
                character_name=name,
                status=status,
                http_status_code=test_status,
                response_time=test_req.elapsed.total_seconds(),
                response_length=len(test_response),
                blocked_by_waf=is_blocked,
                error_message=reason if is_blocked else None,
                reflection_found=reflection_found
            )
            
            session.characters_tested += 1
            session.save()
            
            # Small delay to avoid rate limiting
            time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"Error testing character {char}: {e}")
            # Create error record
            CharacterProbe.objects.create(
                session=session,
                character=char,
                character_code=code,
                character_name=name,
                status='error',
                error_message=str(e)
            )
            session.characters_tested += 1
            session.save()


@api_view(['GET'])
def session_results(request, session_id):
    """Get results of a character probing session"""
    try:
        session = BypasserSession.objects.get(id=session_id)
        character_probes = session.character_probes.all()
        
        data = {
            'session_id': session.id,
            'target': {
                'id': session.target.id,
                'name': session.target.name,
                'url': session.target.url,
            },
            'status': session.status,
            'started_at': session.started_at.isoformat(),
            'completed_at': session.completed_at.isoformat() if session.completed_at else None,
            'statistics': {
                'characters_tested': session.characters_tested,
                'characters_blocked': session.characters_blocked,
                'characters_allowed': session.characters_allowed,
                'encoding_attempts': session.encoding_attempts,
                'successful_bypasses': session.successful_bypasses,
            },
            'character_probes': [{
                'id': probe.id,
                'character': probe.character,
                'character_code': probe.character_code,
                'character_name': probe.character_name,
                'status': probe.status,
                'blocked_by_waf': probe.blocked_by_waf,
                'reflection_found': probe.reflection_found,
                'error_message': probe.error_message,
            } for probe in character_probes],
            'blocked_characters': [
                {
                    'character': probe.character,
                    'name': probe.character_name,
                    'reason': probe.error_message
                }
                for probe in character_probes if probe.status == 'blocked'
            ],
            'allowed_characters': [
                {
                    'character': probe.character,
                    'name': probe.character_name
                }
                for probe in character_probes if probe.status == 'allowed'
            ]
        }
        return Response(data)
    except BypasserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['POST'])
def test_encoding_bypass(request, session_id):
    """
    Test encoding bypass techniques on blocked characters.
    
    Security Note: This function makes HTTP requests to user-provided URLs.
    URL validation was performed when the session was created.
    """
    try:
        session = BypasserSession.objects.get(id=session_id)
        target = session.target
        
        # Get blocked characters from session
        blocked_probes = session.character_probes.filter(status='blocked')
        
        if not blocked_probes.exists():
            return Response({
                'message': 'No blocked characters to test bypasses for'
            })
        
        # Get SSL verification setting
        verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
        
        # Get baseline response
        try:
            if target.http_method == 'GET':
                params = {target.test_parameter: 'baseline'}
                baseline_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
            else:
                data = {target.test_parameter: 'baseline'}
                baseline_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
            
            baseline_response = baseline_req.text
            baseline_status = baseline_req.status_code
        except Exception as e:
            return Response({'error': f'Failed to get baseline: {str(e)}'}, status=500)
        
        # Test encoding bypasses for each blocked character
        results = []
        
        for probe in blocked_probes[:5]:  # Limit to first 5 to avoid long processing
            char = probe.character
            
            # Get all encoding variations
            encodings = EncodingTechniques.get_all_encodings(char)
            
            for encoding_type, encoded_value in encodings.items():
                try:
                    # Test the encoded payload
                    test_value = f"test{encoded_value}value"
                    
                    if target.http_method == 'GET':
                        params = {target.test_parameter: test_value}
                        test_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
                    else:
                        data = {target.test_parameter: test_value}
                        test_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
                    
                    test_response = test_req.text
                    test_status = test_req.status_code
                    
                    # Check if bypass was successful
                    is_blocked, reason = detect_blocking(
                        baseline_response, test_response,
                        baseline_status, test_status
                    )
                    
                    success = not is_blocked
                    reflection_found = char in test_response or encoded_value in test_response
                    
                    # Create encoding attempt record
                    attempt = EncodingAttempt.objects.create(
                        session=session,
                        character_probe=probe,
                        encoding_type=encoding_type,
                        original_payload=char,
                        encoded_payload=encoded_value,
                        success=success,
                        http_status_code=test_status,
                        response_time=test_req.elapsed.total_seconds(),
                        response_length=len(test_response),
                        bypass_confirmed=success and reflection_found,
                        reflection_found=reflection_found,
                        waf_triggered=is_blocked
                    )
                    
                    session.encoding_attempts += 1
                    
                    if success:
                        session.successful_bypasses += 1
                        
                        # Create bypass result if confirmed
                        if reflection_found:
                            BypassResult.objects.create(
                                session=session,
                                character_probe=probe,
                                encoding_attempt=attempt,
                                technique_description=f"Successfully bypassed filter using {encoding_type}",
                                payload_example=test_value,
                                risk_level='high',
                                impact_description=f"The character '{char}' can be bypassed using {encoding_type} encoding",
                                evidence=f"Status: {test_status}, Reflection: {reflection_found}",
                                recommendation="Implement comprehensive input validation and output encoding"
                            )
                        
                        results.append({
                            'character': char,
                            'encoding_type': encoding_type,
                            'encoded_value': encoded_value,
                            'success': True,
                            'reflection_found': reflection_found
                        })
                    
                    session.save()
                    
                    # Small delay
                    time.sleep(0.1)
                    
                except Exception as e:
                    logger.error(f"Error testing encoding {encoding_type} for {char}: {e}")
        
        return Response({
            'message': 'Encoding bypass testing completed',
            'bypasses_found': session.successful_bypasses,
            'encoding_attempts': session.encoding_attempts,
            'successful_bypasses': results
        })
        
    except BypasserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['GET'])
def bypass_results(request, session_id):
    """Get successful bypass results for a session"""
    try:
        session = BypasserSession.objects.get(id=session_id)
        results = session.bypass_results.all()
        
        data = [{
            'id': result.id,
            'character': result.character_probe.character,
            'character_name': result.character_probe.character_name,
            'encoding_type': result.encoding_attempt.encoding_type,
            'encoded_payload': result.encoding_attempt.encoded_payload,
            'technique_description': result.technique_description,
            'payload_example': result.payload_example,
            'risk_level': result.risk_level,
            'impact_description': result.impact_description,
            'evidence': result.evidence,
            'recommendation': result.recommendation,
            'discovered_at': result.discovered_at.isoformat(),
        } for result in results]
        
        return Response(data)
        
    except BypasserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


# ==================== Custom Bypass Techniques API ====================

from .models import CustomBypassTechnique, CustomTechniqueExecution
from .technique_parser import TechniqueParser, test_technique


@api_view(['GET', 'POST'])
def custom_techniques(request):
    """List all custom techniques or create a new one"""
    if request.method == 'GET':
        # Filter parameters
        category = request.GET.get('category', None)
        is_active = request.GET.get('is_active', None)
        
        techniques = CustomBypassTechnique.objects.all()
        
        if category:
            techniques = techniques.filter(category=category)
        if is_active is not None:
            techniques = techniques.filter(is_active=is_active.lower() == 'true')
        
        techniques = techniques[:100]  # Limit results
        
        data = [{
            'id': tech.id,
            'name': tech.name,
            'description': tech.description,
            'category': tech.category,
            'technique_template': tech.technique_template,
            'example_input': tech.example_input,
            'example_output': tech.example_output,
            'tags': tech.tags,
            'author': tech.author,
            'times_used': tech.times_used,
            'times_successful': tech.times_successful,
            'success_rate': tech.success_rate,
            'is_active': tech.is_active,
            'is_public': tech.is_public,
            'created_at': tech.created_at.isoformat(),
        } for tech in techniques]
        
        return Response(data)
    
    elif request.method == 'POST':
        # Create new custom technique
        name = request.data.get('name')
        technique_template = request.data.get('technique_template')
        
        if not name or not technique_template:
            return Response({
                'error': 'Name and technique_template are required'
            }, status=400)
        
        # Validate the template
        is_valid, validation_msg = TechniqueParser.validate_template(technique_template)
        if not is_valid:
            return Response({
                'error': f'Invalid technique template: {validation_msg}'
            }, status=400)
        
        # Create the technique
        technique = CustomBypassTechnique.objects.create(
            name=name,
            description=request.data.get('description', ''),
            category=request.data.get('category', 'mixed'),
            technique_template=technique_template,
            example_input=request.data.get('example_input', ''),
            example_output=request.data.get('example_output', ''),
            tags=request.data.get('tags', ''),
            author=request.data.get('author', ''),
            is_active=request.data.get('is_active', True),
            is_public=request.data.get('is_public', False)
        )
        
        return Response({
            'id': technique.id,
            'message': 'Custom technique created successfully',
            'name': technique.name
        }, status=201)


@api_view(['GET', 'PUT', 'DELETE'])
def custom_technique_detail(request, technique_id):
    """Get, update, or delete a specific custom technique"""
    try:
        technique = CustomBypassTechnique.objects.get(id=technique_id)
    except CustomBypassTechnique.DoesNotExist:
        return Response({'error': 'Technique not found'}, status=404)
    
    if request.method == 'GET':
        data = {
            'id': technique.id,
            'name': technique.name,
            'description': technique.description,
            'category': technique.category,
            'technique_template': technique.technique_template,
            'example_input': technique.example_input,
            'example_output': technique.example_output,
            'tags': technique.tags,
            'author': technique.author,
            'times_used': technique.times_used,
            'times_successful': technique.times_successful,
            'success_rate': technique.success_rate,
            'is_active': technique.is_active,
            'is_public': technique.is_public,
            'created_at': technique.created_at.isoformat(),
            'updated_at': technique.updated_at.isoformat(),
        }
        return Response(data)
    
    elif request.method == 'PUT':
        # Update technique
        if 'technique_template' in request.data:
            # Validate if template is being updated
            is_valid, validation_msg = TechniqueParser.validate_template(
                request.data['technique_template']
            )
            if not is_valid:
                return Response({
                    'error': f'Invalid technique template: {validation_msg}'
                }, status=400)
            technique.technique_template = request.data['technique_template']
        
        # Update other fields
        for field in ['name', 'description', 'category', 'example_input', 
                      'example_output', 'tags', 'author', 'is_active', 'is_public']:
            if field in request.data:
                setattr(technique, field, request.data[field])
        
        technique.save()
        
        return Response({
            'id': technique.id,
            'message': 'Technique updated successfully'
        })
    
    elif request.method == 'DELETE':
        technique.delete()
        return Response({
            'message': 'Technique deleted successfully'
        }, status=204)


@api_view(['POST'])
def test_custom_technique(request, technique_id):
    """Test a custom technique with sample payload"""
    try:
        technique = CustomBypassTechnique.objects.get(id=technique_id)
    except CustomBypassTechnique.DoesNotExist:
        return Response({'error': 'Technique not found'}, status=404)
    
    test_payload = request.data.get('payload', '<script>alert(1)</script>')
    
    # Test the technique
    result = test_technique(technique.technique_template, test_payload)
    
    return Response({
        'technique_name': technique.name,
        'technique_template': technique.technique_template,
        'test_payload': test_payload,
        'success': result['success'],
        'result': result['result'],
        'error': result['error']
    })


@api_view(['POST'])
def use_custom_techniques(request, session_id):
    """Use custom techniques to test bypass on a session"""
    try:
        session = BypasserSession.objects.get(id=session_id)
        target = session.target
    except BypasserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)
    
    # Get technique IDs to use (or all active if not specified)
    technique_ids = request.data.get('technique_ids', [])
    
    if technique_ids:
        techniques = CustomBypassTechnique.objects.filter(
            id__in=technique_ids,
            is_active=True
        )
    else:
        techniques = CustomBypassTechnique.objects.filter(is_active=True)[:20]
    
    if not techniques.exists():
        return Response({
            'message': 'No active custom techniques found'
        })
    
    # Get blocked characters from session to test
    blocked_probes = session.character_probes.filter(status='blocked')[:5]
    
    if not blocked_probes.exists():
        return Response({
            'message': 'No blocked characters to test bypasses for'
        })
    
    # Get SSL verification setting
    verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
    
    # Get baseline response
    try:
        if target.http_method == 'GET':
            params = {target.test_parameter: 'baseline'}
            baseline_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
        else:
            data = {target.test_parameter: 'baseline'}
            baseline_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
        
        baseline_response = baseline_req.text
        baseline_status = baseline_req.status_code
    except Exception as e:
        return Response({'error': f'Failed to get baseline: {str(e)}'}, status=500)
    
    # Test each technique with blocked characters
    results = []
    successful_count = 0
    
    for technique in techniques:
        for probe in blocked_probes:
            char = probe.character
            
            # Parse and execute the technique
            success, transformed_payload, error = TechniqueParser.parse_and_execute(
                technique.technique_template,
                {'payload': char, 'char': char}
            )
            
            if not success:
                logger.error(f"Failed to execute technique {technique.name}: {error}")
                continue
            
            try:
                # Test the transformed payload
                test_value = f"test{transformed_payload}value"
                
                if target.http_method == 'GET':
                    params = {target.test_parameter: test_value}
                    test_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
                else:
                    data = {target.test_parameter: test_value}
                    test_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
                
                test_response = test_req.text
                test_status = test_req.status_code
                
                # Check if bypass was successful
                is_blocked, reason = detect_blocking(
                    baseline_response, test_response,
                    baseline_status, test_status
                )
                
                bypass_success = not is_blocked
                reflection_found = char in test_response or transformed_payload in test_response
                
                # Create execution record
                execution = CustomTechniqueExecution.objects.create(
                    session=session,
                    technique=technique,
                    input_payload=char,
                    output_payload=transformed_payload,
                    success=bypass_success,
                    http_status_code=test_status,
                    response_time=test_req.elapsed.total_seconds(),
                    response_length=len(test_response),
                    bypass_confirmed=bypass_success and reflection_found,
                    reflection_found=reflection_found,
                    waf_triggered=is_blocked
                )
                
                # Update technique statistics
                technique.times_used += 1
                if bypass_success:
                    technique.times_successful += 1
                    successful_count += 1
                technique.update_success_rate()
                
                if bypass_success:
                    results.append({
                        'technique_id': technique.id,
                        'technique_name': technique.name,
                        'character': char,
                        'transformed_payload': transformed_payload,
                        'success': True,
                        'reflection_found': reflection_found
                    })
                
                # Small delay
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error testing custom technique {technique.name} for {char}: {e}")
                CustomTechniqueExecution.objects.create(
                    session=session,
                    technique=technique,
                    input_payload=char,
                    output_payload=transformed_payload,
                    success=False,
                    error_message=str(e)
                )
    
    return Response({
        'message': 'Custom technique testing completed',
        'techniques_tested': techniques.count(),
        'successful_bypasses': successful_count,
        'results': results
    })


@api_view(['GET'])
def get_available_transformations(request):
    """Get list of available transformation functions for technique templates"""
    transformations = TechniqueParser.get_available_transformations()
    variables = TechniqueParser.get_available_variables()
    
    return Response({
        'transformations': transformations,
        'variables': variables,
        'template_syntax': {
            'basic': '{{variable}}',
            'with_transformation': '{{variable|transformation}}',
            'chained': '{{variable|transform1|transform2|transform3}}',
            'example': '{{payload|url_encode_double|html_hex}}'
        },
        'examples': [
            {
                'name': 'Double URL Encoding',
                'template': '{{payload|url_encode_double}}',
                'input': '<script>',
                'output': '%253Cscript%253E'
            },
            {
                'name': 'HTML Entity + URL Encode',
                'template': '{{payload|html_decimal|url_encode}}',
                'input': '<',
                'output': '%26%2360%3B'
            },
            {
                'name': 'Mixed Case with Comments',
                'template': '{{payload|upper|html_comment}}',
                'input': 'script',
                'output': 'S<!---->C<!---->R<!---->I<!---->P<!---->T'
            }
        ]
    })


# ==================== Ready-Made Payloads API ====================

from .models import ReadyMadePayload, PayloadExecution
from .payload_library import ReadyMadePayloads, PayloadCategory, BypassTarget
from .technique_parser import PayloadManipulator


@api_view(['GET'])
def list_payloads(request):
    """List all ready-made payloads with optional filtering"""
    # Filter parameters
    category = request.GET.get('category', None)
    bypass_target = request.GET.get('bypass_target', None)
    risk_level = request.GET.get('risk_level', None)
    search = request.GET.get('search', None)
    is_active = request.GET.get('is_active', None)
    
    # Get payloads from database if populated, otherwise from library
    db_payloads = ReadyMadePayload.objects.all()
    
    if db_payloads.exists():
        # Use database payloads
        if category:
            db_payloads = db_payloads.filter(category=category)
        if bypass_target:
            db_payloads = db_payloads.filter(bypass_target=bypass_target)
        if risk_level:
            db_payloads = db_payloads.filter(risk_level=risk_level)
        if is_active is not None:
            db_payloads = db_payloads.filter(is_active=is_active.lower() == 'true')
        if search:
            db_payloads = db_payloads.filter(
                models.Q(name__icontains=search) |
                models.Q(description__icontains=search) |
                models.Q(payload__icontains=search)
            )
        
        db_payloads = db_payloads[:100]  # Limit results
        
        data = [{
            'id': payload.id,
            'name': payload.name,
            'payload': payload.payload,
            'description': payload.description,
            'category': payload.category,
            'bypass_target': payload.bypass_target,
            'risk_level': payload.risk_level,
            'times_used': payload.times_used,
            'times_successful': payload.times_successful,
            'success_rate': payload.success_rate,
            'is_active': payload.is_active,
            'tags': payload.tags,
        } for payload in db_payloads]
    else:
        # Use library payloads
        all_payloads = ReadyMadePayloads.get_all_payloads()
        
        # Apply filters
        if category:
            all_payloads = {k: v for k, v in all_payloads.items() if v['category'] == category}
        if bypass_target:
            all_payloads = {k: v for k, v in all_payloads.items() if v['bypass_target'] == bypass_target}
        if risk_level:
            all_payloads = {k: v for k, v in all_payloads.items() if v['risk_level'] == risk_level}
        if search:
            all_payloads = ReadyMadePayloads.search_payloads(search)
        
        data = [{
            'name': name,
            'payload': info['payload'],
            'description': info['description'],
            'category': info['category'],
            'bypass_target': info['bypass_target'],
            'risk_level': info['risk_level'],
        } for name, info in list(all_payloads.items())[:100]]
    
    return Response(data)


@api_view(['GET'])
def get_payload(request, payload_id):
    """Get details of a specific payload"""
    try:
        payload = ReadyMadePayload.objects.get(id=payload_id)
        data = {
            'id': payload.id,
            'name': payload.name,
            'payload': payload.payload,
            'description': payload.description,
            'category': payload.category,
            'bypass_target': payload.bypass_target,
            'risk_level': payload.risk_level,
            'times_used': payload.times_used,
            'times_successful': payload.times_successful,
            'success_rate': payload.success_rate,
            'is_active': payload.is_active,
            'is_built_in': payload.is_built_in,
            'tags': payload.tags,
            'created_at': payload.created_at.isoformat(),
        }
        return Response(data)
    except ReadyMadePayload.DoesNotExist:
        return Response({'error': 'Payload not found'}, status=404)


@api_view(['POST'])
def transform_payload(request, payload_id):
    """Apply transformations to a payload"""
    try:
        payload_obj = ReadyMadePayload.objects.get(id=payload_id)
    except ReadyMadePayload.DoesNotExist:
        return Response({'error': 'Payload not found'}, status=404)
    
    # Get transformations from request
    transformations = request.data.get('transformations', [])
    technique_template = request.data.get('technique_template', None)
    
    if not transformations and not technique_template:
        return Response({
            'error': 'Either transformations list or technique_template is required'
        }, status=400)
    
    original_payload = payload_obj.payload
    
    # Apply transformations
    if transformations:
        success, result, error = PayloadManipulator.apply_transformations(
            original_payload,
            transformations
        )
    else:
        success, result, error = PayloadManipulator.apply_technique_to_payload(
            original_payload,
            technique_template
        )
    
    if not success:
        return Response({
            'error': f'Transformation failed: {error}'
        }, status=400)
    
    return Response({
        'payload_name': payload_obj.name,
        'original': original_payload,
        'transformed': result,
        'transformations_applied': ','.join(transformations) if transformations else technique_template,
        'success': True
    })


@api_view(['POST'])
def inject_payload(request, session_id):
    """Inject ready-made payloads into a bypass testing session"""
    try:
        session = BypasserSession.objects.get(id=session_id)
        target = session.target
    except BypasserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)
    
    # Get payload IDs or names to inject
    payload_ids = request.data.get('payload_ids', [])
    payload_names = request.data.get('payload_names', [])
    transformations = request.data.get('transformations', [])
    technique_template = request.data.get('technique_template', None)
    
    if not payload_ids and not payload_names:
        return Response({
            'error': 'Either payload_ids or payload_names is required'
        }, status=400)
    
    # Get SSL verification setting
    verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
    
    # Get payloads
    payloads = []
    if payload_ids:
        payloads.extend(ReadyMadePayload.objects.filter(id__in=payload_ids, is_active=True))
    if payload_names:
        payloads.extend(ReadyMadePayload.objects.filter(name__in=payload_names, is_active=True))
    
    if not payloads:
        return Response({'error': 'No active payloads found'}, status=404)
    
    # Get baseline response
    try:
        if target.http_method == 'GET':
            params = {target.test_parameter: 'baseline'}
            baseline_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
        else:
            data = {target.test_parameter: 'baseline'}
            baseline_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
        
        baseline_response = baseline_req.text
        baseline_status = baseline_req.status_code
    except Exception as e:
        return Response({'error': f'Failed to get baseline: {str(e)}'}, status=500)
    
    # Test each payload
    results = []
    successful_count = 0
    
    for payload_obj in payloads:
        original_payload = payload_obj.payload
        
        # Apply transformations if specified
        if transformations or technique_template:
            if transformations:
                success, test_payload, error = PayloadManipulator.apply_transformations(
                    original_payload, transformations
                )
            else:
                success, test_payload, error = PayloadManipulator.apply_technique_to_payload(
                    original_payload, technique_template
                )
            
            if not success:
                logger.error(f"Failed to transform payload {payload_obj.name}: {error}")
                continue
            
            transform_str = ','.join(transformations) if transformations else technique_template
        else:
            test_payload = original_payload
            transform_str = ''
        
        try:
            # Test the payload
            if target.http_method == 'GET':
                params = {target.test_parameter: test_payload}
                test_req = requests.get(target.url, params=params, timeout=10, verify=verify_ssl)
            else:
                data = {target.test_parameter: test_payload}
                test_req = requests.post(target.url, data=data, timeout=10, verify=verify_ssl)
            
            test_response = test_req.text
            test_status = test_req.status_code
            
            # Check if payload worked
            is_blocked, reason = detect_blocking(
                baseline_response, test_response,
                baseline_status, test_status
            )
            
            payload_success = not is_blocked
            reflection_found = original_payload in test_response or test_payload in test_response
            
            # Create execution record
            execution = PayloadExecution.objects.create(
                session=session,
                payload=payload_obj,
                original_payload=original_payload,
                transformed_payload=test_payload,
                transformations_applied=transform_str,
                success=payload_success,
                http_status_code=test_status,
                response_time=test_req.elapsed.total_seconds(),
                response_length=len(test_response),
                bypass_confirmed=payload_success and reflection_found,
                reflection_found=reflection_found,
                waf_triggered=is_blocked
            )
            
            # Update payload statistics
            payload_obj.times_used += 1
            if payload_success:
                payload_obj.times_successful += 1
                successful_count += 1
            payload_obj.update_success_rate()
            
            if payload_success:
                results.append({
                    'payload_id': payload_obj.id,
                    'payload_name': payload_obj.name,
                    'original': original_payload,
                    'transformed': test_payload,
                    'success': True,
                    'reflection_found': reflection_found
                })
            
            # Small delay
            time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"Error testing payload {payload_obj.name}: {e}")
            PayloadExecution.objects.create(
                session=session,
                payload=payload_obj,
                original_payload=original_payload,
                transformed_payload=test_payload,
                transformations_applied=transform_str,
                success=False,
                error_message=str(e)
            )
    
    return Response({
        'message': 'Payload injection completed',
        'payloads_tested': len(payloads),
        'successful_bypasses': successful_count,
        'results': results
    })


@api_view(['POST'])
def combine_payloads_api(request):
    """Combine multiple payloads with optional transformations"""
    payload_ids = request.data.get('payload_ids', [])
    payload_names = request.data.get('payload_names', [])
    separator = request.data.get('separator', ' ')
    transformations = request.data.get('transformations', [])
    
    if not payload_ids and not payload_names:
        return Response({
            'error': 'Either payload_ids or payload_names is required'
        }, status=400)
    
    # Get payloads
    payloads = []
    if payload_ids:
        payloads.extend(ReadyMadePayload.objects.filter(id__in=payload_ids))
    if payload_names:
        payloads.extend(ReadyMadePayload.objects.filter(name__in=payload_names))
    
    if not payloads:
        return Response({'error': 'No payloads found'}, status=404)
    
    # Extract payload strings
    payload_strings = [p.payload for p in payloads]
    
    # Combine payloads
    success, combined, error = PayloadManipulator.combine_payloads(
        payload_strings,
        separator=separator,
        transformations=transformations if transformations else None
    )
    
    if not success:
        return Response({
            'error': f'Failed to combine payloads: {error}'
        }, status=400)
    
    return Response({
        'payloads_combined': [p.name for p in payloads],
        'separator': separator,
        'transformations': transformations,
        'combined_payload': combined,
        'success': True
    })


@api_view(['GET'])
def fuzz_payload_api(request, payload_id):
    """Generate fuzzed variants of a payload"""
    try:
        payload_obj = ReadyMadePayload.objects.get(id=payload_id)
    except ReadyMadePayload.DoesNotExist:
        return Response({'error': 'Payload not found'}, status=404)
    
    fuzz_type = request.GET.get('type', 'all')
    
    variants = PayloadManipulator.fuzz_payload(payload_obj.payload, fuzz_type)
    
    return Response({
        'payload_name': payload_obj.name,
        'original': payload_obj.payload,
        'fuzz_type': fuzz_type,
        'variants': variants,
        'count': len(variants)
    })


@api_view(['GET'])
def get_payload_categories(request):
    """Get list of available payload categories and bypass targets"""
    return Response({
        'categories': [
            {'value': 'xss', 'label': 'XSS'},
            {'value': 'sqli', 'label': 'SQL Injection'},
            {'value': 'command_injection', 'label': 'Command Injection'},
            {'value': 'path_traversal', 'label': 'Path Traversal'},
            {'value': 'xxe', 'label': 'XXE'},
            {'value': 'ssti', 'label': 'SSTI'},
            {'value': 'ssrf', 'label': 'SSRF'},
            {'value': 'ldap', 'label': 'LDAP Injection'},
            {'value': 'nosql', 'label': 'NoSQL Injection'},
            {'value': 'general', 'label': 'General'},
        ],
        'bypass_targets': [
            {'value': 'waf', 'label': 'WAF'},
            {'value': 'ips', 'label': 'IPS'},
            {'value': 'ids', 'label': 'IDS'},
            {'value': 'firewall', 'label': 'Firewall'},
            {'value': 'filter', 'label': 'Input Filter'},
            {'value': 'all', 'label': 'All'},
        ],
        'risk_levels': [
            {'value': 'info', 'label': 'Informational'},
            {'value': 'low', 'label': 'Low'},
            {'value': 'medium', 'label': 'Medium'},
            {'value': 'high', 'label': 'High'},
            {'value': 'critical', 'label': 'Critical'},
        ]
    })


@api_view(['POST'])
def initialize_payload_library(request):
    """Initialize the database with payloads from the library"""
    if ReadyMadePayload.objects.exists():
        return Response({
            'message': 'Payload library already initialized',
            'count': ReadyMadePayload.objects.count()
        })
    
    all_payloads = ReadyMadePayloads.get_all_payloads()
    created_count = 0
    
    for name, info in all_payloads.items():
        ReadyMadePayload.objects.create(
            name=name,
            payload=info['payload'],
            description=info['description'],
            category=info['category'],
            bypass_target=info['bypass_target'],
            risk_level=info['risk_level'],
            is_built_in=True,
            is_active=True
        )
        created_count += 1
    
    return Response({
        'message': 'Payload library initialized successfully',
        'payloads_created': created_count
    })
