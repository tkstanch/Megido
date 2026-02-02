from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
from .models import (
    BypasserTarget, BypasserSession, CharacterProbe,
    EncodingAttempt, BypassResult
)
from .encoding import EncodingTechniques, SpecialCharacters, detect_blocking
import requests
import os
import time


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
        target = BypasserTarget.objects.create(
            url=request.data.get('url'),
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
    """Perform character probing on the target"""
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
            print(f"Error testing character {char}: {e}")
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
    """Test encoding bypass techniques on blocked characters"""
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
                    print(f"Error testing encoding {encoding_type} for {char}: {e}")
        
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
