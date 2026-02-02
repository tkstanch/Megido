from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import RepeaterRequest, RepeaterResponse
import requests
import json
import time


@api_view(['GET', 'POST'])
def repeater_requests(request):
    """List or create repeater requests"""
    if request.method == 'GET':
        reqs = RepeaterRequest.objects.all()[:50]
        data = [{
            'id': req.id,
            'name': req.name,
            'method': req.method,
            'url': req.url,
            'created_at': req.created_at.isoformat(),
        } for req in reqs]
        return Response(data)
    
    elif request.method == 'POST':
        # Create new repeater request
        req = RepeaterRequest.objects.create(
            url=request.data.get('url'),
            method=request.data.get('method', 'GET'),
            headers=request.data.get('headers', '{}'),
            body=request.data.get('body', ''),
            name=request.data.get('name', '')
        )
        return Response({'id': req.id, 'message': 'Request created'}, status=201)


@api_view(['POST'])
def send_request(request, request_id):
    """Send a repeater request and store the response"""
    try:
        repeater_req = RepeaterRequest.objects.get(id=request_id)
        
        # Parse headers
        try:
            headers = json.loads(repeater_req.headers)
        except:
            headers = {}
        
        # Send the request
        start_time = time.time()
        try:
            response = requests.request(
                method=repeater_req.method,
                url=repeater_req.url,
                headers=headers,
                data=repeater_req.body if repeater_req.body else None,
                timeout=30,
                verify=False  # For testing purposes
            )
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Store the response
            resp = RepeaterResponse.objects.create(
                request=repeater_req,
                status_code=response.status_code,
                headers=json.dumps(dict(response.headers)),
                body=response.text,
                response_time=response_time
            )
            
            return Response({
                'id': resp.id,
                'status_code': resp.status_code,
                'headers': resp.headers,
                'body': resp.body,
                'response_time': resp.response_time
            })
        except Exception as e:
            return Response({'error': str(e)}, status=500)
            
    except RepeaterRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)


def repeater_dashboard(request):
    """Dashboard view for the repeater"""
    return render(request, 'repeater/dashboard.html')
