from django.shortcuts import render, get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import CollaboratorServer, Interaction
from django.utils import timezone
import json


def collaborator_dashboard(request):
    """Dashboard view for the collaborator"""
    return render(request, 'collaborator/dashboard.html')


@api_view(['GET', 'POST'])
def collaborator_servers(request):
    """List or create collaborator servers"""
    if request.method == 'GET':
        servers = CollaboratorServer.objects.all()[:50]
        data = [{
            'id': server.id,
            'domain': server.domain,
            'ip_address': server.ip_address,
            'description': server.description,
            'is_active': server.is_active,
            'created_at': server.created_at.isoformat(),
            'interaction_count': server.interactions.count()
        } for server in servers]
        return Response(data)
    
    elif request.method == 'POST':
        server = CollaboratorServer.objects.create(
            domain=request.data.get('domain'),
            ip_address=request.data.get('ip_address', None),
            description=request.data.get('description', ''),
            is_active=request.data.get('is_active', True)
        )
        return Response({
            'id': server.id, 
            'message': 'Collaborator server created'
        }, status=201)


@api_view(['GET', 'PUT', 'DELETE'])
def collaborator_server_detail(request, server_id):
    """Get, update or delete a specific collaborator server"""
    server = get_object_or_404(CollaboratorServer, id=server_id)
    
    if request.method == 'GET':
        data = {
            'id': server.id,
            'domain': server.domain,
            'ip_address': server.ip_address,
            'description': server.description,
            'is_active': server.is_active,
            'created_at': server.created_at.isoformat(),
            'interaction_count': server.interactions.count()
        }
        return Response(data)
    
    elif request.method == 'PUT':
        server.domain = request.data.get('domain', server.domain)
        server.ip_address = request.data.get('ip_address', server.ip_address)
        server.description = request.data.get('description', server.description)
        server.is_active = request.data.get('is_active', server.is_active)
        server.save()
        return Response({'message': 'Server updated'})
    
    elif request.method == 'DELETE':
        server.delete()
        return Response({'message': 'Server deleted'}, status=204)


@api_view(['GET'])
def interactions(request, server_id):
    """List all interactions for a specific collaborator server"""
    server = get_object_or_404(CollaboratorServer, id=server_id)
    interactions = server.interactions.all()[:100]
    
    data = [{
        'id': interaction.id,
        'interaction_type': interaction.get_interaction_type_display(),
        'interaction_type_code': interaction.interaction_type,
        'source_ip': interaction.source_ip,
        'timestamp': interaction.timestamp.isoformat(),
        'http_method': interaction.http_method,
        'http_path': interaction.http_path,
        'http_headers': interaction.http_headers,
        'http_body': interaction.http_body,
        'dns_query_type': interaction.dns_query_type,
        'dns_query_name': interaction.dns_query_name,
        'raw_data': interaction.raw_data[:500] if interaction.raw_data else ''
    } for interaction in interactions]
    
    return Response(data)


@api_view(['POST'])
def log_interaction(request, server_id):
    """Log a new interaction for a collaborator server"""
    server = get_object_or_404(CollaboratorServer, id=server_id)
    
    if not server.is_active:
        return Response({'error': 'Server is not active'}, status=400)
    
    interaction = Interaction.objects.create(
        server=server,
        interaction_type=request.data.get('interaction_type', 'other'),
        source_ip=request.data.get('source_ip'),
        raw_data=request.data.get('raw_data', ''),
        http_method=request.data.get('http_method'),
        http_path=request.data.get('http_path'),
        http_headers=request.data.get('http_headers'),
        http_body=request.data.get('http_body'),
        dns_query_type=request.data.get('dns_query_type'),
        dns_query_name=request.data.get('dns_query_name')
    )
    
    return Response({
        'id': interaction.id,
        'message': 'Interaction logged'
    }, status=201)


@api_view(['DELETE'])
def clear_interactions(request, server_id):
    """Clear all interactions for a specific server"""
    server = get_object_or_404(CollaboratorServer, id=server_id)
    count = server.interactions.count()
    server.interactions.all().delete()
    return Response({
        'message': f'Cleared {count} interactions'
    })


@api_view(['GET'])
def poll_interactions(request, server_id):
    """Poll for new interactions (for real-time updates)"""
    server = get_object_or_404(CollaboratorServer, id=server_id)
    
    # Get timestamp from query params for polling
    since = request.query_params.get('since')
    
    if since:
        try:
            since_time = timezone.datetime.fromisoformat(since.replace('Z', '+00:00'))
            interactions = server.interactions.filter(timestamp__gt=since_time)[:50]
        except (ValueError, AttributeError):
            interactions = server.interactions.all()[:50]
    else:
        interactions = server.interactions.all()[:50]
    
    data = [{
        'id': interaction.id,
        'interaction_type': interaction.get_interaction_type_display(),
        'interaction_type_code': interaction.interaction_type,
        'source_ip': interaction.source_ip,
        'timestamp': interaction.timestamp.isoformat(),
        'http_method': interaction.http_method,
        'http_path': interaction.http_path,
        'dns_query_type': interaction.dns_query_type,
        'dns_query_name': interaction.dns_query_name,
    } for interaction in interactions]
    
    return Response(data)
