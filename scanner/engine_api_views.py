"""
Engine API Views

REST API endpoints for the multi-engine vulnerability scanner.
"""

import logging
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404

from scanner.models import EngineScan, EngineExecution, EngineFinding
from scanner.engine_plugins.engine_service import EngineService
from scanner.engine_api_serializers import (
    EngineScanSerializer,
    EngineExecutionSerializer,
    EngineFindingSerializer,
    CreateScanSerializer,
    ScanSummarySerializer
)

logger = logging.getLogger(__name__)


class EngineViewSet(viewsets.ViewSet):
    """
    ViewSet for engine management operations.
    """
    permission_classes = []  # Open for demo purposes
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service = EngineService()
    
    def list(self, request):
        """
        List all available engines.
        
        GET /api/engines/
        """
        try:
            engines = self.service.list_available_engines()
            return Response({
                'count': len(engines),
                'engines': engines
            })
        except Exception as e:
            logger.error(f"Failed to list engines: {e}", exc_info=True)
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def categories(self, request):
        """
        Get engine categories.
        
        GET /api/engines/categories/
        """
        categories = [
            {'id': 'sast', 'name': 'SAST', 'description': 'Static Application Security Testing'},
            {'id': 'dast', 'name': 'DAST', 'description': 'Dynamic Application Security Testing'},
            {'id': 'sca', 'name': 'SCA', 'description': 'Software Composition Analysis'},
            {'id': 'secrets', 'name': 'Secrets', 'description': 'Secrets Detection'},
            {'id': 'container', 'name': 'Container', 'description': 'Container Security'},
            {'id': 'cloud', 'name': 'Cloud', 'description': 'Cloud Security'},
            {'id': 'custom', 'name': 'Custom', 'description': 'Custom Analyzers'},
        ]
        
        return Response({'categories': categories})


class EngineScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for engine scan operations.
    """
    queryset = EngineScan.objects.all()
    serializer_class = EngineScanSerializer
    permission_classes = []  # Open for demo purposes
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service = EngineService()
    
    def create(self, request):
        """
        Create and optionally execute a new engine scan.
        
        POST /api/engine-scans/
        
        Body:
        {
            "target_path": "/path/to/scan",
            "target_type": "path",
            "engine_ids": ["bandit", "gitleaks"],
            "categories": ["sast", "secrets"],
            "parallel": true,
            "max_workers": 4,
            "execute_immediately": false
        }
        """
        serializer = CreateScanSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        data = serializer.validated_data
        
        try:
            # Create scan
            scan = self.service.create_scan(
                target_path=data['target_path'],
                target_type=data.get('target_type', 'path'),
                engine_ids=data.get('engine_ids'),
                categories=data.get('categories'),
                parallel=data.get('parallel', True),
                max_workers=data.get('max_workers', 4),
                created_by=request.user.username if request.user.is_authenticated else None
            )
            
            # Execute immediately if requested
            if data.get('execute_immediately', False):
                result = self.service.execute_scan(
                    scan,
                    engine_ids=data.get('engine_ids'),
                    categories=data.get('categories')
                )
                
                return Response({
                    'scan_id': scan.id,
                    'status': 'completed',
                    'message': 'Scan created and executed successfully',
                    'result': result
                }, status=status.HTTP_201_CREATED)
            
            return Response({
                'scan_id': scan.id,
                'status': 'pending',
                'message': 'Scan created successfully. Use /execute/ to run it.'
            }, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error(f"Failed to create scan: {e}", exc_info=True)
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """
        Execute a pending scan.
        
        POST /api/engine-scans/{id}/execute/
        """
        scan = get_object_or_404(EngineScan, pk=pk)
        
        if scan.status not in ['pending', 'failed']:
            return Response(
                {'error': f'Cannot execute scan with status: {scan.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            result = self.service.execute_scan(scan)
            
            return Response({
                'scan_id': scan.id,
                'status': 'completed',
                'message': 'Scan executed successfully',
                'result': result
            })
        
        except Exception as e:
            logger.error(f"Failed to execute scan {pk}: {e}", exc_info=True)
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def summary(self, request, pk=None):
        """
        Get scan summary.
        
        GET /api/engine-scans/{id}/summary/
        """
        try:
            summary = self.service.get_scan_summary(pk)
            
            if 'error' in summary:
                return Response(summary, status=status.HTTP_404_NOT_FOUND)
            
            return Response(summary)
        
        except Exception as e:
            logger.error(f"Failed to get scan summary {pk}: {e}", exc_info=True)
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def findings(self, request, pk=None):
        """
        Get scan findings with filtering.
        
        GET /api/engine-scans/{id}/findings/?severity=high&engine_id=bandit&exclude_duplicates=true
        """
        try:
            severity = request.query_params.get('severity')
            engine_id = request.query_params.get('engine_id')
            exclude_duplicates = request.query_params.get('exclude_duplicates', 'true').lower() == 'true'
            
            findings = self.service.get_scan_findings(
                scan_id=pk,
                severity=severity,
                engine_id=engine_id,
                exclude_duplicates=exclude_duplicates
            )
            
            return Response({
                'scan_id': pk,
                'count': len(findings),
                'findings': findings
            })
        
        except Exception as e:
            logger.error(f"Failed to get findings for scan {pk}: {e}", exc_info=True)
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def history(self, request):
        """
        Get scan history.
        
        GET /api/engine-scans/history/?limit=10&target_path=/path
        """
        try:
            limit = int(request.query_params.get('limit', 10))
            target_path = request.query_params.get('target_path')
            
            history = self.service.get_scan_history(
                limit=limit,
                target_path=target_path
            )
            
            return Response({
                'count': len(history),
                'history': history
            })
        
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}", exc_info=True)
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EngineExecutionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing engine execution details.
    """
    queryset = EngineExecution.objects.all()
    serializer_class = EngineExecutionSerializer
    permission_classes = []
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by scan if provided
        scan_id = self.request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(engine_scan_id=scan_id)
        
        # Filter by engine if provided
        engine_id = self.request.query_params.get('engine_id')
        if engine_id:
            queryset = queryset.filter(engine_id=engine_id)
        
        return queryset


class EngineFindingViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing engine findings.
    """
    queryset = EngineFinding.objects.all()
    serializer_class = EngineFindingSerializer
    permission_classes = []
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by scan if provided
        scan_id = self.request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(engine_scan_id=scan_id)
        
        # Filter by severity if provided
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by engine if provided
        engine_id = self.request.query_params.get('engine_id')
        if engine_id:
            queryset = queryset.filter(engine_id=engine_id)
        
        # Exclude duplicates by default
        exclude_duplicates = self.request.query_params.get('exclude_duplicates', 'true').lower() == 'true'
        if exclude_duplicates:
            queryset = queryset.filter(is_duplicate=False)
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def mark_status(self, request, pk=None):
        """
        Mark finding status (confirmed, false_positive, fixed, accepted).
        
        POST /api/engine-findings/{id}/mark_status/
        
        Body:
        {
            "status": "confirmed",
            "reviewed": true
        }
        """
        finding = get_object_or_404(EngineFinding, pk=pk)
        
        new_status = request.data.get('status')
        if not new_status:
            return Response(
                {'error': 'status is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        valid_statuses = ['new', 'confirmed', 'false_positive', 'fixed', 'accepted']
        if new_status not in valid_statuses:
            return Response(
                {'error': f'Invalid status. Must be one of: {valid_statuses}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        finding.status = new_status
        finding.reviewed = request.data.get('reviewed', True)
        finding.save(update_fields=['status', 'reviewed'])
        
        return Response({
            'id': finding.id,
            'status': finding.status,
            'reviewed': finding.reviewed,
            'message': 'Finding status updated successfully'
        })
