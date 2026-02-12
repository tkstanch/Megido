"""
REST API views for the Discover app.
"""
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.pagination import PageNumberPagination
from django.db.models import Q, Count
from django.utils import timezone
import json
import threading
import logging

from .models import Scan, SensitiveFinding
from .serializers import (
    ScanSerializer, ScanListSerializer, ScanCreateSerializer,
    SensitiveFindingSerializer, SensitiveFindingListSerializer,
    ScanStatusSerializer
)
from .utils import (
    collect_wayback_urls, 
    collect_shodan_data, 
    collect_hunter_emails,
    extract_domain,
    search_google_dorks
)
from .dorks import generate_dorks_for_target
from .views import run_sensitive_scan_async


logger = logging.getLogger(__name__)


class StandardResultsSetPagination(PageNumberPagination):
    """Standard pagination class"""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class ScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for OSINT Scans.
    
    Provides:
    - list: Get all scans
    - retrieve: Get a specific scan
    - create: Start a new scan
    - update/partial_update: Update scan details
    - destroy: Delete a scan
    
    Custom actions:
    - status: Get real-time scan status
    - findings: Get findings for a scan with filtering
    - statistics: Get statistics about scans
    """
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    pagination_class = StandardResultsSetPagination
    permission_classes = [AllowAny]  # Configure based on requirements
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['target']
    ordering_fields = ['scan_date', 'total_findings', 'high_risk_findings']
    ordering = ['-scan_date']
    
    def get_serializer_class(self):
        """Use different serializers for list vs detail views"""
        if self.action == 'list':
            return ScanListSerializer
        elif self.action == 'create':
            return ScanCreateSerializer
        return ScanSerializer
    
    def create(self, request, *args, **kwargs):
        """
        Create a new scan.
        
        POST /api/scans/
        {
            "target": "example.com",
            "enable_sensitive_scan": true,
            "enable_dork_search": false
        }
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        target = serializer.validated_data['target']
        enable_sensitive_scan = serializer.validated_data.get('enable_sensitive_scan', True)
        enable_dork_search = serializer.validated_data.get('enable_dork_search', False)
        
        # Clean target
        target = extract_domain(target)
        
        # Collect data from all sources
        logger.info(f"Starting OSINT scan for {target}")
        wayback_results = collect_wayback_urls(target)
        shodan_results = collect_shodan_data(target)
        hunter_results = collect_hunter_emails(target)
        dork_queries = generate_dorks_for_target(target)
        
        # Search Google Dorks if enabled
        dork_results = {}
        if enable_dork_search:
            logger.info(f"Automated dork search enabled for {target}")
            dork_results = search_google_dorks(target, dork_queries)
        else:
            dork_results = {
                'search_enabled': False,
                'api_configured': False,
                'categories': {}
            }
        
        # Save scan to database
        scan = Scan.objects.create(
            target=target,
            wayback_urls=json.dumps(wayback_results.get('urls', [])),
            shodan_data=json.dumps(shodan_results.get('data', {})),
            hunter_data=json.dumps(hunter_results.get('emails', [])),
            dork_queries=json.dumps(dork_queries),
            dork_results=json.dumps(dork_results),
            total_urls=len(wayback_results.get('urls', [])),
            total_emails=len(hunter_results.get('emails', []))
        )
        
        # Start background sensitive scan if enabled
        if enable_sensitive_scan:
            urls = wayback_results.get('urls', [])
            if urls:
                url_list = [url.get('original') if isinstance(url, dict) else url for url in urls]
                thread = threading.Thread(
                    target=run_sensitive_scan_async,
                    args=(scan.id, url_list),
                    daemon=True
                )
                thread.start()
                logger.info(f"Started background sensitive scan for scan {scan.id}")
        
        # Return created scan
        response_serializer = ScanSerializer(scan)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """
        Get real-time status of a scan.
        
        GET /api/scans/{id}/status/
        """
        scan = self.get_object()
        serializer = ScanStatusSerializer({
            'scan_id': scan.id,
            'target': scan.target,
            'scan_completed': True,
            'sensitive_scan_completed': scan.sensitive_scan_completed,
            'total_findings': scan.total_findings,
            'high_risk_findings': scan.high_risk_findings,
            'scan_date': scan.scan_date,
        })
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def findings(self, request, pk=None):
        """
        Get findings for a scan with filtering options.
        
        GET /api/scans/{id}/findings/?severity=critical&verified=true
        """
        scan = self.get_object()
        findings = scan.sensitive_findings.all()
        
        # Apply filters
        severity = request.query_params.get('severity')
        if severity:
            findings = findings.filter(severity=severity)
        
        verified = request.query_params.get('verified')
        if verified is not None:
            findings = findings.filter(verified=verified.lower() == 'true')
        
        false_positive = request.query_params.get('false_positive')
        if false_positive is not None:
            findings = findings.filter(false_positive=false_positive.lower() == 'true')
        
        finding_type = request.query_params.get('type')
        if finding_type:
            findings = findings.filter(finding_type__icontains=finding_type)
        
        # Paginate results
        page = self.paginate_queryset(findings)
        if page is not None:
            serializer = SensitiveFindingSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = SensitiveFindingSerializer(findings, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """
        Get overall statistics about all scans.
        
        GET /api/scans/statistics/
        """
        total_scans = Scan.objects.count()
        total_findings = Scan.objects.aggregate(
            total=Count('sensitive_findings')
        )['total'] or 0
        
        recent_scans = Scan.objects.filter(
            scan_date__gte=timezone.now() - timezone.timedelta(days=7)
        ).count()
        
        high_risk_scans = Scan.objects.filter(
            high_risk_findings__gt=0
        ).count()
        
        # Findings by severity across all scans
        severity_stats = SensitiveFinding.objects.aggregate(
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
            medium=Count('id', filter=Q(severity='medium')),
            low=Count('id', filter=Q(severity='low')),
            info=Count('id', filter=Q(severity='info')),
        )
        
        return Response({
            'total_scans': total_scans,
            'total_findings': total_findings,
            'recent_scans_last_7_days': recent_scans,
            'scans_with_high_risk_findings': high_risk_scans,
            'findings_by_severity': severity_stats,
        })


class SensitiveFindingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Sensitive Findings.
    
    Provides CRUD operations and filtering for findings.
    """
    queryset = SensitiveFinding.objects.all()
    serializer_class = SensitiveFindingSerializer
    pagination_class = StandardResultsSetPagination
    permission_classes = [AllowAny]  # Configure based on requirements
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['finding_type', 'url', 'value']
    ordering_fields = ['discovered_at', 'severity']
    ordering = ['-discovered_at']
    
    def get_serializer_class(self):
        """Use lighter serializer for list views"""
        if self.action == 'list':
            return SensitiveFindingListSerializer
        return SensitiveFindingSerializer
    
    def get_queryset(self):
        """Apply query parameter filters"""
        queryset = super().get_queryset()
        
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by scan
        scan_id = self.request.query_params.get('scan_id')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        
        # Filter by verified status
        verified = self.request.query_params.get('verified')
        if verified is not None:
            queryset = queryset.filter(verified=verified.lower() == 'true')
        
        # Filter by false positive
        false_positive = self.request.query_params.get('false_positive')
        if false_positive is not None:
            queryset = queryset.filter(false_positive=false_positive.lower() == 'true')
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """
        Mark a finding as verified.
        
        POST /api/findings/{id}/verify/
        """
        finding = self.get_object()
        finding.verified = True
        finding.save()
        serializer = self.get_serializer(finding)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def mark_false_positive(self, request, pk=None):
        """
        Mark a finding as false positive.
        
        POST /api/findings/{id}/mark_false_positive/
        """
        finding = self.get_object()
        finding.false_positive = True
        finding.verified = False
        finding.save()
        serializer = self.get_serializer(finding)
        return Response(serializer.data)


@api_view(['GET'])
@permission_classes([AllowAny])
def api_health(request):
    """
    Health check endpoint for the API.
    
    GET /api/health/
    """
    return Response({
        'status': 'healthy',
        'service': 'Megido Discover API',
        'timestamp': timezone.now().isoformat(),
    })
