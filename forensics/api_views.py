"""REST API views for the Forensics app."""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from .models import ForensicCase, EvidenceItem, ForensicFile, IOCIndicator, TimelineEvent, AnalysisTask
import json


def api_cases(request):
    cases = ForensicCase.objects.all().values(
        'id', 'case_number', 'title', 'status', 'classification', 'created_at'
    )
    return JsonResponse({'cases': list(cases)})


def api_case_detail(request, pk):
    case = get_object_or_404(ForensicCase, pk=pk)
    data = {
        'id': case.id,
        'case_number': case.case_number,
        'title': case.title,
        'description': case.description,
        'status': case.status,
        'classification': case.classification,
        'created_at': case.created_at.isoformat(),
        'evidence_count': case.evidence_items.count(),
        'file_count': case.files.count(),
    }
    return JsonResponse(data)


def api_evidence(request, case_pk=None):
    evidence = EvidenceItem.objects.all()
    if case_pk:
        evidence = evidence.filter(case_id=case_pk)
    data = list(evidence.values(
        'id', 'name', 'acquisition_type', 'acquisition_timestamp',
        'sha256_hash', 'integrity_verified', 'case_id'
    ))
    return JsonResponse({'evidence': data})


def api_files(request):
    files = ForensicFile.objects.all()
    data = list(files.values(
        'id', 'original_filename', 'file_size', 'file_type', 'sha256_hash',
        'upload_date', 'entropy', 'is_encrypted', 'is_packed', 'analysis_complete'
    ))
    return JsonResponse({'files': data})


def api_file_detail(request, pk):
    f = get_object_or_404(ForensicFile, pk=pk)
    data = {
        'id': f.id,
        'original_filename': f.original_filename,
        'file_size': f.file_size,
        'file_type': f.file_type,
        'mime_type': f.mime_type,
        'sha256_hash': f.sha256_hash,
        'md5_hash': f.md5_hash,
        'sha1_hash': f.sha1_hash,
        'entropy': f.entropy,
        'is_encrypted': f.is_encrypted,
        'is_packed': f.is_packed,
        'magic_bytes': f.magic_bytes,
        'upload_date': f.upload_date.isoformat(),
        'analysis_complete': f.analysis_complete,
        'ioc_count': f.iocs.count(),
        'timeline_count': f.timeline_events.count(),
    }
    return JsonResponse(data)


def api_iocs(request):
    iocs = IOCIndicator.objects.all()
    ioc_type = request.GET.get('type')
    if ioc_type:
        iocs = iocs.filter(ioc_type=ioc_type)
    limit = min(int(request.GET.get('limit', 100)), 1000)
    data = list(iocs.values(
        'id', 'ioc_type', 'ioc_value', 'confidence', 'source', 'mitre_technique', 'first_seen'
    )[:limit])
    return JsonResponse({'iocs': data, 'total': iocs.count()})


def api_timeline(request):
    events = TimelineEvent.objects.all().order_by('event_time')
    forensic_file_id = request.GET.get('file_id')
    if forensic_file_id:
        events = events.filter(forensic_file_id=forensic_file_id)
    limit = min(int(request.GET.get('limit', 200)), 5000)
    data = list(events.values(
        'id', 'event_time', 'event_type', 'source', 'description', 'artifact_path'
    )[:limit])
    return JsonResponse({'events': data, 'total': events.count()})


def api_stats(request):
    from django.db.models import Count
    stats = {
        'total_cases': ForensicCase.objects.count(),
        'open_cases': ForensicCase.objects.filter(status='open').count(),
        'total_evidence': EvidenceItem.objects.count(),
        'total_files': ForensicFile.objects.count(),
        'total_iocs': IOCIndicator.objects.count(),
        'total_timeline_events': TimelineEvent.objects.count(),
        'pending_tasks': AnalysisTask.objects.filter(status='pending').count(),
        'ioc_types': list(IOCIndicator.objects.values('ioc_type').annotate(count=Count('id'))),
    }
    return JsonResponse(stats)
