"""Views for the Forensics app."""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.db.models import Count, Q
import json
import os

from .models import (ForensicCase, EvidenceItem, ChainOfCustodyEntry, ForensicFile,
                     TimelineEvent, IOCIndicator, ForensicReport, AnalysisTask, YARARule)
from .forms import ForensicFileUploadForm, ForensicCaseForm, EvidenceItemForm
from .utils.parse import analyze_file, extract_device_info
from .utils.ioc_extraction import extract_iocs
from .utils.entropy import calculate_entropy, calculate_file_entropy, is_likely_encrypted, is_likely_packed
from .utils.file_signatures import detect_by_magic_bytes
from .utils.reporting import generate_html_report, generate_json_report


def dashboard(request):
    case_count = ForensicCase.objects.count()
    evidence_count = EvidenceItem.objects.count()
    file_count = ForensicFile.objects.count()
    ioc_count = IOCIndicator.objects.count()
    recent_cases = ForensicCase.objects.all()[:5]
    recent_files = ForensicFile.objects.all()[:5]
    active_tasks = AnalysisTask.objects.filter(status__in=['pending', 'running'])[:10]
    context = {
        'case_count': case_count,
        'evidence_count': evidence_count,
        'file_count': file_count,
        'ioc_count': ioc_count,
        'recent_cases': recent_cases,
        'recent_files': recent_files,
        'active_tasks': active_tasks,
    }
    return render(request, 'forensics/dashboard.html', context)


def upload_file(request):
    if request.method == 'POST':
        form = ForensicFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            forensic_file = form.save(commit=False)
            uploaded_file = request.FILES['uploaded_file']
            forensic_file.original_filename = uploaded_file.name
            try:
                analysis_results = analyze_file(uploaded_file, uploaded_file.name)
                device_info = extract_device_info(uploaded_file, uploaded_file.name)
                forensic_file.sha256_hash = analysis_results['sha256_hash']
                forensic_file.md5_hash = analysis_results['md5_hash']
                forensic_file.file_size = analysis_results['file_size']
                forensic_file.file_type = analysis_results['file_type']
                forensic_file.mime_type = analysis_results['mime_type']
                forensic_file.hex_sample = analysis_results['hex_sample']
                forensic_file.device_model = device_info.get('device_model')
                forensic_file.os_version = device_info.get('os_version')
                forensic_file.serial_number = device_info.get('serial_number')
                uploaded_file.seek(0)
                raw_data = uploaded_file.read(65536)
                uploaded_file.seek(0)
                ent = calculate_entropy(raw_data)
                forensic_file.entropy = ent
                forensic_file.is_encrypted = is_likely_encrypted(ent)
                forensic_file.is_packed = is_likely_packed(ent)
                sig_result = detect_by_magic_bytes(raw_data)
                if sig_result:
                    forensic_file.magic_bytes = sig_result.get('magic_hex', '')
                    if not forensic_file.file_type or forensic_file.file_type.startswith('Unknown'):
                        forensic_file.file_type = sig_result.get('description', forensic_file.file_type)
                        forensic_file.mime_type = sig_result.get('mime_type', forensic_file.mime_type)
                forensic_file.analysis_complete = True
                forensic_file.save()
                try:
                    ioc_results = extract_iocs(raw_data)
                    for ioc_type, ioc_list in ioc_results.items():
                        for ioc_val in ioc_list[:50]:
                            IOCIndicator.objects.get_or_create(
                                ioc_type=ioc_type,
                                ioc_value=str(ioc_val)[:500],
                                defaults={
                                    'source': forensic_file.original_filename,
                                    'forensic_file': forensic_file,
                                    'confidence': 'medium',
                                }
                            )
                except Exception:
                    pass
                messages.success(request, f'File "{uploaded_file.name}" uploaded and analyzed successfully!')
                return redirect('forensics:file_detail', pk=forensic_file.pk)
            except Exception as e:
                messages.error(request, f'Error analyzing file: {str(e)}')
                return redirect('forensics:upload')
    else:
        form = ForensicFileUploadForm()
    return render(request, 'forensics/upload.html', {'form': form})


def file_detail(request, pk):
    forensic_file = get_object_or_404(ForensicFile, pk=pk)
    hex_sample = forensic_file.hex_sample
    hex_lines = []
    if hex_sample:
        hex_bytes = hex_sample.split()
        for i in range(0, len(hex_bytes), 16):
            line_bytes = hex_bytes[i:i+16]
            hex_part = ' '.join(line_bytes)
            ascii_part = ''.join(
                chr(int(b, 16)) if 32 <= int(b, 16) < 127 else '.'
                for b in line_bytes
            )
            hex_lines.append({'offset': f'{i:08x}', 'hex': hex_part, 'ascii': ascii_part})
    iocs = forensic_file.iocs.all()[:100]
    timeline = forensic_file.timeline_events.all()[:50]
    context = {'file': forensic_file, 'hex_lines': hex_lines, 'iocs': iocs, 'timeline': timeline}
    return render(request, 'forensics/detail.html', context)


def file_list(request):
    files = ForensicFile.objects.all()
    paginator = Paginator(files, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'forensics/list.html', {'page_obj': page_obj})


def case_list(request):
    cases = ForensicCase.objects.annotate(
        evidence_count=Count('evidence_items'),
        file_count=Count('files')
    )
    paginator = Paginator(cases, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'forensics/case_list.html', {'page_obj': page_obj})


def case_create(request):
    if request.method == 'POST':
        form = ForensicCaseForm(request.POST)
        if form.is_valid():
            case = form.save(commit=False)
            if request.user.is_authenticated:
                case.investigator = request.user
            case.save()
            messages.success(request, f'Case {case.case_number} created successfully!')
            return redirect('forensics:case_detail', pk=case.pk)
    else:
        form = ForensicCaseForm()
    return render(request, 'forensics/case_create.html', {'form': form})


def case_detail(request, pk):
    case = get_object_or_404(ForensicCase, pk=pk)
    evidence_items = case.evidence_items.all()
    files = case.files.all()
    reports = case.reports.all()
    iocs = IOCIndicator.objects.filter(
        Q(forensic_file__case=case) | Q(evidence_item__case=case)
    ).distinct()[:100]
    timeline = TimelineEvent.objects.filter(
        Q(forensic_file__case=case) | Q(evidence_item__case=case)
    ).order_by('event_time')[:200]
    context = {
        'case': case,
        'evidence_items': evidence_items,
        'files': files,
        'reports': reports,
        'iocs': iocs,
        'timeline': timeline,
    }
    return render(request, 'forensics/case_detail.html', context)


def evidence_detail(request, pk):
    evidence = get_object_or_404(EvidenceItem, pk=pk)
    custody_entries = evidence.custody_entries.all()
    artifacts = evidence.artifacts.all()[:100]
    iocs = evidence.iocs.all()[:100]
    timeline = evidence.timeline_events.order_by('event_time')[:200]
    context = {
        'evidence': evidence,
        'custody_entries': custody_entries,
        'artifacts': artifacts,
        'iocs': iocs,
        'timeline': timeline,
    }
    return render(request, 'forensics/evidence_detail.html', context)


def ioc_list(request):
    iocs = IOCIndicator.objects.all()
    ioc_type_filter = request.GET.get('type')
    if ioc_type_filter:
        iocs = iocs.filter(ioc_type=ioc_type_filter)
    search_q = request.GET.get('q')
    if search_q:
        iocs = iocs.filter(ioc_value__icontains=search_q)
    paginator = Paginator(iocs, 50)
    page_obj = paginator.get_page(request.GET.get('page'))
    ioc_types = IOCIndicator.IOC_TYPES
    return render(request, 'forensics/ioc_list.html', {
        'page_obj': page_obj,
        'ioc_types': ioc_types,
        'ioc_type_filter': ioc_type_filter,
        'search_q': search_q,
    })


def ioc_export(request):
    iocs = IOCIndicator.objects.all()
    ioc_type_filter = request.GET.get('type')
    if ioc_type_filter:
        iocs = iocs.filter(ioc_type=ioc_type_filter)
    export_format = request.GET.get('format', 'json')
    if export_format == 'json':
        data = list(iocs.values('ioc_type', 'ioc_value', 'confidence', 'source', 'mitre_technique'))
        return JsonResponse({'iocs': data})
    elif export_format == 'csv':
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['type', 'value', 'confidence', 'source', 'mitre_technique'])
        for ioc in iocs:
            writer.writerow([ioc.ioc_type, ioc.ioc_value, ioc.confidence, ioc.source, ioc.mitre_technique])
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="iocs.csv"'
        return response
    elif export_format == 'stix':
        try:
            from .utils.stix_export import export_iocs_to_stix
            stix_data = export_iocs_to_stix(list(iocs))
            return JsonResponse(stix_data)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Unsupported format'}, status=400)


def report_list(request):
    reports = ForensicReport.objects.all()
    paginator = Paginator(reports, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    return render(request, 'forensics/report_list.html', {'page_obj': page_obj})


def report_generate(request, case_pk):
    case = get_object_or_404(ForensicCase, pk=case_pk)
    report_type = request.GET.get('type', 'technical')
    report_format = request.GET.get('format', 'html')
    if report_format == 'html':
        html_content = generate_html_report(case)
        ForensicReport.objects.create(
            case=case,
            report_type=report_type,
            format='html',
            title=f"{case.title} - {report_type.title()} Report",
            generated_by=request.user if request.user.is_authenticated else None,
            summary=f"Auto-generated {report_type} report for case {case.case_number}",
        )
        return HttpResponse(html_content, content_type='text/html')
    elif report_format == 'json':
        json_data = generate_json_report(case)
        ForensicReport.objects.create(
            case=case,
            report_type=report_type,
            format='json',
            title=f"{case.title} - {report_type.title()} Report",
            generated_by=request.user if request.user.is_authenticated else None,
        )
        return JsonResponse(json_data)
    elif report_format == 'pdf':
        try:
            from .utils.reporting import generate_pdf_report
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
                tmp_path = tmp.name
            pdf_path = generate_pdf_report(case, tmp_path)
            with open(pdf_path, 'rb') as f:
                pdf_content = f.read()
            os.unlink(pdf_path)
            ForensicReport.objects.create(
                case=case,
                report_type=report_type,
                format='pdf',
                title=f"{case.title} - {report_type.title()} Report",
                generated_by=request.user if request.user.is_authenticated else None,
            )
            response = HttpResponse(pdf_content, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="report_{case.case_number}.pdf"'
            return response
        except Exception as e:
            messages.error(request, f'PDF generation failed: {str(e)}')
            return redirect('forensics:case_detail', pk=case_pk)
    messages.error(request, 'Unsupported report format')
    return redirect('forensics:case_detail', pk=case_pk)


def analysis_disk(request, pk):
    forensic_file = get_object_or_404(ForensicFile, pk=pk)
    result = {}
    if request.method == 'POST':
        try:
            from .utils.disk_analysis import analyze_disk_image
            file_path = forensic_file.uploaded_file.path
            result = analyze_disk_image(file_path)
            AnalysisTask.objects.create(
                forensic_file=forensic_file,
                task_type='disk',
                status='completed',
                result_summary=json.dumps(result)[:1000],
                completed_at=timezone.now(),
            )
            messages.success(request, 'Disk analysis completed.')
        except Exception as e:
            messages.error(request, f'Disk analysis failed: {str(e)}')
    return render(request, 'forensics/analysis_results.html', {
        'forensic_file': forensic_file,
        'analysis_type': 'Disk Analysis',
        'result': result,
    })


def analysis_memory(request, pk):
    forensic_file = get_object_or_404(ForensicFile, pk=pk)
    result = {}
    if request.method == 'POST':
        try:
            from .utils.memory_analysis import analyze_memory_dump
            file_path = forensic_file.uploaded_file.path
            result = analyze_memory_dump(file_path)
            AnalysisTask.objects.create(
                forensic_file=forensic_file,
                task_type='memory',
                status='completed',
                result_summary=json.dumps(result)[:1000],
                completed_at=timezone.now(),
            )
            messages.success(request, 'Memory analysis completed.')
        except Exception as e:
            messages.error(request, f'Memory analysis failed: {str(e)}')
    return render(request, 'forensics/analysis_results.html', {
        'forensic_file': forensic_file,
        'analysis_type': 'Memory Analysis',
        'result': result,
    })


def analysis_network(request, pk):
    forensic_file = get_object_or_404(ForensicFile, pk=pk)
    result = {}
    if request.method == 'POST':
        try:
            from .utils.network_forensics import analyze_pcap
            file_path = forensic_file.uploaded_file.path
            result = analyze_pcap(file_path)
            AnalysisTask.objects.create(
                forensic_file=forensic_file,
                task_type='network',
                status='completed',
                result_summary=json.dumps(result)[:1000],
                completed_at=timezone.now(),
            )
            messages.success(request, 'Network analysis completed.')
        except Exception as e:
            messages.error(request, f'Network analysis failed: {str(e)}')
    return render(request, 'forensics/analysis_results.html', {
        'forensic_file': forensic_file,
        'analysis_type': 'Network Analysis',
        'result': result,
    })


def analysis_timeline(request, pk):
    forensic_file = get_object_or_404(ForensicFile, pk=pk)
    if request.method == 'POST':
        try:
            from .utils.timeline import generate_timeline
            events = generate_timeline(forensic_file)
            for ev in events[:500]:
                TimelineEvent.objects.create(
                    forensic_file=forensic_file,
                    event_time=ev.get('event_time', timezone.now()),
                    event_type=ev.get('event_type', 'other'),
                    source=ev.get('source', 'unknown'),
                    description=ev.get('description', ''),
                    artifact_path=ev.get('artifact_path', ''),
                )
            messages.success(request, f'Timeline generated with {len(events)} events.')
        except Exception as e:
            messages.error(request, f'Timeline generation failed: {str(e)}')
    existing_events = forensic_file.timeline_events.all().order_by('event_time')
    return render(request, 'forensics/timeline.html', {
        'forensic_file': forensic_file,
        'events': existing_events,
    })


def yara_rule_list(request):
    rules = YARARule.objects.filter(is_active=True)
    return render(request, 'forensics/yara_rules.html', {'rules': rules})
