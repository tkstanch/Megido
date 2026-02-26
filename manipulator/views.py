import csv

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.utils import timezone
import json

from .models import (
    VulnerabilityType, Payload, EncodingTechnique,
    PayloadManipulation, CraftedPayload,
    AttackCampaign, DiscoveredInjectionPoint, InjectionResult, PayloadSource,
)
from .encoding_utils import apply_encoding, apply_multiple_encodings, get_available_encodings


def manipulator_home(request):
    """
    Main manipulator page showing all vulnerability types.
    """
    vulnerabilities = VulnerabilityType.objects.all()
    context = {
        'title': 'Payload Manipulator',
        'vulnerabilities': vulnerabilities,
    }
    return render(request, 'manipulator/home.html', context)


def vulnerability_detail(request, vuln_id):
    """
    Show details for a specific vulnerability with its payloads and tricks.
    """
    vulnerability = get_object_or_404(VulnerabilityType, id=vuln_id)
    payloads = vulnerability.payloads.all()
    manipulation_tricks = vulnerability.manipulation_tricks.all()
    
    context = {
        'title': f'{vulnerability.name} - Payload Manipulator',
        'vulnerability': vulnerability,
        'payloads': payloads,
        'manipulation_tricks': manipulation_tricks,
    }
    return render(request, 'manipulator/vulnerability_detail.html', context)


def craft_payload(request):
    """
    Page for crafting and encoding payloads.
    """
    vulnerabilities = VulnerabilityType.objects.all()
    encodings = get_available_encodings()
    
    if request.method == 'POST':
        payload_id = request.POST.get('payload_id')
        base_text = request.POST.get('base_text', '')
        selected_encodings = request.POST.getlist('encodings')
        
        # Get base payload if specified
        base_payload = None
        if payload_id:
            base_payload = get_object_or_404(Payload, id=payload_id)
            if not base_text:
                base_text = base_payload.payload_text
        
        # Apply encodings
        if selected_encodings and base_text:
            crafted_text, success, errors = apply_multiple_encodings(
                base_text, selected_encodings
            )
            
            # Save crafted payload
            if base_payload:
                crafted = CraftedPayload.objects.create(
                    base_payload=base_payload,
                    crafted_text=crafted_text,
                    encodings_applied=selected_encodings
                )
                messages.success(request, 'Payload crafted and saved successfully!')
            
            context = {
                'title': 'Craft Payload',
                'vulnerabilities': vulnerabilities,
                'encodings': encodings,
                'base_text': base_text,
                'crafted_text': crafted_text,
                'selected_encodings': selected_encodings,
                'success': success,
                'errors': errors,
            }
            return render(request, 'manipulator/craft_payload.html', context)
    
    context = {
        'title': 'Craft Payload',
        'vulnerabilities': vulnerabilities,
        'encodings': encodings,
    }
    return render(request, 'manipulator/craft_payload.html', context)


@require_http_methods(["POST"])
def encode_payload_ajax(request):
    """
    AJAX endpoint to encode payload in real-time.
    """
    try:
        data = json.loads(request.body)
        payload_text = data.get('payload', '')
        encoding_name = data.get('encoding', '')
        
        encoded, success, error = apply_encoding(payload_text, encoding_name)
        
        return JsonResponse({
            'success': success,
            'encoded': encoded,
            'error': error
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


def payload_library(request):
    """
    View all payloads across all vulnerabilities.
    """
    vuln_filter = request.GET.get('vulnerability', '')
    platform_filter = request.GET.get('platform', '')
    
    payloads = Payload.objects.all().select_related('vulnerability')
    
    if vuln_filter:
        payloads = payloads.filter(vulnerability__name=vuln_filter)
    
    if platform_filter:
        payloads = payloads.filter(platform__icontains=platform_filter)
    
    vulnerabilities = VulnerabilityType.objects.all()
    
    context = {
        'title': 'Payload Library',
        'payloads': payloads,
        'vulnerabilities': vulnerabilities,
        'selected_vuln': vuln_filter,
        'selected_platform': platform_filter,
    }
    return render(request, 'manipulator/payload_library.html', context)


def add_payload(request):
    """
    Add a custom payload.
    """
    if request.method == 'POST':
        vuln_id = request.POST.get('vulnerability')
        name = request.POST.get('name')
        payload_text = request.POST.get('payload_text')
        description = request.POST.get('description', '')
        bypass_technique = request.POST.get('bypass_technique', '')
        platform = request.POST.get('platform', '')
        
        vulnerability = get_object_or_404(VulnerabilityType, id=vuln_id)
        
        payload = Payload.objects.create(
            vulnerability=vulnerability,
            name=name,
            payload_text=payload_text,
            description=description,
            bypass_technique=bypass_technique,
            platform=platform,
            is_custom=True
        )
        
        messages.success(request, f'Payload "{name}" added successfully!')
        return redirect('manipulator:vulnerability_detail', vuln_id=vuln_id)
    
    vulnerabilities = VulnerabilityType.objects.all()
    context = {
        'title': 'Add Custom Payload',
        'vulnerabilities': vulnerabilities,
    }
    return render(request, 'manipulator/add_payload.html', context)


def crafted_payloads(request):
    """
    View all crafted payloads.
    """
    crafted = CraftedPayload.objects.all().select_related('base_payload__vulnerability')
    
    context = {
        'title': 'Crafted Payloads',
        'crafted_payloads': crafted,
    }
    return render(request, 'manipulator/crafted_payloads.html', context)


def manipulation_tricks(request):
    """
    View all manipulation tricks and bypass techniques.
    """
    vuln_filter = request.GET.get('vulnerability', '')
    
    tricks = PayloadManipulation.objects.all().select_related('vulnerability')
    
    if vuln_filter:
        tricks = tricks.filter(vulnerability__name=vuln_filter)
    
    vulnerabilities = VulnerabilityType.objects.all()
    
    context = {
        'title': 'Manipulation Tricks',
        'tricks': tricks,
        'vulnerabilities': vulnerabilities,
        'selected_vuln': vuln_filter,
    }
    return render(request, 'manipulator/manipulation_tricks.html', context)


def encoding_tools(request):
    """
    Encoding tools page with all available encodings.
    """
    encodings = get_available_encodings()
    
    if request.method == 'POST':
        input_text = request.POST.get('input_text', '')
        encoding_name = request.POST.get('encoding')
        
        if input_text and encoding_name:
            encoded, success, error = apply_encoding(input_text, encoding_name)
            
            context = {
                'title': 'Encoding Tools',
                'encodings': encodings,
                'input_text': input_text,
                'encoded_text': encoded,
                'selected_encoding': encoding_name,
                'success': success,
                'error': error,
            }
            return render(request, 'manipulator/encoding_tools.html', context)
    
    context = {
        'title': 'Encoding Tools',
        'encodings': encodings,
    }
    return render(request, 'manipulator/encoding_tools.html', context)


# === Campaign Views ===


def campaign_list(request):
    """List all campaigns."""
    campaigns = AttackCampaign.objects.all().order_by('-created_at')
    context = {
        'title': 'Attack Campaigns',
        'campaigns': campaigns,
    }
    return render(request, 'manipulator/campaign_list.html', context)


def campaign_start(request):
    """Launch a new attack campaign."""
    vulnerabilities = VulnerabilityType.objects.all()

    if request.method == 'POST':
        name = request.POST.get('name', 'Campaign').strip() or 'Campaign'
        target_url = request.POST.get('target_url', '').strip()
        mode = request.POST.get('mode', 'auto')
        manipulation_level = request.POST.get('manipulation_level', 'moderate')
        concurrency = int(request.POST.get('concurrency', 10))
        max_depth = int(request.POST.get('max_depth', 5))
        vuln_types = request.POST.getlist('vuln_types')
        custom_payload_text = request.POST.get('custom_payload_text', '')
        use_builtin = request.POST.get('use_builtin_payloads') == 'on'
        use_custom = request.POST.get('use_custom_payloads') == 'on'
        include_headers = request.POST.get('include_headers') == 'on'
        include_cookies = request.POST.get('include_cookies') == 'on'

        if not target_url:
            messages.error(request, 'Target URL is required.')
        else:
            campaign = AttackCampaign.objects.create(
                name=name,
                target_url=target_url,
                mode=mode,
                manipulation_level=manipulation_level,
                concurrency=max(1, min(20, concurrency)),
                max_depth=max(1, min(10, max_depth)),
                vuln_types_to_test=vuln_types,
                custom_payload_text=custom_payload_text,
                use_builtin_payloads=use_builtin,
                use_custom_payloads=use_custom,
                include_headers=include_headers,
                include_cookies=include_cookies,
                status='pending',
            )

            if mode in ('auto', 'semi'):
                try:
                    from .campaign_manager import CampaignManager
                    manager = CampaignManager(campaign.id)
                    manager.start()
                    campaign.status = 'crawling'
                    campaign.started_at = timezone.now()
                    campaign.save(update_fields=['status', 'started_at'])
                except Exception as e:
                    messages.warning(request, f'Campaign created but could not start automatically: {e}')

            messages.success(request, f'Campaign "{name}" created successfully!')
            return redirect('manipulator:campaign_detail', campaign_id=campaign.id)

    context = {
        'title': 'Launch Attack Campaign',
        'vulnerabilities': vulnerabilities,
    }
    return render(request, 'manipulator/campaign_start.html', context)


def campaign_detail(request, campaign_id):
    """Campaign detail dashboard."""
    campaign = get_object_or_404(AttackCampaign, id=campaign_id)
    injection_points = campaign.injection_points.all()[:50]
    recent_results = campaign.results.filter(is_successful=True).order_by('-tested_at')[:20]
    context = {
        'title': f'Campaign: {campaign.name}',
        'campaign': campaign,
        'injection_points': injection_points,
        'recent_results': recent_results,
    }
    return render(request, 'manipulator/campaign_dashboard.html', context)


def campaign_status(request, campaign_id):
    """AJAX endpoint for live campaign status."""
    campaign = get_object_or_404(AttackCampaign, id=campaign_id)
    return JsonResponse({
        'status': campaign.status,
        'total_injection_points': campaign.total_injection_points,
        'total_payloads_tested': campaign.total_payloads_tested,
        'total_requests_sent': campaign.total_requests_sent,
        'successful_exploits': campaign.successful_exploits,
        'recent_exploits': list(
            campaign.results.filter(is_successful=True)
            .order_by('-tested_at')[:10]
            .values('id', 'vulnerability_type', 'severity', 'request_url', 'tested_at')
        ),
    })


@require_http_methods(["POST"])
def campaign_pause(request, campaign_id):
    """Pause a running campaign."""
    campaign = get_object_or_404(AttackCampaign, id=campaign_id)
    if campaign.status in ('crawling', 'injecting'):
        campaign.status = 'paused'
        campaign.save(update_fields=['status'])
        return JsonResponse({'status': 'paused'})
    return JsonResponse({'error': 'Campaign not running'}, status=400)


@require_http_methods(["POST"])
def campaign_resume(request, campaign_id):
    """Resume a paused campaign."""
    campaign = get_object_or_404(AttackCampaign, id=campaign_id)
    if campaign.status == 'paused':
        try:
            from .campaign_manager import CampaignManager
            manager = CampaignManager(campaign.id)
            manager.start()
            campaign.status = 'injecting'
            campaign.save(update_fields=['status'])
            return JsonResponse({'status': 'resumed'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Campaign not paused'}, status=400)


def campaign_results(request, campaign_id):
    """View all injection results for a campaign."""
    campaign = get_object_or_404(AttackCampaign, id=campaign_id)
    results = campaign.results.all().order_by('-is_successful', '-tested_at')
    context = {
        'title': f'Results: {campaign.name}',
        'campaign': campaign,
        'results': results,
        'show_all': True,
    }
    return render(request, 'manipulator/campaign_results.html', context)


def campaign_exploits(request, campaign_id):
    """View only successful exploits with PoCs."""
    campaign = get_object_or_404(AttackCampaign, id=campaign_id)
    exploits = campaign.results.filter(is_successful=True).order_by('-tested_at')
    context = {
        'title': f'Exploits: {campaign.name}',
        'campaign': campaign,
        'results': exploits,
        'show_all': False,
    }
    return render(request, 'manipulator/campaign_results.html', context)


def exploit_detail(request, result_id):
    """Full PoC view for a single exploit."""
    result = get_object_or_404(InjectionResult, id=result_id)
    context = {
        'title': f'Exploit: {result.vulnerability_type}',
        'result': result,
    }
    return render(request, 'manipulator/exploit_detail.html', context)


def campaign_export(request, campaign_id):
    """Export campaign results as JSON or CSV."""
    campaign = get_object_or_404(AttackCampaign, id=campaign_id)
    export_format = request.GET.get('format', 'json')

    if export_format == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="campaign_{campaign_id}_results.csv"'
        writer = csv.writer(response)
        writer.writerow(['ID', 'URL', 'Parameter', 'Type', 'Payload', 'Vuln Type', 'Severity', 'Success', 'Confidence', 'Tested At'])
        for r in campaign.results.all():
            writer.writerow([
                r.id, r.request_url, r.injection_point.parameter_name,
                r.injection_point.parameter_type, r.payload_text[:100],
                r.vulnerability_type, r.severity, r.is_successful,
                f'{r.confidence:.0%}', r.tested_at.isoformat(),
            ])
        return response
    else:
        data = {
            'campaign': {
                'id': campaign.id,
                'name': campaign.name,
                'target_url': campaign.target_url,
                'status': campaign.status,
                'total_injection_points': campaign.total_injection_points,
                'total_payloads_tested': campaign.total_payloads_tested,
                'successful_exploits': campaign.successful_exploits,
            },
            'results': list(campaign.results.values(
                'id', 'payload_text', 'vulnerability_type', 'severity',
                'is_successful', 'confidence', 'request_url', 'response_status',
                'detection_method', 'evidence', 'tested_at',
            )),
        }
        return JsonResponse(data)


def payload_import(request):
    """Import payloads from text/file."""
    from .payload_learner import PayloadLearner

    vulnerabilities = VulnerabilityType.objects.all()

    if request.method == 'POST':
        payload_text = request.POST.get('payload_text', '')
        vuln_type_override = request.POST.get('vuln_type', '') or None
        source_name = request.POST.get('source_name', 'Imported')

        if not payload_text:
            messages.error(request, 'No payloads provided.')
        else:
            learner = PayloadLearner()
            import_result = learner.import_payloads(payload_text, vuln_type_override)
            save_result = learner.save_imported_payloads(import_result['payloads'], source_name)

            messages.success(
                request,
                f'Import complete: {save_result["saved"]} payloads saved, '
                f'{save_result["skipped"]} skipped (duplicates).',
            )

            context = {
                'title': 'Import Payloads',
                'vulnerabilities': vulnerabilities,
                'import_result': import_result,
                'save_result': save_result,
            }
            return render(request, 'manipulator/payload_import.html', context)

    context = {
        'title': 'Import Payloads',
        'vulnerabilities': vulnerabilities,
    }
    return render(request, 'manipulator/payload_import.html', context)


def payload_effectiveness(request):
    """View payload effectiveness rankings."""
    vulnerabilities = VulnerabilityType.objects.prefetch_related('payloads').all()
    top_payloads = Payload.objects.filter(success_rate__gt=0).order_by('-success_rate')[:50]
    context = {
        'title': 'Payload Effectiveness',
        'vulnerabilities': vulnerabilities,
        'top_payloads': top_payloads,
    }
    return render(request, 'manipulator/payload_effectiveness.html', context)
