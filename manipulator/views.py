from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib import messages
import json

from .models import (
    VulnerabilityType, Payload, EncodingTechnique,
    PayloadManipulation, CraftedPayload
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
