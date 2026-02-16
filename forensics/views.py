"""
Views for the Forensics app.

Handles file upload, analysis, and display of results.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator
from .models import ForensicFile
from .forms import ForensicFileUploadForm
from .utils.parse import analyze_file, extract_device_info


def dashboard(request):
    """
    Main dashboard view for forensics app.
    
    Displays upload form and list of recently analyzed files.
    
    Args:
        request: HttpRequest object
    
    Returns:
        HttpResponse with rendered dashboard template
    """
    # Get recent files
    recent_files = ForensicFile.objects.all()[:10]
    
    context = {
        'recent_files': recent_files,
    }
    
    return render(request, 'forensics/dashboard.html', context)


def upload_file(request):
    """
    Handle file upload and analysis.
    
    Accepts file upload via POST, performs basic analysis, and stores results.
    
    Args:
        request: HttpRequest object
    
    Returns:
        HttpResponse with rendered upload form or redirect to results
    """
    if request.method == 'POST':
        form = ForensicFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            # Save the file but don't commit yet
            forensic_file = form.save(commit=False)
            
            # Get the uploaded file
            uploaded_file = request.FILES['uploaded_file']
            forensic_file.original_filename = uploaded_file.name
            
            # Perform analysis
            try:
                analysis_results = analyze_file(uploaded_file, uploaded_file.name)
                device_info = extract_device_info(uploaded_file, uploaded_file.name)
                
                # Populate analysis fields
                forensic_file.sha256_hash = analysis_results['sha256_hash']
                forensic_file.md5_hash = analysis_results['md5_hash']
                forensic_file.file_size = analysis_results['file_size']
                forensic_file.file_type = analysis_results['file_type']
                forensic_file.mime_type = analysis_results['mime_type']
                forensic_file.hex_sample = analysis_results['hex_sample']
                
                # Populate device info (if available)
                forensic_file.device_model = device_info.get('device_model')
                forensic_file.os_version = device_info.get('os_version')
                forensic_file.serial_number = device_info.get('serial_number')
                
                # Save to database
                forensic_file.save()
                
                messages.success(request, f'File "{uploaded_file.name}" uploaded and analyzed successfully!')
                return redirect('forensics:file_detail', pk=forensic_file.pk)
                
            except Exception as e:
                messages.error(request, f'Error analyzing file: {str(e)}')
                return redirect('forensics:upload')
    else:
        form = ForensicFileUploadForm()
    
    context = {
        'form': form,
    }
    
    return render(request, 'forensics/upload.html', context)


def file_detail(request, pk):
    """
    Display detailed analysis results for a specific file.
    
    Args:
        request: HttpRequest object
        pk: Primary key of ForensicFile
    
    Returns:
        HttpResponse with rendered detail template
    """
    forensic_file = get_object_or_404(ForensicFile, pk=pk)
    
    # Split hex sample into lines of 16 bytes (32 hex chars + spaces)
    hex_sample = forensic_file.hex_sample
    hex_lines = []
    if hex_sample:
        hex_bytes = hex_sample.split()
        for i in range(0, len(hex_bytes), 16):
            line_bytes = hex_bytes[i:i+16]
            hex_part = ' '.join(line_bytes)
            # Create ASCII representation
            ascii_part = ''.join(
                chr(int(b, 16)) if 32 <= int(b, 16) < 127 else '.'
                for b in line_bytes
            )
            hex_lines.append({
                'offset': f'{i:08x}',
                'hex': hex_part,
                'ascii': ascii_part,
            })
    
    context = {
        'file': forensic_file,
        'hex_lines': hex_lines,
    }
    
    return render(request, 'forensics/detail.html', context)


def file_list(request):
    """
    Display paginated list of all analyzed files.
    
    Args:
        request: HttpRequest object
    
    Returns:
        HttpResponse with rendered list template
    """
    files = ForensicFile.objects.all()
    paginator = Paginator(files, 20)  # Show 20 files per page
    
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }
    
    return render(request, 'forensics/list.html', context)
