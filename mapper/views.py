from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, FileResponse, HttpResponse
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils.html import escape
from django.db import connection
from django.db.models import Q
from urllib.parse import urlparse
import re
import secrets
from datetime import timedelta
from django.utils import timezone

from .models import (
    ValidationRule, SecureFileUpload, RedirectLog, LoginAttempt,
    SecureSessionToken, AccessLog, SanitizedUserData, PasswordPolicy,
    ErrorLog, DependencyAudit
)


def get_client_ip(request):
    """Extract client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_safe_url(url, allowed_hosts):
    """
    Validate redirect URL to prevent open redirect vulnerabilities.
    Security: Prevents header injection and open redirects.
    """
    if not url:
        return False
    
    # Remove any newline characters to prevent header injection
    url = url.replace('\n', '').replace('\r', '')
    
    parsed = urlparse(url)
    
    # Only allow relative URLs or URLs to whitelisted hosts
    if not parsed.netloc:
        # Relative URL
        return True
    
    return parsed.netloc in allowed_hosts


@csrf_protect
@require_http_methods(["GET", "POST"])
def secure_login(request):
    """
    Secure login view with protection against username enumeration and brute force.
    Security: Prevents username enumeration, rate limiting, secure error messages.
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Check for brute force attempts
        recent_attempts = LoginAttempt.objects.filter(
            Q(username=username) | Q(ip_address=ip_address),
            attempted_at__gte=timezone.now() - timedelta(minutes=15)
        ).count()
        
        if recent_attempts >= 5:
            # Log the attempt
            LoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                success=False,
                failure_reason='Rate limit exceeded',
                user_agent=user_agent
            )
            # Generic error message to prevent username enumeration
            return JsonResponse({
                'error': 'Invalid credentials. Please try again later.'
            }, status=429)
        
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Successful login
            auth_login(request, user)
            LoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                success=True,
                user_agent=user_agent
            )
            return JsonResponse({'success': True, 'redirect': '/'})
        else:
            # Failed login - use generic message to prevent username enumeration
            LoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                success=False,
                failure_reason='Invalid credentials',
                user_agent=user_agent
            )
            return JsonResponse({
                'error': 'Invalid credentials. Please try again.'
            }, status=401)
    
    return render(request, 'mapper/login.html')


@login_required
@csrf_protect
@require_http_methods(["POST"])
def secure_file_upload(request):
    """
    Secure file upload handler with path traversal prevention.
    Security: Validates file types, prevents path traversal, generates secure filenames.
    """
    if 'file' not in request.FILES:
        return JsonResponse({'error': 'No file provided'}, status=400)
    
    uploaded_file = request.FILES['file']
    
    # Validate file size (max 10MB)
    max_size = 10 * 1024 * 1024
    if uploaded_file.size > max_size:
        return JsonResponse({'error': 'File too large'}, status=400)
    
    # Validate file extension
    allowed_extensions = ['pdf', 'txt', 'jpg', 'png']
    file_ext = uploaded_file.name.split('.')[-1].lower()
    if file_ext not in allowed_extensions:
        return JsonResponse({'error': 'Invalid file type'}, status=400)
    
    try:
        # Create secure file upload record
        secure_file = SecureFileUpload(
            original_filename=uploaded_file.name,
            file=uploaded_file,
            content_type=uploaded_file.content_type,
            file_size=uploaded_file.size,
            uploaded_by=request.user
        )
        secure_file.save()
        
        return JsonResponse({
            'success': True,
            'file_id': str(secure_file.file_id)
        })
    except ValidationError as e:
        return JsonResponse({'error': str(e)}, status=400)


@login_required
@require_http_methods(["GET"])
def secure_file_download(request, file_id):
    """
    Secure file download with access control.
    Security: Validates file access, prevents path traversal, checks permissions.
    """
    try:
        secure_file = get_object_or_404(SecureFileUpload, file_id=file_id)
        
        # Check if user has permission to download
        if secure_file.uploaded_by != request.user and not request.user.is_staff:
            # Log access denial
            AccessLog.objects.create(
                user=request.user,
                resource_type='file',
                resource_id=str(file_id),
                action='view',
                granted=False,
                denial_reason='Insufficient permissions',
                ip_address=get_client_ip(request)
            )
            raise PermissionDenied("You don't have permission to download this file.")
        
        # Log successful access
        AccessLog.objects.create(
            user=request.user,
            resource_type='file',
            resource_id=str(file_id),
            action='view',
            granted=True,
            ip_address=get_client_ip(request)
        )
        
        # Return file with secure headers
        response = FileResponse(secure_file.file.open('rb'))
        response['Content-Type'] = secure_file.content_type
        # Prevent inline execution of scripts
        response['Content-Disposition'] = f'attachment; filename="{escape(secure_file.original_filename)}"'
        response['X-Content-Type-Options'] = 'nosniff'
        return response
        
    except SecureFileUpload.DoesNotExist:
        return JsonResponse({'error': 'File not found'}, status=404)


@csrf_protect
@require_http_methods(["GET"])
def secure_redirect(request):
    """
    Secure redirect handler preventing open redirect vulnerabilities.
    Security: Validates redirect URLs, prevents header injection.
    """
    redirect_url = request.GET.get('url', '')
    
    # Define allowed redirect hosts
    allowed_hosts = ['localhost', '127.0.0.1'] + list(request.get_host().split(','))
    
    # Log redirect attempt
    redirect_log = RedirectLog.objects.create(
        redirect_url=redirect_url,
        is_whitelisted=is_safe_url(redirect_url, allowed_hosts),
        requested_by=request.user if request.user.is_authenticated else None,
        requested_at=timezone.now(),
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    if is_safe_url(redirect_url, allowed_hosts):
        return redirect(redirect_url)
    else:
        # Redirect to safe default
        return redirect('/')


@login_required
@require_http_methods(["GET"])
def user_data_view(request):
    """
    Display user-supplied data with XSS prevention.
    Security: Properly escapes user data, uses Django's built-in XSS protection.
    """
    user_data = SanitizedUserData.objects.filter(user=request.user)
    
    # Django templates automatically escape data, but we sanitize at model level too
    return render(request, 'mapper/user_data.html', {
        'user_data': user_data
    })


@login_required
@require_http_methods(["POST"])
def submit_user_data(request):
    """
    Handle user-submitted data with proper sanitization.
    Security: Sanitizes input, prevents stored XSS.
    """
    field_name = request.POST.get('field_name', '')
    raw_value = request.POST.get('value', '')
    
    # Sanitize the value (Django's escape handles HTML entities)
    sanitized_value = escape(raw_value)
    
    # Save both raw and sanitized versions
    user_data = SanitizedUserData.objects.create(
        user=request.user,
        field_name=escape(field_name),
        raw_value=raw_value,
        sanitized_value=sanitized_value
    )
    
    return JsonResponse({
        'success': True,
        'id': user_data.id
    })


@login_required
@require_http_methods(["GET"])
def secure_query(request):
    """
    Demonstrate SQL injection prevention using Django ORM.
    Security: Uses parameterized queries, never concatenates user input into SQL.
    """
    search_term = request.GET.get('search', '')
    
    # SECURE: Using Django ORM with parameterized queries
    results = SecureFileUpload.objects.filter(
        original_filename__icontains=search_term
    ).values('original_filename', 'uploaded_at')
    
    # NEVER do this: f"SELECT * FROM files WHERE name = '{search_term}'"
    # That would be vulnerable to SQL injection
    
    return JsonResponse({
        'results': list(results)
    })


def validate_password_strength(password):
    """
    Validate password against security policy.
    Security: Enforces strong password requirements.
    """
    try:
        policy = PasswordPolicy.objects.filter(is_active=True).first()
        if not policy:
            policy = PasswordPolicy.objects.create()  # Use defaults
        
        errors = []
        
        if len(password) < policy.min_length:
            errors.append(f'Password must be at least {policy.min_length} characters long')
        
        if policy.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        
        if policy.require_lowercase and not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        
        if policy.require_digits and not re.search(r'\d', password):
            errors.append('Password must contain at least one digit')
        
        if policy.require_special_chars and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append('Password must contain at least one special character')
        
        return len(errors) == 0, errors
    
    except Exception as e:
        # Log error but don't expose details
        ErrorLog.objects.create(
            error_type='PasswordValidationError',
            error_message=str(e),
            user_message='An error occurred during password validation'
        )
        return False, ['An error occurred during password validation']


@csrf_protect
@require_http_methods(["POST"])
def validate_input(request):
    """
    Server-side validation that mirrors client-side validation.
    Security: Never trust client-side validation alone.
    """
    field_name = request.POST.get('field_name', '')
    field_value = request.POST.get('field_value', '')
    
    # Get validation rules for this field
    rules = ValidationRule.objects.filter(field_name=field_name, is_active=True)
    
    errors = []
    for rule in rules:
        if rule.rule_type == 'required' and not field_value:
            errors.append(rule.error_message)
        elif rule.rule_type == 'email' and field_value:
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, field_value):
                errors.append(rule.error_message)
        elif rule.rule_type == 'min_length' and len(field_value) < int(rule.rule_value):
            errors.append(rule.error_message)
        elif rule.rule_type == 'max_length' and len(field_value) > int(rule.rule_value):
            errors.append(rule.error_message)
        elif rule.rule_type == 'pattern' and not re.match(rule.rule_value, field_value):
            errors.append(rule.error_message)
    
    if errors:
        return JsonResponse({'valid': False, 'errors': errors}, status=400)
    
    return JsonResponse({'valid': True})


def mapper_home(request):
    """Home page for the Mapper app."""
    return render(request, 'mapper/home.html', {
        'title': 'Attack Surface Mapper',
        'description': 'Security-focused Django app demonstrating secure development practices'
    })
