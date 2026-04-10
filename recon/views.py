"""
Views for the Recon app.

Provides a dashboard for managing ReconProject objects and individual
module views for triggering and displaying recon results.
"""
import json
import logging

from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from .models import (
    BucketFinding,
    CertificateDiscovery,
    DirectoryFinding,
    GitHubFinding,
    IPDiscovery,
    ReconProject,
    ReconTask,
    ScopeTarget,
    ServicePort,
    SubdomainResult,
    TechFingerprint,
    WhoisResult,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@require_http_methods(['GET'])
def dashboard(request):
    """Display all ReconProject objects with summary statistics."""
    projects = ReconProject.objects.filter(is_active=True).prefetch_related('tasks')
    context = {'projects': projects}
    return render(request, 'recon/dashboard.html', context)


# ---------------------------------------------------------------------------
# Project management
# ---------------------------------------------------------------------------

@require_http_methods(['GET', 'POST'])
def create_project(request):
    """Form to create a new ReconProject."""
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        if not name:
            messages.error(request, 'Project name is required.')
            return render(request, 'recon/create_project.html')
        project = ReconProject.objects.create(
            name=name,
            description=description,
            user=request.user if request.user.is_authenticated else None,
        )
        messages.success(request, f'Project "{project.name}" created.')
        return redirect('recon:project_detail', project_id=project.pk)
    return render(request, 'recon/create_project.html')


@require_http_methods(['GET', 'POST'])
def project_detail(request, project_id):
    """Project overview: scope targets, module links, task history."""
    project = get_object_or_404(ReconProject, pk=project_id)

    if request.method == 'POST':
        target = request.POST.get('target', '').strip()
        target_type = request.POST.get('target_type', 'domain')
        if target:
            ScopeTarget.objects.get_or_create(
                project=project,
                target=target,
                defaults={'target_type': target_type},
            )
            messages.success(request, f'Target "{target}" added.')
        return redirect('recon:project_detail', project_id=project.pk)

    tasks = project.tasks.order_by('-created_at')[:20]
    targets = project.targets.all()
    context = {
        'project': project,
        'tasks': tasks,
        'targets': targets,
        'target_type_choices': ScopeTarget.TARGET_TYPE_CHOICES,
    }
    return render(request, 'recon/project_detail.html', context)


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

@require_http_methods(['POST'])
def whois_lookup(request, project_id):
    """Trigger a WHOIS lookup for the supplied domain."""
    project = get_object_or_404(ReconProject, pk=project_id)
    domain = request.POST.get('domain', '').strip()
    if not domain:
        messages.error(request, 'Please supply a domain.')
        return redirect('recon:whois_results', project_id=project.pk)

    task = ReconTask.objects.create(
        project=project,
        task_type='whois',
        target=domain,
    )
    try:
        from .tasks import run_whois_lookup
        result = run_whois_lookup.delay(project.pk, domain)
        task.celery_task_id = result.id
        task.save(update_fields=['celery_task_id'])
        messages.success(request, f'WHOIS lookup started for {domain}.')
    except Exception as exc:
        logger.error("Failed to queue WHOIS task: %s", exc)
        messages.warning(
            request,
            f'WHOIS lookup queued (task runner may be offline): {exc}',
        )
    return redirect('recon:whois_results', project_id=project.pk)


@require_http_methods(['GET', 'POST'])
def whois_results(request, project_id):
    """Display WhoisResult records for the project."""
    project = get_object_or_404(ReconProject, pk=project_id)
    if request.method == 'POST':
        return whois_lookup(request, project_id)
    results = project.whois_results.all()
    failed_tasks = project.tasks.filter(task_type='whois', status='failed').order_by('-completed_at')[:5]
    context = {'project': project, 'results': results, 'failed_tasks': failed_tasks}
    return render(request, 'recon/whois_results.html', context)


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------

@require_http_methods(['POST'])
def subdomain_enum(request, project_id):
    """Start subdomain enumeration for the supplied domain."""
    project = get_object_or_404(ReconProject, pk=project_id)
    domain = request.POST.get('domain', '').strip()
    if not domain:
        messages.error(request, 'Please supply a domain.')
        return redirect('recon:subdomain_results', project_id=project.pk)

    task = ReconTask.objects.create(
        project=project,
        task_type='subdomain_enum',
        target=domain,
    )
    try:
        from .tasks import run_subdomain_enum
        result = run_subdomain_enum.delay(project.pk, domain)
        task.celery_task_id = result.id
        task.save(update_fields=['celery_task_id'])
        messages.success(request, f'Subdomain enumeration started for {domain}.')
    except Exception as exc:
        logger.error("Failed to queue subdomain task: %s", exc)
        messages.warning(request, f'Task queued (runner may be offline): {exc}')
    return redirect('recon:subdomain_results', project_id=project.pk)


@require_http_methods(['GET', 'POST'])
def subdomain_results(request, project_id):
    """Display SubdomainResult records for the project."""
    project = get_object_or_404(ReconProject, pk=project_id)
    if request.method == 'POST':
        return subdomain_enum(request, project_id)
    results = project.subdomains.all()
    failed_tasks = project.tasks.filter(task_type='subdomain_enum', status='failed').order_by('-completed_at')[:5]
    context = {'project': project, 'results': results, 'failed_tasks': failed_tasks}
    return render(request, 'recon/subdomains.html', context)


# ---------------------------------------------------------------------------
# Services / ports
# ---------------------------------------------------------------------------

@require_http_methods(['POST'])
def service_scan(request, project_id):
    """Start a port scan for the supplied host."""
    project = get_object_or_404(ReconProject, pk=project_id)
    host = request.POST.get('host', '').strip()
    if not host:
        messages.error(request, 'Please supply a host.')
        return redirect('recon:service_results', project_id=project.pk)

    task = ReconTask.objects.create(
        project=project,
        task_type='port_scan',
        target=host,
    )
    try:
        from .tasks import run_port_scan
        result = run_port_scan.delay(project.pk, host)
        task.celery_task_id = result.id
        task.save(update_fields=['celery_task_id'])
        messages.success(request, f'Port scan started for {host}.')
    except Exception as exc:
        logger.error("Failed to queue port scan task: %s", exc)
        messages.warning(request, f'Task queued (runner may be offline): {exc}')
    return redirect('recon:service_results', project_id=project.pk)


@require_http_methods(['GET', 'POST'])
def service_results(request, project_id):
    """Display ServicePort records for the project."""
    project = get_object_or_404(ReconProject, pk=project_id)
    if request.method == 'POST':
        return service_scan(request, project_id)
    results = project.services.all()
    failed_tasks = project.tasks.filter(task_type='port_scan', status='failed').order_by('-completed_at')[:5]
    context = {'project': project, 'results': results, 'failed_tasks': failed_tasks}
    return render(request, 'recon/services.html', context)


# ---------------------------------------------------------------------------
# Directory brute-force
# ---------------------------------------------------------------------------

@require_http_methods(['POST'])
def directory_bruteforce(request, project_id):
    """Start directory brute-force for the supplied URL."""
    project = get_object_or_404(ReconProject, pk=project_id)
    target_url = request.POST.get('target_url', '').strip()
    if not target_url:
        messages.error(request, 'Please supply a target URL.')
        return redirect('recon:directory_results', project_id=project.pk)

    task = ReconTask.objects.create(
        project=project,
        task_type='directory_brute',
        target=target_url,
    )
    try:
        from .tasks import run_directory_bruteforce
        result = run_directory_bruteforce.delay(project.pk, target_url)
        task.celery_task_id = result.id
        task.save(update_fields=['celery_task_id'])
        messages.success(request, f'Directory brute-force started for {target_url}.')
    except Exception as exc:
        logger.error("Failed to queue directory task: %s", exc)
        messages.warning(request, f'Task queued (runner may be offline): {exc}')
    return redirect('recon:directory_results', project_id=project.pk)


@require_http_methods(['GET', 'POST'])
def directory_results(request, project_id):
    """Display DirectoryFinding records for the project."""
    project = get_object_or_404(ReconProject, pk=project_id)
    if request.method == 'POST':
        return directory_bruteforce(request, project_id)
    results = project.directories.all()
    failed_tasks = project.tasks.filter(task_type='directory_brute', status='failed').order_by('-completed_at')[:5]
    context = {'project': project, 'results': results, 'failed_tasks': failed_tasks}
    return render(request, 'recon/directories.html', context)


# ---------------------------------------------------------------------------
# Bucket discovery
# ---------------------------------------------------------------------------

@require_http_methods(['POST'])
def bucket_discovery(request, project_id):
    """Start bucket discovery for the supplied keyword."""
    project = get_object_or_404(ReconProject, pk=project_id)
    keyword = request.POST.get('keyword', '').strip()
    if not keyword:
        messages.error(request, 'Please supply a keyword.')
        return redirect('recon:bucket_results', project_id=project.pk)

    task = ReconTask.objects.create(
        project=project,
        task_type='bucket_discovery',
        target=keyword,
    )
    try:
        from .tasks import run_bucket_discovery
        result = run_bucket_discovery.delay(project.pk, keyword)
        task.celery_task_id = result.id
        task.save(update_fields=['celery_task_id'])
        messages.success(request, f'Bucket discovery started for "{keyword}".')
    except Exception as exc:
        logger.error("Failed to queue bucket task: %s", exc)
        messages.warning(request, f'Task queued (runner may be offline): {exc}')
    return redirect('recon:bucket_results', project_id=project.pk)


@require_http_methods(['GET', 'POST'])
def bucket_results(request, project_id):
    """Display BucketFinding records for the project."""
    project = get_object_or_404(ReconProject, pk=project_id)
    if request.method == 'POST':
        return bucket_discovery(request, project_id)
    results = project.buckets.all()
    failed_tasks = project.tasks.filter(task_type='bucket_discovery', status='failed').order_by('-completed_at')[:5]
    context = {'project': project, 'results': results, 'failed_tasks': failed_tasks}
    return render(request, 'recon/buckets.html', context)


# ---------------------------------------------------------------------------
# GitHub recon
# ---------------------------------------------------------------------------

@require_http_methods(['POST'])
def github_recon(request, project_id):
    """Start GitHub reconnaissance for the supplied organisation."""
    project = get_object_or_404(ReconProject, pk=project_id)
    org_name = request.POST.get('org_name', '').strip()
    if not org_name:
        messages.error(request, 'Please supply a GitHub organisation name.')
        return redirect('recon:github_results', project_id=project.pk)

    task = ReconTask.objects.create(
        project=project,
        task_type='github_recon',
        target=org_name,
    )
    try:
        from .tasks import run_github_recon
        result = run_github_recon.delay(project.pk, org_name)
        task.celery_task_id = result.id
        task.save(update_fields=['celery_task_id'])
        messages.success(request, f'GitHub recon started for "{org_name}".')
    except Exception as exc:
        logger.error("Failed to queue GitHub task: %s", exc)
        messages.warning(request, f'Task queued (runner may be offline): {exc}')
    return redirect('recon:github_results', project_id=project.pk)


@require_http_methods(['GET', 'POST'])
def github_results(request, project_id):
    """Display GitHubFinding records for the project."""
    project = get_object_or_404(ReconProject, pk=project_id)
    if request.method == 'POST':
        return github_recon(request, project_id)
    results = project.github_findings.all()
    failed_tasks = project.tasks.filter(task_type='github_recon', status='failed').order_by('-completed_at')[:5]
    context = {'project': project, 'results': results, 'failed_tasks': failed_tasks}
    return render(request, 'recon/github_recon.html', context)


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

@require_http_methods(['POST'])
def fingerprint_scan(request, project_id):
    """Start tech-stack fingerprinting for the supplied URL."""
    project = get_object_or_404(ReconProject, pk=project_id)
    target_url = request.POST.get('target_url', '').strip()
    if not target_url:
        messages.error(request, 'Please supply a target URL.')
        return redirect('recon:fingerprint_results', project_id=project.pk)

    task = ReconTask.objects.create(
        project=project,
        task_type='fingerprinting',
        target=target_url,
    )
    try:
        from .tasks import run_fingerprinting
        result = run_fingerprinting.delay(project.pk, target_url)
        task.celery_task_id = result.id
        task.save(update_fields=['celery_task_id'])
        messages.success(request, f'Fingerprinting started for {target_url}.')
    except Exception as exc:
        logger.error("Failed to queue fingerprint task: %s", exc)
        messages.warning(request, f'Task queued (runner may be offline): {exc}')
    return redirect('recon:fingerprint_results', project_id=project.pk)


@require_http_methods(['GET', 'POST'])
def fingerprint_results(request, project_id):
    """Display TechFingerprint records for the project."""
    project = get_object_or_404(ReconProject, pk=project_id)
    if request.method == 'POST':
        return fingerprint_scan(request, project_id)
    results = project.tech_fingerprints.all()
    failed_tasks = project.tasks.filter(task_type='fingerprinting', status='failed').order_by('-completed_at')[:5]
    context = {'project': project, 'results': results, 'failed_tasks': failed_tasks}
    return render(request, 'recon/fingerprint.html', context)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@require_http_methods(['GET'])
def generate_report(request, project_id):
    """Generate a full recon report aggregating all findings."""
    project = get_object_or_404(ReconProject, pk=project_id)
    context = {
        'project': project,
        'whois_results': project.whois_results.all(),
        'subdomains': project.subdomains.all(),
        'services': project.services.filter(is_open=True),
        'directories': project.directories.all(),
        'buckets': project.buckets.all(),
        'github_findings': project.github_findings.all(),
        'tech_fingerprints': project.tech_fingerprints.all(),
        'certificates': project.certificates.all(),
        'ip_discoveries': project.ip_discoveries.all(),
        'tasks': project.tasks.all(),
    }
    return render(request, 'recon/report.html', context)


# ---------------------------------------------------------------------------
# Task status API
# ---------------------------------------------------------------------------

@require_http_methods(['GET'])
def task_status_api(request, task_id):
    """JSON endpoint returning the current status of a ReconTask."""
    task = get_object_or_404(ReconTask, pk=task_id)
    return JsonResponse({
        'id': task.pk,
        'task_type': task.task_type,
        'status': task.status,
        'progress': task.progress,
        'target': task.target,
        'result_summary': task.result_summary,
        'error_message': task.error_message,
        'created_at': task.created_at.isoformat(),
        'started_at': task.started_at.isoformat() if task.started_at else None,
        'completed_at': task.completed_at.isoformat() if task.completed_at else None,
    })
