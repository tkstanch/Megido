"""
Celery tasks for the Recon app.

Each task updates a ReconTask record's status, runs the appropriate service
function(s), persists results to the database, and records completion or
failure.
"""
import json
import logging

from celery import shared_task
from celery.exceptions import Terminated
from django.utils import timezone

logger = logging.getLogger(__name__)


def _mark_running(task_obj):
    """Set task status to running and record start time."""
    task_obj.status = 'running'
    task_obj.started_at = timezone.now()
    task_obj.save(update_fields=['status', 'started_at'])


def _mark_completed(task_obj, summary=''):
    """Set task status to completed."""
    task_obj.status = 'completed'
    task_obj.progress = 100
    task_obj.result_summary = summary
    task_obj.completed_at = timezone.now()
    task_obj.save(update_fields=['status', 'progress', 'result_summary', 'completed_at'])


def _mark_failed(task_obj, error_message=''):
    """Set task status to failed and record error message."""
    task_obj.status = 'failed'
    task_obj.error_message = str(error_message)[:2000]
    task_obj.completed_at = timezone.now()
    task_obj.save(update_fields=['status', 'error_message', 'completed_at'])


def _mark_cancelled(task_obj):
    """Set task status to cancelled."""
    task_obj.status = 'cancelled'
    task_obj.completed_at = timezone.now()
    task_obj.save(update_fields=['status', 'completed_at'])


def _create_task(project, task_type, target):
    """Helper – create a new ReconTask record for tracking task progress."""
    from .models import ReconTask
    return ReconTask.objects.create(
        project=project,
        task_type=task_type,
        target=target,
    )


@shared_task(bind=True)
def run_whois_lookup(self, project_id: int, domain: str):
    """
    Run a WHOIS lookup for *domain* and save results to WhoisResult.

    Args:
        project_id: Primary key of the ReconProject.
        domain: Domain to query.
    """
    from .models import ReconProject, ReconTask, WhoisResult

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='whois',
        target=domain,
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])
        _mark_running(task_obj)

    try:
        project = ReconProject.objects.get(pk=project_id)
        from .services.whois_service import perform_whois_lookup
        data = perform_whois_lookup(domain)
        WhoisResult.objects.create(
            project=project,
            domain=domain,
            raw_data=data.get('raw_data', ''),
            registrar=data.get('registrar', ''),
            registrant_name=data.get('registrant_name', ''),
            registrant_email=data.get('registrant_email', ''),
            registrant_org=data.get('registrant_org', ''),
            registrant_phone=data.get('registrant_phone', ''),
            registrant_address=data.get('registrant_address', ''),
            creation_date=data.get('creation_date', ''),
            expiration_date=data.get('expiration_date', ''),
            name_servers=data.get('name_servers', '[]'),
            status=data.get('status', ''),
            warning=data.get('warning', ''),
        )
        if task_obj:
            _mark_completed(task_obj, f"WHOIS lookup completed for {domain}")
        logger.info("WHOIS lookup complete for %s", domain)
    except Terminated:
        logger.info("WHOIS task for %s was cancelled by user.", domain)
        if task_obj:
            _mark_cancelled(task_obj)
        return
    except Exception as exc:
        logger.error("WHOIS task failed for %s: %s", domain, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise


@shared_task(bind=True)
def run_subdomain_enum(self, project_id: int, domain: str):
    """
    Run subdomain enumeration and save SubdomainResult records.

    Args:
        project_id: Primary key of the ReconProject.
        domain: Root domain to enumerate.
    """
    from .models import ReconProject, ReconTask, SubdomainResult

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='subdomain_enum',
        target=domain,
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])
        _mark_running(task_obj)

    try:
        project = ReconProject.objects.get(pk=project_id)
        from .services.subdomain_service import brute_force_subdomains, enumerate_from_certs

        results = brute_force_subdomains(domain)
        results += enumerate_from_certs(domain)

        saved = 0
        for r in results:
            _, created = SubdomainResult.objects.get_or_create(
                project=project,
                subdomain=r['subdomain'],
                defaults={
                    'ip_address': r.get('ip_address') or None,
                    'source': r.get('source', ''),
                    'is_alive': bool(r.get('ip_address')),
                },
            )
            if created:
                saved += 1

        if task_obj:
            _mark_completed(task_obj, f"Found {saved} new subdomains for {domain}")
        logger.info("Subdomain enum complete for %s: %d new", domain, saved)
    except Terminated:
        logger.info("Subdomain enum for %s was cancelled by user.", domain)
        if task_obj:
            _mark_cancelled(task_obj)
        return
    except Exception as exc:
        logger.error("Subdomain enum failed for %s: %s", domain, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise


@shared_task(bind=True)
def run_port_scan(self, project_id: int, host: str, api_key: str = None):
    """
    Run a passive port scan via Shodan and save ServicePort records.

    Args:
        project_id: Primary key of the ReconProject.
        host: Hostname or IP to scan.
        api_key: Optional Shodan API key override.
    """
    from .models import ReconProject, ReconTask, ServicePort

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='port_scan',
        target=host,
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])
        _mark_running(task_obj)

    try:
        project = ReconProject.objects.get(pk=project_id)
        from django.conf import settings
        from .services.port_service import active_scan_socket, passive_scan_shodan

        services = passive_scan_shodan(host, api_key)
        source = 'shodan'

        # Fall back to socket-based scan when Shodan is not configured or
        # returned no results (e.g. host not indexed yet).
        if not services:
            logger.info("Shodan unavailable for %s; using socket-based fallback", host)
            services = active_scan_socket(host)
            source = 'socket'

        saved = 0
        for s in services:
            _, created = ServicePort.objects.get_or_create(
                project=project,
                host=host,
                port=s.get('port', 0),
                protocol=s.get('protocol', 'tcp'),
                defaults={
                    'service_name': s.get('service_name', ''),
                    'service_version': s.get('service_version', ''),
                    'banner': s.get('banner', ''),
                    'source': source,
                },
            )
            if created:
                saved += 1

        if task_obj:
            _mark_completed(task_obj, f"Found {saved} new services for {host} (source: {source})")
        logger.info("Port scan complete for %s: %d services (source: %s)", host, saved, source)
    except Terminated:
        logger.info("Port scan for %s was cancelled by user.", host)
        if task_obj:
            _mark_cancelled(task_obj)
        return
    except Exception as exc:
        logger.error("Port scan failed for %s: %s", host, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise


@shared_task(bind=True)
def run_directory_bruteforce(self, project_id: int, target_url: str):
    """
    Run directory brute-forcing and save DirectoryFinding records.

    Args:
        project_id: Primary key of the ReconProject.
        target_url: Base URL to probe.
    """
    from .models import DirectoryFinding, ReconProject, ReconTask

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='directory_brute',
        target=target_url,
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])
        _mark_running(task_obj)

    try:
        project = ReconProject.objects.get(pk=project_id)
        from .services.directory_service import brute_force_directories

        findings = brute_force_directories(target_url)
        saved = 0
        for f in findings:
            DirectoryFinding.objects.create(
                project=project,
                target_url=target_url,
                path=f['path'],
                full_url=f.get('full_url', ''),
                status_code=f['status_code'],
                content_length=f.get('content_length'),
                content_type=f.get('content_type', ''),
                redirect_url=f.get('redirect_url', ''),
                is_interesting=f.get('is_interesting', False),
            )
            saved += 1

        if task_obj:
            _mark_completed(task_obj, f"Found {saved} paths at {target_url}")
        logger.info("Dir brute complete for %s: %d paths", target_url, saved)
    except Terminated:
        logger.info("Directory bruteforce for %s was cancelled by user.", target_url)
        if task_obj:
            _mark_cancelled(task_obj)
        return
    except Exception as exc:
        logger.error("Dir brute failed for %s: %s", target_url, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise


@shared_task(bind=True)
def run_bucket_discovery(self, project_id: int, keyword: str):
    """
    Run cloud bucket discovery and save BucketFinding records.

    Args:
        project_id: Primary key of the ReconProject.
        keyword: Seed keyword for generating bucket name variations.
    """
    from .models import BucketFinding, ReconProject, ReconTask

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='bucket_discovery',
        target=keyword,
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])
        _mark_running(task_obj)

    try:
        project = ReconProject.objects.get(pk=project_id)
        from .services.bucket_service import check_s3_bucket, generate_bucket_names

        bucket_names = generate_bucket_names(keyword)
        saved = 0
        for name in bucket_names:
            result = check_s3_bucket(name)
            if result.get('exists'):
                _, created = BucketFinding.objects.get_or_create(
                    project=project,
                    bucket_name=name,
                    provider='aws',
                    defaults={
                        'bucket_url': result.get('bucket_url', ''),
                        'is_public': result.get('is_public'),
                        'is_listable': result.get('is_listable', False),
                        'is_writable': result.get('is_writable', False),
                        'keywords': keyword,
                    },
                )
                if created:
                    saved += 1

        if task_obj:
            _mark_completed(task_obj, f"Found {saved} buckets for keyword '{keyword}'")
        logger.info("Bucket discovery complete for '%s': %d found", keyword, saved)
    except Terminated:
        logger.info("Bucket discovery for '%s' was cancelled by user.", keyword)
        if task_obj:
            _mark_cancelled(task_obj)
        return
    except Exception as exc:
        logger.error("Bucket discovery failed for '%s': %s", keyword, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise


@shared_task(bind=True)
def run_github_recon(self, project_id: int, org_name: str):
    """
    Run GitHub reconnaissance and save GitHubFinding records.

    Args:
        project_id: Primary key of the ReconProject.
        org_name: GitHub organisation or user name.
    """
    from .models import GitHubFinding, ReconProject, ReconTask

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='github_recon',
        target=org_name,
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])
        _mark_running(task_obj)

    # Keywords that make a repository interesting enough to record
    _INTERESTING_KEYWORDS = (
        'internal', 'private', 'staging', 'dev', 'secret', 'config',
        'credential', 'backup', 'infra', 'deploy', 'prod', 'password',
        'key', 'token', 'auth', 'admin',
    )

    def _repo_is_interesting(repo: dict) -> bool:
        """Return True when the repo name/description contains a sensitive keyword."""
        haystack = (
            repo.get('name', '') + ' ' + (repo.get('description', '') or '')
        ).lower()
        return any(kw in haystack for kw in _INTERESTING_KEYWORDS)

    try:
        project = ReconProject.objects.get(pk=project_id)
        from .services.github_service import search_github_repos, search_sensitive_data

        # --- 1. Repositories (filtered to interesting ones only) ---
        repos = search_github_repos(org_name)
        repo_saved = 0
        for repo in repos:
            if not _repo_is_interesting(repo):
                continue
            GitHubFinding.objects.get_or_create(
                project=project,
                finding_type='repo',
                url=repo.get('html_url', ''),
                defaults={
                    'repository': repo.get('full_name', ''),
                    'content': repo.get('description', ''),
                    'severity': 'info',
                },
            )
            repo_saved += 1

        # --- 2. Sensitive data / secrets ---
        sensitive = search_sensitive_data(org_name)
        secret_saved = 0
        for finding in sensitive:
            _, created = GitHubFinding.objects.get_or_create(
                project=project,
                url=finding.get('url', ''),
                defaults={
                    'finding_type': finding.get('finding_type', 'leak'),
                    'repository': finding.get('repository', ''),
                    'file_path': finding.get('file_path', ''),
                    'content': finding.get('pattern', ''),
                    'severity': finding.get('severity', 'medium'),
                },
            )
            if created:
                secret_saved += 1

        summary = (
            f"Found {repo_saved} interesting repos and "
            f"{secret_saved} sensitive findings for '{org_name}'"
        )
        if task_obj:
            _mark_completed(task_obj, summary)
        logger.info("GitHub recon complete for '%s': %s", org_name, summary)
    except Terminated:
        logger.info("GitHub recon for '%s' was cancelled by user.", org_name)
        if task_obj:
            _mark_cancelled(task_obj)
        return
    except Exception as exc:
        logger.error("GitHub recon failed for '%s': %s", org_name, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise


def _do_fingerprinting(project_id: int, target_url: str, task_obj=None) -> int:
    """
    Core fingerprinting logic – fetch *target_url*, persist findings, and
    update *task_obj* status.  Returns the number of saved findings.

    Extracted so it can be called both from the Celery task and as a
    synchronous fallback when the broker is unavailable.
    """
    from .models import ReconProject, TechFingerprint
    from .services.fingerprint_service import fingerprint_url

    if task_obj:
        _mark_running(task_obj)

    try:
        project = ReconProject.objects.get(pk=project_id)

        findings = fingerprint_url(target_url)
        saved = 0
        for f in findings:
            TechFingerprint.objects.create(
                project=project,
                target_url=target_url,
                technology=f.get('technology', ''),
                version=f.get('version', ''),
                category=f.get('category', ''),
                evidence=f.get('evidence', ''),
                confidence=f.get('confidence', 100),
            )
            saved += 1

        if task_obj:
            _mark_completed(task_obj, f"Identified {saved} technologies at {target_url}")
        logger.info("Fingerprinting complete for %s: %d techs", target_url, saved)
        return saved
    except Terminated:
        logger.info("Fingerprinting for %s was cancelled by user.", target_url)
        if task_obj:
            _mark_cancelled(task_obj)
        return 0
    except Exception as exc:
        logger.error("Fingerprinting failed for %s: %s", target_url, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise


@shared_task(bind=True)
def run_fingerprinting(self, project_id: int, target_url: str):
    """
    Run technology fingerprinting and save TechFingerprint records.

    Args:
        project_id: Primary key of the ReconProject.
        target_url: URL to fingerprint.
    """
    from .models import ReconTask

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='fingerprinting',
        target=target_url,
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])

    _do_fingerprinting(project_id, target_url, task_obj=task_obj)


@shared_task(bind=True)
def run_full_recon(self, project_id: int):
    """
    Orchestrate a full recon run for all in-scope targets of a project.

    Dispatches individual module tasks for each target in the project scope.

    Args:
        project_id: Primary key of the ReconProject.
    """
    from .models import ReconProject, ReconTask

    task_obj = ReconTask.objects.filter(
        project_id=project_id,
        task_type='full_recon',
        status='pending',
    ).first()

    if task_obj:
        task_obj.celery_task_id = self.request.id
        task_obj.save(update_fields=['celery_task_id'])
        _mark_running(task_obj)

    try:
        project = ReconProject.objects.get(pk=project_id)
        targets = list(project.targets.filter(is_in_scope=True))

        dispatched = 0
        for scope in targets:
            target = scope.target
            if scope.target_type in ('domain', 'subdomain', 'wildcard'):
                run_whois_lookup.delay(project_id, target)
                run_subdomain_enum.delay(project_id, target)
                dispatched += 2
            elif scope.target_type == 'ip':
                run_port_scan.delay(project_id, target)
                dispatched += 1

        if task_obj:
            _mark_completed(
                task_obj,
                f"Full recon dispatched {dispatched} subtasks across {len(targets)} targets",
            )
        logger.info("Full recon dispatched for project %d: %d tasks", project_id, dispatched)
    except Terminated:
        logger.info("Full recon for project %d was cancelled by user.", project_id)
        if task_obj:
            _mark_cancelled(task_obj)
        return
    except Exception as exc:
        logger.error("Full recon failed for project %d: %s", project_id, exc)
        if task_obj:
            _mark_failed(task_obj, exc)
        raise
