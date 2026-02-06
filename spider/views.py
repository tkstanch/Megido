from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
from .models import (
    SpiderTarget, SpiderSession, DiscoveredURL,
    HiddenContent, BruteForceAttempt, InferredContent,
    ToolScanResult, ParameterDiscoveryAttempt,
    DiscoveredParameter, ParameterBruteForce
)
from .stealth import create_stealth_session
import requests
from requests.exceptions import Timeout, ConnectionError, RequestException, SSLError
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import re
import os
import json
from collections import deque
import time
import logging

# Configure logger for spider module
logger = logging.getLogger(__name__)


def make_request_with_retry(stealth_session, url, max_retries=3, timeout=30, method='GET', **kwargs):
    """
    Make HTTP request with retry logic and exponential backoff
    
    Args:
        stealth_session: StealthSession instance
        url: URL to request
        max_retries: Maximum retry attempts
        timeout: Request timeout in seconds
        method: HTTP method (GET, POST, OPTIONS, TRACE, etc.)
        **kwargs: Additional arguments for requests
    
    Returns:
        Response object or None if all retries failed
    """
    logger.debug(f"Making {method} request to {url} (max_retries={max_retries}, timeout={timeout})")
    
    for attempt in range(max_retries + 1):
        try:
            if method.upper() == 'GET':
                response = stealth_session.get(url, timeout=timeout, **kwargs)
            elif method.upper() == 'POST':
                response = stealth_session.post(url, timeout=timeout, **kwargs)
            elif method.upper() == 'OPTIONS':
                response = stealth_session.options(url, timeout=timeout, **kwargs)
            else:
                # For other methods (TRACE, PUT, DELETE, etc.)
                response = stealth_session.request(method, url, timeout=timeout, **kwargs)
            
            logger.debug(f"Request successful: {url} - Status: {response.status_code}")
            return response
            
        except SSLError as e:
            # SSL/TLS errors - typically not recoverable
            error_msg = f"SSL error for {url}: {str(e)}"
            logger.error(error_msg)
            return None
            
        except Timeout as e:
            error_type = "timeout_error"
            if attempt < max_retries:
                # Exponential backoff: 1s, 2s, 4s
                backoff_delay = 2 ** attempt
                logger.warning(f"Request timeout (attempt {attempt + 1}/{max_retries + 1}), retrying in {backoff_delay}s: {url} - {e}")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Request timed out after {max_retries + 1} attempts: {url} - {e}")
                return None
                
        except ConnectionError as e:
            error_type = "connection_error"
            if attempt < max_retries:
                # Exponential backoff: 1s, 2s, 4s
                backoff_delay = 2 ** attempt
                logger.warning(f"Connection error (attempt {attempt + 1}/{max_retries + 1}), retrying in {backoff_delay}s: {url} - {e}")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Connection failed after {max_retries + 1} attempts: {url} - {e}")
                return None
                
        except RequestException as e:
            # Non-recoverable error, don't retry
            error_msg = f"Non-recoverable request error for {url}: {str(e)}"
            logger.error(error_msg)
            return None
    
    return None


def index(request):
    """Spider dashboard view"""
    return render(request, 'spider/dashboard.html')


@api_view(['GET', 'POST'])
def spider_targets(request):
    """List or create spider targets"""
    if request.method == 'GET':
        targets = SpiderTarget.objects.all()[:50]
        data = [{
            'id': target.id,
            'name': target.name,
            'url': target.url,
            'max_depth': target.max_depth,
            'use_dirbuster': target.use_dirbuster,
            'use_nikto': target.use_nikto,
            'use_wikto': target.use_wikto,
            'enable_brute_force': target.enable_brute_force,
            'enable_inference': target.enable_inference,
            'enable_parameter_discovery': target.enable_parameter_discovery,
            'enable_stealth_mode': target.enable_stealth_mode,
            'use_random_user_agents': target.use_random_user_agents,
            'stealth_delay_min': target.stealth_delay_min,
            'stealth_delay_max': target.stealth_delay_max,
            'request_timeout': target.request_timeout,
            'max_retries': target.max_retries,
            'created_at': target.created_at.isoformat(),
        } for target in targets]
        return Response(data)
    
    elif request.method == 'POST':
        url = request.data.get('url')
        if not url:
            return Response({'error': 'URL is required'}, status=400)
        
        target, created = SpiderTarget.objects.get_or_create(
            url=url,
            defaults={
                'name': request.data.get('name', ''),
                'description': request.data.get('description', ''),
                'max_depth': request.data.get('max_depth', 3),
                'follow_external_links': request.data.get('follow_external_links', False),
                'use_dirbuster': request.data.get('use_dirbuster', True),
                'use_nikto': request.data.get('use_nikto', True),
                'use_wikto': request.data.get('use_wikto', True),
                'enable_brute_force': request.data.get('enable_brute_force', True),
                'enable_inference': request.data.get('enable_inference', True),
                'enable_parameter_discovery': request.data.get('enable_parameter_discovery', True),
                'enable_stealth_mode': request.data.get('enable_stealth_mode', True),
                'use_random_user_agents': request.data.get('use_random_user_agents', True),
                'stealth_delay_min': request.data.get('stealth_delay_min', 1.0),
                'stealth_delay_max': request.data.get('stealth_delay_max', 3.0),
                'request_timeout': request.data.get('request_timeout', 30),
                'max_retries': request.data.get('max_retries', 3),
            }
        )
        
        if created:
            return Response({
                'id': target.id,
                'message': 'Target created',
                'created': True
            }, status=201)
        else:
            return Response({
                'id': target.id,
                'message': 'Target with this URL already exists',
                'created': False
            }, status=200)


@api_view(['POST'])
def start_spider(request, target_id):
    """Start a spider session on a target"""
    logger.info(f"Starting spider session for target_id={target_id}")
    
    try:
        target = SpiderTarget.objects.get(id=target_id)
        session = SpiderSession.objects.create(target=target, status='running')
        logger.info(f"Created spider session {session.id} for target {target.url}")
        
        try:
            # Run comprehensive spidering
            run_spider_session(session, target)
            
            session.status = 'completed'
            session.completed_at = timezone.now()
            session.save()
            
            logger.info(f"Spider session {session.id} completed successfully. "
                       f"URLs discovered: {session.urls_discovered}, "
                       f"Hidden content: {session.hidden_content_found}")
            
            return Response({
                'id': session.id,
                'message': 'Spider session completed',
                'urls_discovered': session.urls_discovered,
                'hidden_content_found': session.hidden_content_found,
            })
            
        except Exception as e:
            # Categorize error type
            error_category = "unknown_error"
            error_message = str(e)
            
            if "SSL" in error_message or "ssl" in error_message.lower():
                error_category = "ssl_error"
            elif "Connection" in error_message or "connection" in error_message.lower():
                error_category = "connection_error"
            elif "timeout" in error_message.lower():
                error_category = "timeout_error"
            elif "database" in error_message.lower() or "integrity" in error_message.lower():
                error_category = "database_error"
            
            logger.error(f"Spider session {session.id} failed with {error_category}: {error_message}", 
                        exc_info=True)
            
            # Update session with detailed error information
            session.status = 'failed'
            session.error_message = f"[{error_category}] {error_message}"
            session.completed_at = timezone.now()
            
            try:
                session.save()
            except Exception as save_error:
                logger.error(f"Failed to save error status for session {session.id}: {save_error}")
            
            # Return structured error response
            return Response({
                'error': error_message,
                'error_category': error_category,
                'session_id': session.id,
                'message': 'Spider session failed. Check error_message for details.'
            }, status=500)
            
    except SpiderTarget.DoesNotExist:
        logger.warning(f"Target with id={target_id} not found")
        return Response({'error': 'Target not found'}, status=404)
    except Exception as e:
        logger.error(f"Unexpected error starting spider for target_id={target_id}: {e}", exc_info=True)
        return Response({
            'error': str(e),
            'error_category': 'unexpected_error',
            'message': 'An unexpected error occurred'
        }, status=500)


def run_spider_session(session, target):
    """Main spider logic - orchestrates all discovery methods"""
    logger.info(f"Running spider session {session.id} for target {target.url}")
    verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
    
    # Create stealth session
    stealth_session = create_stealth_session(target, verify_ssl)
    logger.debug(f"Created stealth session for {target.url} (SSL verification: {verify_ssl})")
    
    try:
        # Phase 1: Web Crawling
        logger.info(f"Phase 1: Starting web crawling for session {session.id}")
        crawl_website(session, target, stealth_session)
        
        # Phase 2: DirBuster-style directory discovery
        if target.use_dirbuster:
            logger.info(f"Phase 2: Starting DirBuster discovery for session {session.id}")
            run_dirbuster_discovery(session, target, stealth_session)
        
        # Phase 3: Nikto scanning
        if target.use_nikto:
            logger.info(f"Phase 3: Starting Nikto scan for session {session.id}")
            run_nikto_scan(session, target, stealth_session)
        
        # Phase 4: Wikto scanning
        if target.use_wikto:
            logger.info(f"Phase 4: Starting Wikto scan for session {session.id}")
            run_wikto_scan(session, target, stealth_session)
        
        # Phase 5: Brute force hidden content
        if target.enable_brute_force:
            logger.info(f"Phase 5: Starting brute force for session {session.id}")
            brute_force_paths(session, target, stealth_session)
        
        # Phase 6: Content inference
        if target.enable_inference:
            logger.info(f"Phase 6: Starting content inference for session {session.id}")
            infer_content(session, target, stealth_session)
        
        # Phase 7: Hidden parameter discovery
        if target.enable_parameter_discovery:
            logger.info(f"Phase 7: Starting parameter discovery for session {session.id}")
            discover_hidden_parameters(session, target, stealth_session)
        
        # Update session statistics
        session.urls_discovered = session.discovered_urls.count()
        session.hidden_content_found = session.hidden_content.count()
        session.inference_results = session.inferred_content.count()
        session.parameters_discovered = session.discovered_parameters.count()
        session.save()
        
        logger.info(f"Spider session {session.id} phases completed successfully")
        
    finally:
        # Always close stealth session, even if exceptions occur
        try:
            logger.debug(f"Closing stealth session for session {session.id}")
            stealth_session.close()
            logger.debug(f"Stealth session closed successfully for session {session.id}")
        except Exception as close_error:
            # Log but don't raise - cleanup errors shouldn't fail the request
            logger.warning(f"Error closing stealth session for session {session.id}: {close_error}")


def crawl_website(session, target, stealth_session):
    """Crawl website starting from target URL"""
    logger.info(f"Starting crawl for session {session.id}, target: {target.url}, max_depth: {target.max_depth}")
    visited = set()
    to_visit = deque([(target.url, 0)])  # (url, depth)
    base_domain = urlparse(target.url).netloc
    
    urls_processed = 0
    urls_failed = 0
    
    while to_visit and len(visited) < 500:  # Limit to 500 URLs
        current_url, depth = to_visit.popleft()
        
        if current_url in visited or depth > target.max_depth:
            continue
        
        visited.add(current_url)
        urls_processed += 1
        
        try:
            response = make_request_with_retry(
                stealth_session, 
                current_url, 
                max_retries=target.max_retries,
                timeout=target.request_timeout,
                allow_redirects=True
            )
            
            if response is None:
                # Request failed after all retries
                urls_failed += 1
                logger.debug(f"Failed to crawl {current_url} after retries")
                continue
            
            # Record discovered URL
            discovered, created = DiscoveredURL.objects.get_or_create(
                session=session,
                url=current_url,
                defaults={
                    'discovery_method': 'crawl',
                    'depth': depth,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds(),
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                }
            )
            
            # Parse HTML and find links
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Get page title
                if created and soup.title:
                    discovered.title = soup.title.string[:500] if soup.title.string else ''
                    discovered.save()
                
                # Extract all links
                for link in soup.find_all(['a', 'link'], href=True):
                    href = link['href']
                    absolute_url = urljoin(current_url, href)
                    parsed = urlparse(absolute_url)
                    
                    # Check if we should follow this link
                    if not target.follow_external_links and parsed.netloc != base_domain:
                        continue
                    
                    # Clean URL (remove fragments)
                    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
                    
                    if clean_url not in visited and clean_url.startswith(('http://', 'https://')):
                        to_visit.append((clean_url, depth + 1))
                
                # Look for forms, scripts, images that might reveal hidden content
                for tag in soup.find_all(['form', 'script', 'img', 'iframe']):
                    for attr in ['action', 'src', 'data-src']:
                        if tag.get(attr):
                            absolute_url = urljoin(current_url, tag[attr])
                            if absolute_url not in visited:
                                to_visit.append((absolute_url, depth + 1))
        
        except Exception as e:
            urls_failed += 1
            logger.warning(f"Error crawling {current_url}: {e}")
            continue
    
    session.urls_crawled = len(visited)
    session.save()
    
    logger.info(f"Crawl complete for session {session.id}: "
               f"{urls_processed} URLs processed, {urls_failed} failed, {len(visited)} visited")


def run_dirbuster_discovery(session, target, stealth_session):
    """Simulate DirBuster-style directory/file discovery"""
    logger.info(f"Starting DirBuster discovery for session {session.id}")
    tool_result = ToolScanResult.objects.create(
        session=session,
        tool_name='dirbuster',
        status='running'
    )
    
    # Common directories and files to check
    common_paths = [
        # Directories
        'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
        'backup', 'backups', 'old', 'test', 'temp', 'tmp',
        'uploads', 'images', 'files', 'download', 'downloads',
        'api', 'rest', 'v1', 'v2', 'graphql',
        'config', 'conf', 'configuration',
        'includes', 'inc', 'lib', 'libs', 'vendor',
        'static', 'assets', 'css', 'js', 'scripts',
        'cgi-bin', 'bin', 'src', 'source',
        # Common files
        'robots.txt', 'sitemap.xml', 'security.txt', '.well-known',
        'readme', 'README', 'README.md', 'README.txt',
        'changelog', 'CHANGELOG', 'CHANGELOG.md',
        'license', 'LICENSE', 'LICENSE.txt',
        '.git', '.svn', '.env', '.htaccess', 'web.config',
        'package.json', 'composer.json', 'Gemfile',
        'phpinfo.php', 'info.php', 'test.php',
        'backup.sql', 'backup.zip', 'backup.tar.gz',
        'config.php', 'settings.php', 'database.php',
        'wp-config.php', 'configuration.php',
    ]
    
    findings = []
    failed_requests = 0
    parsed_url = urlparse(target.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for path in common_paths:
        test_url = f"{base_url}/{path}"
        
        try:
            response = make_request_with_retry(
                stealth_session, 
                test_url, 
                max_retries=target.max_retries,
                timeout=target.request_timeout,
                allow_redirects=False
            )
            
            if response is None:
                # Request failed after all retries
                failed_requests += 1
                continue
            
            # Record if found (200-399 status codes)
            if 200 <= response.status_code < 400:
                DiscoveredURL.objects.get_or_create(
                    session=session,
                    url=test_url,
                    defaults={
                        'discovery_method': 'dirbuster',
                        'status_code': response.status_code,
                        'response_time': response.elapsed.total_seconds(),
                        'content_type': response.headers.get('Content-Type', ''),
                        'is_hidden': True,
                        'is_interesting': True,
                    }
                )
                
                # Determine content type
                content_type = 'other'
                if path.endswith(('.sql', '.zip', '.tar.gz', '.bak')):
                    content_type = 'backup'
                elif 'config' in path.lower() or path in ['.env', 'web.config', '.htaccess']:
                    content_type = 'config'
                elif 'admin' in path.lower():
                    content_type = 'admin_panel'
                elif path in ['test.php', 'phpinfo.php', 'info.php']:
                    content_type = 'test_file'
                elif response.status_code == 301 or not path.split('.')[-1] in ['php', 'html', 'txt']:
                    content_type = 'directory'
                else:
                    content_type = 'file'
                
                # Determine risk level
                risk_level = 'info'
                if content_type in ['backup', 'config', 'test_file']:
                    risk_level = 'high'
                elif content_type == 'admin_panel':
                    risk_level = 'medium'
                
                HiddenContent.objects.create(
                    session=session,
                    url=test_url,
                    content_type=content_type,
                    discovery_method='dirbuster',
                    status_code=response.status_code,
                    risk_level=risk_level,
                    content_sample=response.text[:500] if response.text else ''
                )
                
                findings.append({'url': test_url, 'status': response.status_code})
                logger.debug(f"DirBuster found: {test_url} (status: {response.status_code})")
        
        except Exception as e:
            failed_requests += 1
            logger.debug(f"DirBuster error testing {test_url}: {e}")
            continue
    
    tool_result.status = 'completed'
    tool_result.completed_at = timezone.now()
    tool_result.findings_count = len(findings)
    tool_result.parsed_results = findings
    tool_result.save()
    
    logger.info(f"DirBuster discovery complete for session {session.id}: "
               f"{len(findings)} findings, {failed_requests} failed requests")


def run_nikto_scan(session, target, stealth_session):
    """Simulate Nikto-style vulnerability scanning"""
    logger.info(f"Starting Nikto scan for session {session.id}")
    tool_result = ToolScanResult.objects.create(
        session=session,
        tool_name='nikto',
        status='running'
    )
    
    findings = []
    failed_checks = 0
    
    # Nikto-style checks
    nikto_checks = [
        # Check for server information disclosure
        {'path': '/', 'header': 'Server', 'description': 'Server version disclosure'},
        {'path': '/', 'header': 'X-Powered-By', 'description': 'Technology disclosure'},
        
        # Check for common vulnerable files
        {'path': '/phpinfo.php', 'description': 'PHP info disclosure'},
        {'path': '/server-status', 'description': 'Apache server status'},
        {'path': '/server-info', 'description': 'Apache server info'},
        
        # Check HTTP methods
        {'method': 'OPTIONS', 'path': '/', 'description': 'HTTP methods check'},
        {'method': 'TRACE', 'path': '/', 'description': 'TRACE method enabled'},
    ]
    
    parsed_url = urlparse(target.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for check in nikto_checks:
        try:
            test_url = base_url + check.get('path', '/')
            method = check.get('method', 'GET')
            
            response = make_request_with_retry(
                stealth_session, 
                test_url, 
                max_retries=target.max_retries,
                timeout=target.request_timeout,
                method=method
            )
            
            if response is None:
                # Request failed after all retries
                failed_checks += 1
                continue
            
            # Check headers if specified
            if 'header' in check:
                header_value = response.headers.get(check['header'])
                if header_value:
                    findings.append({
                        'url': test_url,
                        'issue': check['description'],
                        'evidence': f"{check['header']}: {header_value}",
                        'severity': 'info'
                    })
                    logger.debug(f"Nikto found header: {check['header']} = {header_value}")
            
            # Check for successful responses
            if 200 <= response.status_code < 300:
                findings.append({
                    'url': test_url,
                    'issue': check['description'],
                    'status_code': response.status_code,
                    'severity': 'medium'
                })
                
                HiddenContent.objects.create(
                    session=session,
                    url=test_url,
                    content_type='other',
                    discovery_method='nikto',
                    status_code=response.status_code,
                    risk_level='medium',
                    notes=check['description']
                )
                logger.debug(f"Nikto finding: {test_url} - {check['description']}")
        
        except Exception as e:
            failed_checks += 1
            logger.debug(f"Nikto check failed for {check.get('description', 'unknown')}: {e}")
            continue
    
    tool_result.status = 'completed'
    tool_result.completed_at = timezone.now()
    tool_result.findings_count = len(findings)
    tool_result.parsed_results = findings
    tool_result.raw_output = json.dumps(findings, indent=2)
    tool_result.save()
    
    logger.info(f"Nikto scan complete for session {session.id}: "
               f"{len(findings)} findings, {failed_checks} failed checks")


def run_wikto_scan(session, target, stealth_session):
    """Simulate Wikto-style scanning (Windows-focused Nikto alternative)"""
    logger.info(f"Starting Wikto scan for session {session.id}")
    tool_result = ToolScanResult.objects.create(
        session=session,
        tool_name='wikto',
        status='running'
    )
    
    findings = []
    failed_checks = 0
    
    # Wikto-style checks (Windows/IIS focused)
    wikto_checks = [
        '/web.config',
        '/Web.config',
        '/_vti_bin/',
        '/_vti_pvt/',
        '/aspnet_client/',
        '/App_Data/',
        '/bin/',
        '/Trace.axd',
        '/trace.axd',
        '/elmah.axd',
        '/admin',
        '/administrator',
        '/iisadmin/',
        '/scripts/',
        '/certsrv/',
        '/exchange/',
        '/owa/',
        '/ecp/',
    ]
    
    parsed_url = urlparse(target.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for path in wikto_checks:
        test_url = base_url + path
        
        try:
            response = make_request_with_retry(
                stealth_session, 
                test_url, 
                max_retries=target.max_retries,
                timeout=target.request_timeout,
                allow_redirects=False
            )
            
            if response is None:
                # Request failed after all retries
                failed_checks += 1
                continue
            
            if 200 <= response.status_code < 400:
                findings.append({
                    'url': test_url,
                    'status_code': response.status_code,
                    'issue': f'Accessible resource: {path}',
                    'severity': 'medium'
                })
                
                HiddenContent.objects.create(
                    session=session,
                    url=test_url,
                    content_type='config' if 'config' in path.lower() else 'directory',
                    discovery_method='wikto',
                    status_code=response.status_code,
                    risk_level='medium',
                    notes=f'Windows/IIS resource found: {path}'
                )
                logger.debug(f"Wikto found: {test_url} (status: {response.status_code})")
        
        except Exception as e:
            failed_checks += 1
            logger.debug(f"Wikto check failed for {path}: {e}")
            continue
    
    tool_result.status = 'completed'
    tool_result.completed_at = timezone.now()
    tool_result.findings_count = len(findings)
    tool_result.parsed_results = findings
    tool_result.save()
    
    logger.info(f"Wikto scan complete for session {session.id}: "
               f"{len(findings)} findings, {failed_checks} failed checks")


def brute_force_paths(session, target, stealth_session):
    """Brute force common paths and patterns"""
    logger.info(f"Starting brute force for session {session.id}")
    parsed_url = urlparse(target.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    successful_attempts = 0
    failed_attempts = 0
    
    # Common path patterns to brute force
    patterns = [
        # Numeric IDs
        *[f'/api/users/{i}' for i in range(1, 6)],
        *[f'/api/items/{i}' for i in range(1, 6)],
        *[f'/user/{i}' for i in range(1, 6)],
        
        # Year-based
        *[f'/archive/{year}' for year in range(2020, 2025)],
        *[f'/blog/{year}' for year in range(2020, 2025)],
        
        # Common variations
        '/api/v1', '/api/v2', '/api/v3',
        '/v1', '/v2', '/v3',
        '/old', '/new', '/beta', '/test',
    ]
    
    for path in patterns:
        test_url = base_url + path
        
        try:
            response = make_request_with_retry(
                stealth_session, 
                test_url, 
                max_retries=target.max_retries,
                timeout=target.request_timeout,
                allow_redirects=False
            )
            
            if response is None:
                # Request failed after all retries, still record the attempt
                failed_attempts += 1
                BruteForceAttempt.objects.create(
                    session=session,
                    base_url=base_url,
                    path_tested=path,
                    full_url=test_url,
                    status_code=None,
                    success=False
                )
                continue
            
            success = 200 <= response.status_code < 400
            
            BruteForceAttempt.objects.create(
                session=session,
                base_url=base_url,
                path_tested=path,
                full_url=test_url,
                status_code=response.status_code,
                response_time=response.elapsed.total_seconds(),
                content_length=len(response.content),
                success=success
            )
            
            if success:
                successful_attempts += 1
                DiscoveredURL.objects.get_or_create(
                    session=session,
                    url=test_url,
                    defaults={
                        'discovery_method': 'brute_force',
                        'status_code': response.status_code,
                        'is_hidden': True,
                    }
                )
                logger.debug(f"Brute force success: {test_url} (status: {response.status_code})")
        
        except Exception as e:
            failed_attempts += 1
            logger.debug(f"Brute force error testing {path}: {e}")
            continue
    
    logger.info(f"Brute force complete for session {session.id}: "
               f"{successful_attempts} successful, {failed_attempts} failed")


def infer_content(session, target, stealth_session):
    """Infer potential URLs based on discovered content"""
    logger.info(f"Starting content inference for session {session.id}")
    discovered_urls = session.discovered_urls.all()[:50]  # Limit for performance
    
    inferences_created = 0
    verifications_successful = 0
    
    for discovered in discovered_urls:
        parsed = urlparse(discovered.url)
        path = parsed.path
        
        # Pattern 1: Version inference
        # If we see /api/v1, try v2, v3, etc.
        version_match = re.search(r'/v(\d+)/', path)
        if version_match:
            current_version = int(version_match.group(1))
            for new_version in range(1, current_version + 3):
                if new_version != current_version:
                    new_path = path.replace(f'/v{current_version}/', f'/v{new_version}/')
                    inferred_url = urlunparse((parsed.scheme, parsed.netloc, new_path, '', '', ''))
                    
                    _, created = InferredContent.objects.get_or_create(
                        session=session,
                        inferred_url=inferred_url,
                        defaults={
                            'source_url': discovered.url,
                            'inference_type': 'version',
                            'confidence': 0.8,
                            'reasoning': f'Version pattern detected, inferred v{new_version} from v{current_version}'
                        }
                    )
                    if created:
                        inferences_created += 1
        
        # Pattern 2: File extension variation
        # If we see file.html, try file.php, file.asp, etc.
        if '.' in path.split('/')[-1]:
            filename = path.split('/')[-1]
            name, ext = filename.rsplit('.', 1)
            for new_ext in ['php', 'asp', 'aspx', 'jsp', 'html', 'htm']:
                if new_ext != ext:
                    new_filename = f"{name}.{new_ext}"
                    new_path = path.rsplit('/', 1)[0] + '/' + new_filename
                    inferred_url = urlunparse((parsed.scheme, parsed.netloc, new_path, '', '', ''))
                    
                    _, created = InferredContent.objects.get_or_create(
                        session=session,
                        inferred_url=inferred_url,
                        defaults={
                            'source_url': discovered.url,
                            'inference_type': 'pattern',
                            'confidence': 0.6,
                            'reasoning': f'File extension variation: .{ext} -> .{new_ext}'
                        }
                    )
                    if created:
                        inferences_created += 1
        
        # Pattern 3: Backup file inference
        # If we see config.php, try config.php.bak, config.php~, etc.
        if path.endswith(('.php', '.asp', '.aspx', '.conf', '.config')):
            for suffix in ['.bak', '.backup', '.old', '~', '.save']:
                inferred_url = discovered.url + suffix
                
                _, created = InferredContent.objects.get_or_create(
                    session=session,
                    inferred_url=inferred_url,
                    defaults={
                        'source_url': discovered.url,
                        'inference_type': 'pattern',
                        'confidence': 0.7,
                        'reasoning': f'Backup file pattern: added {suffix} suffix'
                    }
                )
                if created:
                    inferences_created += 1
        
        # Pattern 4: Technology stack inference
        # If we see WordPress files, infer other WP paths
        if 'wp-content' in path or 'wp-includes' in path:
            wp_paths = ['/wp-admin/', '/wp-login.php', '/xmlrpc.php', '/wp-config.php.bak']
            base_url = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
            
            for wp_path in wp_paths:
                inferred_url = base_url + wp_path
                
                _, created = InferredContent.objects.get_or_create(
                    session=session,
                    inferred_url=inferred_url,
                    defaults={
                        'source_url': discovered.url,
                        'inference_type': 'technology',
                        'confidence': 0.9,
                        'reasoning': 'WordPress detected, inferring standard WP paths'
                    }
                )
                if created:
                    inferences_created += 1
    
    logger.info(f"Created {inferences_created} inferences for session {session.id}")
    
    # Verify top inferred content (high confidence only)
    high_confidence = session.inferred_content.filter(confidence__gte=0.7, verified=False)[:20]
    
    for inferred in high_confidence:
        try:
            response = make_request_with_retry(
                stealth_session,
                inferred.inferred_url,
                max_retries=target.max_retries,
                timeout=target.request_timeout,
                method='GET'
            )
            
            if response is None:
                inferred.verified = True
                inferred.exists = False
                inferred.save()
                continue
            
            inferred.verified = True
            inferred.verified_at = timezone.now()
            inferred.exists = 200 <= response.status_code < 400
            inferred.status_code = response.status_code
            inferred.save()
            
            if inferred.exists:
                verifications_successful += 1
                DiscoveredURL.objects.get_or_create(
                    session=session,
                    url=inferred.inferred_url,
                    defaults={
                        'discovery_method': 'inference',
                        'status_code': response.status_code,
                        'is_hidden': True,
                    }
                )
                logger.debug(f"Verified inference: {inferred.inferred_url} (status: {response.status_code})")
        
        except Exception as e:
            logger.debug(f"Error verifying inference {inferred.inferred_url}: {e}")
            inferred.verified = True
            inferred.exists = False
            inferred.save()
    
    logger.info(f"Inference complete for session {session.id}: "
               f"{inferences_created} created, {verifications_successful} verified")


@api_view(['GET'])
def spider_results(request, session_id):
    """Get results of a spider session"""
    try:
        session = SpiderSession.objects.get(id=session_id)
        
        data = {
            'session_id': session.id,
            'status': session.status,
            'target': {
                'id': session.target.id,
                'name': session.target.name,
                'url': session.target.url,
            },
            'statistics': {
                'urls_discovered': session.urls_discovered,
                'urls_crawled': session.urls_crawled,
                'hidden_content_found': session.hidden_content_found,
                'inference_results': session.inference_results,
                'parameters_discovered': session.parameters_discovered,
            },
            'started_at': session.started_at.isoformat(),
            'completed_at': session.completed_at.isoformat() if session.completed_at else None,
            
            'discovered_urls': [{
                'url': url.url,
                'method': url.discovery_method,
                'status_code': url.status_code,
                'is_hidden': url.is_hidden,
                'is_interesting': url.is_interesting,
            } for url in session.discovered_urls.all()[:100]],
            
            'hidden_content': [{
                'url': content.url,
                'type': content.content_type,
                'method': content.discovery_method,
                'risk_level': content.risk_level,
                'status_code': content.status_code,
            } for content in session.hidden_content.all()],
            
            'tool_results': [{
                'tool': result.tool_name,
                'status': result.status,
                'findings_count': result.findings_count,
                'completed_at': result.completed_at.isoformat() if result.completed_at else None,
            } for result in session.tool_results.all()],
            
            'inferred_content': [{
                'url': inf.inferred_url,
                'type': inf.inference_type,
                'confidence': inf.confidence,
                'verified': inf.verified,
                'exists': inf.exists,
            } for inf in session.inferred_content.filter(verified=True, exists=True)],
            
            'discovered_parameters': [{
                'parameter_name': param.parameter_name,
                'parameter_value': param.parameter_value,
                'parameter_type': param.parameter_type,
                'target_url': param.target_url,
                'risk_level': param.risk_level,
                'http_method': param.http_method,
                'reveals_debug_info': param.reveals_debug_info,
                'reveals_source_code': param.reveals_source_code,
                'reveals_hidden_content': param.reveals_hidden_content,
            } for param in session.discovered_parameters.all()],
        }
        
        return Response(data)
    except SpiderSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


def discover_hidden_parameters(session, target, stealth_session):
    """Discover hidden parameters using common debug parameter names and values"""
    
    # Common debug parameter names
    parameter_names = [
        'debug', 'test', 'hide', 'source', 'dev', 'developer',
        'admin', 'trace', 'verbose', 'log', 'logging', 'show',
        'display', 'output', 'print', 'dump', 'echo', 'preview',
        'view', 'mode', 'env', 'environment', 'config', 'configuration',
        'demo', 'example', 'sample', 'internal', 'backdoor',
        'old', 'legacy', 'deprecate', 'obsolete', 'temp', 'tmp',
    ]
    
    # Common parameter values
    parameter_values = [
        'true', 'false', 'yes', 'no', 'on', 'off',
        '1', '0', 'enabled', 'disabled', 'enable', 'disable',
        'all', 'full', 'complete', 'verbose', 'detailed',
    ]
    
    # Get URLs to test - prioritize interesting ones
    urls_to_test = []
    
    # Test target URL
    urls_to_test.append(target.url)
    
    # Add discovered URLs that look interesting
    interesting_urls = session.discovered_urls.filter(
        is_interesting=True
    )[:10]  # Limit to prevent too many requests
    
    for discovered in interesting_urls:
        if discovered.url not in urls_to_test:
            urls_to_test.append(discovered.url)
    
    # If no interesting URLs, test a few regular ones
    if len(urls_to_test) == 1:
        regular_urls = session.discovered_urls.all()[:5]
        for discovered in regular_urls:
            if discovered.url not in urls_to_test:
                urls_to_test.append(discovered.url)
    
    # Test each URL with parameter combinations
    for test_url in urls_to_test:
        # Get baseline response first
        baseline_response = get_baseline_response(test_url, verify_ssl)
        if not baseline_response:
            continue
        
        # Test all parameter combinations
        for param_name in parameter_names:
            for param_value in parameter_values:
                # Test GET request with query parameter
                test_parameter_get(
                    session, test_url, param_name, param_value,
                    baseline_response, verify_ssl
                )
                
                # Test POST request (query + body)
                test_parameter_post(
                    session, test_url, param_name, param_value,
                    baseline_response, verify_ssl
                )
                
    
    # Brute force discovered parameters
    brute_force_discovered_parameters(session, verify_ssl)


def get_baseline_response(url, verify_ssl):
    """Get baseline response without any parameters"""
    try:
        response = stealth_session.get(url, timeout=5)
        return {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'content': response.text,
            'headers': dict(response.headers),
        }
    except Exception as e:
        return None


def test_parameter_get(session, url, param_name, param_value, baseline, verify_ssl):
    """Test parameter with GET request"""
    from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
    
    # Parse URL and add parameter
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [param_value]
    
    new_query = urlencode(params, doseq=True)
    test_url = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))
    
    try:
        response = stealth_session.get(test_url, timeout=5)
        
        # Analyze response
        response_diff = (
            response.status_code != baseline['status_code'] or
            abs(len(response.content) - baseline['content_length']) > 100
        )
        
        behavior_changed = response_diff
        error_revealed = check_for_errors(response.text)
        content_revealed = check_for_new_content(response.text, baseline['content'])
        
        # Record attempt
        attempt = ParameterDiscoveryAttempt.objects.create(
            session=session,
            target_url=url,
            parameter_name=param_name,
            parameter_value=param_value,
            http_method='GET',
            parameter_location='query',
            status_code=response.status_code,
            response_time=response.elapsed.total_seconds(),
            content_length=len(response.content),
            response_diff=response_diff,
            behavior_changed=behavior_changed,
            error_revealed=error_revealed,
            content_revealed=content_revealed,
        )
        
        # If parameter had an effect, mark it as discovered
        if behavior_changed or error_revealed or content_revealed:
            discover_parameter(
                session, url, param_name, param_value, 'GET',
                response, baseline, error_revealed, content_revealed
            )
    
    except Exception as e:
        pass


def test_parameter_post(session, url, param_name, param_value, baseline, verify_ssl):
    """Test parameter with POST request (both query string and body)"""
    from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
    
    # Parse URL and add parameter to query string
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [param_value]
    
    new_query = urlencode(params, doseq=True)
    test_url = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))
    
    # Also add parameter to POST body
    post_data = {param_name: param_value}
    
    try:
        response = stealth_session.post(
            test_url,
            data=post_data,
            timeout=5,
            verify=verify_ssl
        )
        
        # Analyze response
        response_diff = (
            response.status_code != baseline['status_code'] or
            abs(len(response.content) - baseline['content_length']) > 100
        )
        
        behavior_changed = response_diff
        error_revealed = check_for_errors(response.text)
        content_revealed = check_for_new_content(response.text, baseline['content'])
        
        # Record attempt
        attempt = ParameterDiscoveryAttempt.objects.create(
            session=session,
            target_url=url,
            parameter_name=param_name,
            parameter_value=param_value,
            http_method='POST',
            parameter_location='both',
            status_code=response.status_code,
            response_time=response.elapsed.total_seconds(),
            content_length=len(response.content),
            response_diff=response_diff,
            behavior_changed=behavior_changed,
            error_revealed=error_revealed,
            content_revealed=content_revealed,
        )
        
        # If parameter had an effect, mark it as discovered
        if behavior_changed or error_revealed or content_revealed:
            discover_parameter(
                session, url, param_name, param_value, 'POST',
                response, baseline, error_revealed, content_revealed
            )
    
    except Exception as e:
        pass


def check_for_errors(content):
    """Check if response contains error or debug information"""
    error_patterns = [
        'error', 'exception', 'traceback', 'stack trace',
        'warning', 'debug', 'sql', 'query', 'database',
        'path', 'file not found', 'undefined', 'null',
    ]
    
    content_lower = content.lower()
    for pattern in error_patterns:
        if pattern in content_lower:
            return True
    return False


def check_for_new_content(response_content, baseline_content):
    """Check if response reveals new content compared to baseline"""
    # Simple length comparison
    if abs(len(response_content) - len(baseline_content)) > 500:
        return True
    
    # Check for new sections or elements
    new_keywords = [
        'hidden', 'secret', 'internal', 'admin', 'developer',
        'config', 'configuration', 'debug', 'trace', 'log',
    ]
    
    response_lower = response_content.lower()
    baseline_lower = baseline_content.lower()
    
    for keyword in new_keywords:
        if keyword in response_lower and keyword not in baseline_lower:
            return True
    
    return False


def discover_parameter(session, url, param_name, param_value, method, response, baseline, error_revealed, content_revealed):
    """Mark a parameter as discovered"""
    
    # Determine parameter type
    param_type = 'other'
    if 'debug' in param_name.lower() or 'trace' in param_name.lower():
        param_type = 'debug'
    elif 'test' in param_name.lower() or 'demo' in param_name.lower():
        param_type = 'test'
    elif 'admin' in param_name.lower():
        param_type = 'admin'
    elif 'dev' in param_name.lower() or 'developer' in param_name.lower():
        param_type = 'developer'
    elif any(x in param_name.lower() for x in ['show', 'hide', 'display', 'view']):
        param_type = 'feature_flag'
    
    # Determine risk level
    risk_level = 'low'
    if error_revealed:
        risk_level = 'high'
    elif content_revealed:
        risk_level = 'medium'
    elif response.status_code != baseline['status_code']:
        risk_level = 'medium'
    
    # Build evidence
    evidence_parts = []
    if response.status_code != baseline['status_code']:
        evidence_parts.append(f"Status code changed from {baseline['status_code']} to {response.status_code}")
    if abs(len(response.content) - baseline['content_length']) > 100:
        evidence_parts.append(f"Content length changed from {baseline['content_length']} to {len(response.content)}")
    if error_revealed:
        evidence_parts.append("Response reveals error/debug information")
    if content_revealed:
        evidence_parts.append("Response reveals new content")
    
    evidence = "; ".join(evidence_parts)
    
    # Check for source code revelation
    reveals_source = any(x in response.text.lower() for x in ['<?php', '<?=', '<%', 'def ', 'function ', 'class '])
    
    # Create discovered parameter
    try:
        param, created = DiscoveredParameter.objects.get_or_create(
            session=session,
            target_url=url,
            parameter_name=param_name,
            parameter_value=param_value,
            defaults={
                'parameter_type': param_type,
                'http_method': method,
                'discovery_evidence': evidence,
                'risk_level': risk_level,
                'reveals_debug_info': error_revealed,
                'reveals_source_code': reveals_source,
                'reveals_hidden_content': content_revealed,
                'enables_functionality': response.status_code == 200 and baseline['status_code'] != 200,
                'causes_error': response.status_code >= 500,
            }
        )
    except Exception as e:
        pass


def brute_force_discovered_parameters(session, verify_ssl):
    """Perform brute force on discovered parameters to find more values"""
    
    discovered_params = session.discovered_parameters.all()[:10]  # Limit for performance
    
    # Brute force values
    brute_values = [
        # Boolean variations
        'True', 'False', 'TRUE', 'FALSE', 'Yes', 'No', 'YES', 'NO',
        # Numbers
        '2', '3', '10', '100', '1000', '-1',
        # Special values
        'null', 'none', 'undefined', '*', 'all', 'everything',
        # Common strings
        'admin', 'root', 'system', 'test', 'dev', 'prod',
        # Path traversal
        '../', '../../', '../../../',
        # SQL injection attempts (detection only)
        "' OR '1'='1", "1' OR '1'='1",
    ]
    
    for param in discovered_params:
        baseline_url = param.target_url
        
        for test_value in brute_values:
            if test_value == param.parameter_value:
                continue  # Skip the original value
            
            try:
                # Build test URL
                from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
                parsed = urlparse(baseline_url)
                params_dict = parse_qs(parsed.query)
                params_dict[param.parameter_name] = [test_value]
                
                new_query = urlencode(params_dict, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                # Make request
                if param.http_method == 'GET':
                    response = stealth_session.get(test_url, timeout=3)
                else:
                    response = stealth_session.post(
                        test_url,
                        data={param.parameter_name: test_value},
                        timeout=3,
                        verify=verify_ssl
                    )
                
                # Check for interesting response
                success = False
                finding = ""
                
                if response.status_code == 200:
                    success = True
                    finding = f"Valid response with value '{test_value}'"
                elif response.status_code >= 500:
                    success = True
                    finding = f"Server error triggered with value '{test_value}'"
                elif check_for_errors(response.text):
                    success = True
                    finding = f"Error information revealed with value '{test_value}'"
                
                # Record brute force attempt
                ParameterBruteForce.objects.create(
                    session=session,
                    discovered_parameter=param,
                    test_value=test_value,
                    test_description=f"Testing alternate value for {param.parameter_name}",
                    status_code=response.status_code,
                    response_time=response.elapsed.total_seconds(),
                    content_length=len(response.content),
                    success=success,
                    finding_description=finding if success else None,
                )
                
                # Small delay
                time.sleep(0.05)
                
            except Exception as e:
                continue
