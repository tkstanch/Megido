from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
from .models import (
    SpiderTarget, SpiderSession, DiscoveredURL,
    HiddenContent, BruteForceAttempt, InferredContent,
    ToolScanResult
)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import re
import os
import json
from collections import deque
import time


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
            'created_at': target.created_at.isoformat(),
        } for target in targets]
        return Response(data)
    
    elif request.method == 'POST':
        target = SpiderTarget.objects.create(
            url=request.data.get('url'),
            name=request.data.get('name', ''),
            description=request.data.get('description', ''),
            max_depth=request.data.get('max_depth', 3),
            follow_external_links=request.data.get('follow_external_links', False),
            use_dirbuster=request.data.get('use_dirbuster', True),
            use_nikto=request.data.get('use_nikto', True),
            use_wikto=request.data.get('use_wikto', True),
            enable_brute_force=request.data.get('enable_brute_force', True),
            enable_inference=request.data.get('enable_inference', True),
        )
        return Response({'id': target.id, 'message': 'Target created'}, status=201)


@api_view(['POST'])
def start_spider(request, target_id):
    """Start a spider session on a target"""
    try:
        target = SpiderTarget.objects.get(id=target_id)
        session = SpiderSession.objects.create(target=target, status='running')
        
        try:
            # Run comprehensive spidering
            run_spider_session(session, target)
            
            session.status = 'completed'
            session.completed_at = timezone.now()
            session.save()
            
            return Response({
                'id': session.id,
                'message': 'Spider session completed',
                'urls_discovered': session.urls_discovered,
                'hidden_content_found': session.hidden_content_found,
            })
        except Exception as e:
            session.status = 'failed'
            session.error_message = str(e)
            session.save()
            return Response({'error': str(e)}, status=500)
            
    except SpiderTarget.DoesNotExist:
        return Response({'error': 'Target not found'}, status=404)


def run_spider_session(session, target):
    """Main spider logic - orchestrates all discovery methods"""
    verify_ssl = os.environ.get('MEGIDO_VERIFY_SSL', 'False') == 'True'
    
    # Phase 1: Web Crawling
    crawl_website(session, target, verify_ssl)
    
    # Phase 2: DirBuster-style directory discovery
    if target.use_dirbuster:
        run_dirbuster_discovery(session, target, verify_ssl)
    
    # Phase 3: Nikto scanning
    if target.use_nikto:
        run_nikto_scan(session, target, verify_ssl)
    
    # Phase 4: Wikto scanning
    if target.use_wikto:
        run_wikto_scan(session, target, verify_ssl)
    
    # Phase 5: Brute force hidden content
    if target.enable_brute_force:
        brute_force_paths(session, target, verify_ssl)
    
    # Phase 6: Content inference
    if target.enable_inference:
        infer_content(session, target, verify_ssl)
    
    # Update session statistics
    session.urls_discovered = session.discovered_urls.count()
    session.hidden_content_found = session.hidden_content.count()
    session.inference_results = session.inferred_content.count()
    session.save()


def crawl_website(session, target, verify_ssl):
    """Crawl website starting from target URL"""
    visited = set()
    to_visit = deque([(target.url, 0)])  # (url, depth)
    base_domain = urlparse(target.url).netloc
    
    while to_visit and len(visited) < 500:  # Limit to 500 URLs
        current_url, depth = to_visit.popleft()
        
        if current_url in visited or depth > target.max_depth:
            continue
        
        visited.add(current_url)
        
        try:
            response = requests.get(current_url, timeout=10, verify=verify_ssl, allow_redirects=True)
            
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
            print(f"Error crawling {current_url}: {e}")
            continue
    
    session.urls_crawled = len(visited)
    session.save()


def run_dirbuster_discovery(session, target, verify_ssl):
    """Simulate DirBuster-style directory/file discovery"""
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
    parsed_url = urlparse(target.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for path in common_paths:
        test_url = f"{base_url}/{path}"
        
        try:
            response = requests.get(test_url, timeout=5, verify=verify_ssl, allow_redirects=False)
            
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
        
        except Exception as e:
            continue
    
    tool_result.status = 'completed'
    tool_result.completed_at = timezone.now()
    tool_result.findings_count = len(findings)
    tool_result.parsed_results = findings
    tool_result.save()


def run_nikto_scan(session, target, verify_ssl):
    """Simulate Nikto-style vulnerability scanning"""
    tool_result = ToolScanResult.objects.create(
        session=session,
        tool_name='nikto',
        status='running'
    )
    
    findings = []
    
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
            
            if method == 'GET':
                response = requests.get(test_url, timeout=5, verify=verify_ssl)
            elif method == 'OPTIONS':
                response = requests.options(test_url, timeout=5, verify=verify_ssl)
            elif method == 'TRACE':
                response = requests.request('TRACE', test_url, timeout=5, verify=verify_ssl)
            else:
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
        
        except Exception as e:
            continue
    
    tool_result.status = 'completed'
    tool_result.completed_at = timezone.now()
    tool_result.findings_count = len(findings)
    tool_result.parsed_results = findings
    tool_result.raw_output = json.dumps(findings, indent=2)
    tool_result.save()


def run_wikto_scan(session, target, verify_ssl):
    """Simulate Wikto-style scanning (Windows-focused Nikto alternative)"""
    tool_result = ToolScanResult.objects.create(
        session=session,
        tool_name='wikto',
        status='running'
    )
    
    findings = []
    
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
            response = requests.get(test_url, timeout=5, verify=verify_ssl, allow_redirects=False)
            
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
        
        except Exception as e:
            continue
    
    tool_result.status = 'completed'
    tool_result.completed_at = timezone.now()
    tool_result.findings_count = len(findings)
    tool_result.parsed_results = findings
    tool_result.save()


def brute_force_paths(session, target, verify_ssl):
    """Brute force common paths and patterns"""
    parsed_url = urlparse(target.url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
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
            response = requests.get(test_url, timeout=3, verify=verify_ssl, allow_redirects=False)
            
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
                DiscoveredURL.objects.get_or_create(
                    session=session,
                    url=test_url,
                    defaults={
                        'discovery_method': 'brute_force',
                        'status_code': response.status_code,
                        'is_hidden': True,
                    }
                )
        
        except Exception as e:
            continue


def infer_content(session, target, verify_ssl):
    """Infer potential URLs based on discovered content"""
    discovered_urls = session.discovered_urls.all()[:50]  # Limit for performance
    
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
                    
                    InferredContent.objects.get_or_create(
                        session=session,
                        inferred_url=inferred_url,
                        defaults={
                            'source_url': discovered.url,
                            'inference_type': 'version',
                            'confidence': 0.8,
                            'reasoning': f'Version pattern detected, inferred v{new_version} from v{current_version}'
                        }
                    )
        
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
                    
                    InferredContent.objects.get_or_create(
                        session=session,
                        inferred_url=inferred_url,
                        defaults={
                            'source_url': discovered.url,
                            'inference_type': 'pattern',
                            'confidence': 0.6,
                            'reasoning': f'File extension variation: .{ext} -> .{new_ext}'
                        }
                    )
        
        # Pattern 3: Backup file inference
        # If we see config.php, try config.php.bak, config.php~, etc.
        if path.endswith(('.php', '.asp', '.aspx', '.conf', '.config')):
            for suffix in ['.bak', '.backup', '.old', '~', '.save']:
                inferred_url = discovered.url + suffix
                
                InferredContent.objects.get_or_create(
                    session=session,
                    inferred_url=inferred_url,
                    defaults={
                        'source_url': discovered.url,
                        'inference_type': 'pattern',
                        'confidence': 0.7,
                        'reasoning': f'Backup file pattern: added {suffix} suffix'
                    }
                )
        
        # Pattern 4: Technology stack inference
        # If we see WordPress files, infer other WP paths
        if 'wp-content' in path or 'wp-includes' in path:
            wp_paths = ['/wp-admin/', '/wp-login.php', '/xmlrpc.php', '/wp-config.php.bak']
            base_url = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
            
            for wp_path in wp_paths:
                inferred_url = base_url + wp_path
                
                InferredContent.objects.get_or_create(
                    session=session,
                    inferred_url=inferred_url,
                    defaults={
                        'source_url': discovered.url,
                        'inference_type': 'technology',
                        'confidence': 0.9,
                        'reasoning': 'WordPress detected, inferring standard WP paths'
                    }
                )
    
    # Verify top inferred content (high confidence only)
    high_confidence = session.inferred_content.filter(confidence__gte=0.7, verified=False)[:20]
    
    for inferred in high_confidence:
        try:
            response = requests.get(inferred.inferred_url, timeout=5, verify=verify_ssl, allow_redirects=False)
            
            inferred.verified = True
            inferred.verified_at = timezone.now()
            inferred.exists = 200 <= response.status_code < 400
            inferred.status_code = response.status_code
            inferred.save()
            
            if inferred.exists:
                DiscoveredURL.objects.get_or_create(
                    session=session,
                    url=inferred.inferred_url,
                    defaults={
                        'discovery_method': 'inference',
                        'status_code': response.status_code,
                        'is_hidden': True,
                    }
                )
        
        except Exception as e:
            inferred.verified = True
            inferred.exists = False
            inferred.save()


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
        }
        
        return Response(data)
    except SpiderSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)
