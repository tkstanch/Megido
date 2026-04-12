from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import BrowserSession, BrowserHistory, BrowserAppInteraction, BrowserSettings
from app_manager.models import AppConfiguration
from interceptor.models import InterceptorSettings
import importlib
import json
import subprocess
import sys
import os
import shutil
import platform
import tempfile
import webbrowser
from pathlib import Path


def browser_view(request):
    """Main browser interface view"""
    # Get or create browser session
    user = request.user if request.user.is_authenticated else None
    session = BrowserSession.objects.create(user=user, session_name='Browser Session')
    
    # Get all enabled apps for the toolbar
    enabled_apps = AppConfiguration.objects.filter(is_enabled=True)
    
    # Get interceptor status
    interceptor_settings = InterceptorSettings.get_settings()
    
    return render(request, 'browser/browser.html', {
        'session': session,
        'enabled_apps': enabled_apps,
        'interceptor_enabled': interceptor_settings.is_enabled
    })


@api_view(['GET'])
def list_sessions(request):
    """API endpoint to list browser sessions"""
    sessions = BrowserSession.objects.all()[:50]
    data = [{
        'id': session.id,
        'session_name': session.session_name,
        'user': session.user.username if session.user else 'Anonymous',
        'started_at': session.started_at.isoformat(),
        'ended_at': session.ended_at.isoformat() if session.ended_at else None,
        'is_active': session.is_active,
    } for session in sessions]
    return Response(data)


@api_view(['POST'])
def add_history(request):
    """API endpoint to add browser history entry"""
    session_id = request.data.get('session_id')
    url = request.data.get('url')
    title = request.data.get('title', '')
    
    try:
        session = BrowserSession.objects.get(id=session_id)
        history = BrowserHistory.objects.create(
            session=session,
            url=url,
            title=title
        )
        return Response({
            'success': True,
            'history_id': history.id
        })
    except BrowserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['GET'])
def get_history(request, session_id):
    """API endpoint to get browser history for a session"""
    try:
        session = BrowserSession.objects.get(id=session_id)
        history = session.history.all()[:100]
        data = [{
            'id': h.id,
            'url': h.url,
            'title': h.title,
            'visited_at': h.visited_at.isoformat(),
        } for h in history]
        return Response(data)
    except BrowserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['POST'])
def log_app_interaction(request):
    """API endpoint to log app interaction from browser"""
    session_id = request.data.get('session_id')
    app_name = request.data.get('app_name')
    action = request.data.get('action')
    target_url = request.data.get('target_url', '')
    result = request.data.get('result', '')
    
    try:
        session = BrowserSession.objects.get(id=session_id)
        interaction = BrowserAppInteraction.objects.create(
            session=session,
            app_name=app_name,
            action=action,
            target_url=target_url,
            result=result
        )
        return Response({
            'success': True,
            'interaction_id': interaction.id
        })
    except BrowserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['GET'])
def get_enabled_apps(request):
    """API endpoint to get all enabled apps"""
    apps = AppConfiguration.objects.filter(is_enabled=True)
    data = [{
        'app_name': app.app_name,
        'display_name': app.display_name,
        'icon': app.icon,
        'capabilities': app.get_capabilities_list(),
    } for app in apps]
    return Response(data)


@api_view(['GET', 'POST'])
def browser_interceptor_status(request):
    """API endpoint to get or toggle interceptor status from browser"""
    settings = InterceptorSettings.get_settings()
    
    if request.method == 'GET':
        return Response({
            'is_enabled': settings.is_enabled,
            'updated_at': settings.updated_at.isoformat()
        })
    
    elif request.method == 'POST':
        is_enabled = request.data.get('is_enabled', settings.is_enabled)
        
        # Validate boolean type
        if not isinstance(is_enabled, bool):
            return Response({
                'error': 'is_enabled must be a boolean value'
            }, status=400)
        
        settings.is_enabled = is_enabled
        settings.save()
        return Response({
            'success': True,
            'is_enabled': settings.is_enabled,
            'message': f"Interceptor {'enabled' if settings.is_enabled else 'disabled'}"
        })


@api_view(['POST'])
def launch_pyqt_browser(request):
    """API endpoint to launch PyQt6 desktop browser with mitmproxy integration
    
    Request body parameters:
        django_url (str): Django server URL (default: http://127.0.0.1:8000)
        proxy_port (int): mitmproxy port (default: 8080)
        enable_proxy (bool): Enable mitmproxy integration (default: true)
    """
    try:
        # Get Django URL from request or use default
        django_url = request.data.get('django_url', 'http://127.0.0.1:8000')
        
        # Get proxy configuration
        proxy_port = request.data.get('proxy_port', 8080)
        enable_proxy = request.data.get('enable_proxy', True)
        
        # Validate django_url to prevent command injection
        # Only allow URLs starting with http:// or https://
        if not (django_url.startswith('http://') or django_url.startswith('https://')):
            return Response({
                'success': False,
                'error': 'Invalid Django URL. Must start with http:// or https://'
            }, status=400)
        
        # Validate proxy_port
        try:
            proxy_port = int(proxy_port)
        except (TypeError, ValueError):
            return Response({
                'success': False,
                'error': 'Invalid proxy port. Must be an integer between 1 and 65535'
            }, status=400)
        if proxy_port < 1 or proxy_port > 65535:
            return Response({
                'success': False,
                'error': 'Invalid proxy port. Must be an integer between 1 and 65535'
            }, status=400)
        
        # Validate enable_proxy
        if not isinstance(enable_proxy, bool):
            return Response({
                'success': False,
                'error': 'Invalid enable_proxy value. Must be a boolean'
            }, status=400)
        
        # Check if PyQt6 is installed
        try:
            import importlib
            importlib.import_module('PyQt6.QtWidgets')
        except ImportError:
            return Response({
                'success': False,
                'error': (
                    'PyQt6 is not installed. Install it with: pip install PyQt6 PyQt6-WebEngine\n'
                    'Alternatively, use the "Launch External Browser" option to open Firefox or Chrome.'
                )
            }, status=500)
        
        # Path to PyQt6 launcher
        base_dir = Path(__file__).parent.parent
        launcher_path = base_dir / 'launch_megido_browser.py'
        
        if not launcher_path.exists():
            return Response({
                'success': False,
                'error': (
                    f'Desktop browser launcher not found at {launcher_path}. '
                    'Use the "Launch External Browser" option instead.'
                )
            }, status=500)
        
        # Build command with proxy configuration
        cmd = [sys.executable, str(launcher_path), '--django-url', django_url]
        
        if enable_proxy:
            cmd.extend(['--proxy-port', str(proxy_port)])
        else:
            cmd.append('--no-proxy')
        
        # Launch PyQt6 browser in background, capturing stderr for diagnostics
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True  # Detach from parent process
        )
        
        # Brief poll to detect immediate failures (e.g. import errors)
        import time
        time.sleep(0.5)
        ret = process.poll()
        if ret is not None and ret != 0:
            stderr_output = process.stderr.read().decode('utf-8', errors='replace')
            return Response({
                'success': False,
                'error': f'Browser process exited immediately (code {ret}). '
                         f'Details: {stderr_output[:500]}'
            }, status=500)
        
        return Response({
            'success': True,
            'message': 'Desktop browser launched successfully!',
            'proxy_enabled': enable_proxy,
            'proxy_port': proxy_port if enable_proxy else None
        })
        
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=500)


@api_view(['GET'])
def browser_launch_status(request):
    """API endpoint to check if a browser process is currently running"""
    try:
        # Check for running PyQt6 browser process
        current_pid = os.getpid()
        running = False
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'cmdline']):
                if proc.info['pid'] == current_pid:
                    continue
                cmdline = proc.info.get('cmdline') or []
                if any('launch_megido_browser' in arg for arg in cmdline):
                    running = True
                    break
        except ImportError:
            pass  # psutil not available; status unknown
        
        return Response({
            'browser_running': running,
            'message': 'Browser is running' if running else 'No browser detected'
        })
    except Exception as e:
        return Response({'browser_running': False, 'error': str(e)}, status=500)


@api_view(['POST'])
def launch_external_browser(request):
    """API endpoint to launch an external browser (Firefox, Chrome, Edge, Safari)
    configured to use mitmproxy as a proxy for traffic interception.

    Request body parameters:
        browser      (str): Browser to launch: 'firefox', 'chrome', 'chromium',
                            'edge', 'safari' (default: 'firefox')
        url          (str): Initial URL to open (default: 'http://example.com')
        proxy_host   (str): Proxy host (default: '127.0.0.1')
        proxy_port   (int): Proxy port (default: 8080)
        enable_proxy (bool): Whether to configure proxy settings (default: true)
    """
    try:
        browser_name = (request.data.get('browser') or 'firefox').lower().strip()
        url = request.data.get('url', 'http://example.com')
        proxy_host = request.data.get('proxy_host', '127.0.0.1')
        proxy_port = request.data.get('proxy_port', 8080)
        enable_proxy = request.data.get('enable_proxy', True)

        # Validate URL
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url

        # Validate proxy_port
        try:
            proxy_port = int(proxy_port)
        except (TypeError, ValueError):
            proxy_port = 8080
        if proxy_port < 1 or proxy_port > 65535:
            proxy_port = 8080

        # Validate enable_proxy
        if not isinstance(enable_proxy, bool):
            enable_proxy = True

        # Dispatch to browser-specific launcher
        if browser_name == 'firefox':
            return _launch_firefox(url, proxy_host, proxy_port, enable_proxy)
        elif browser_name in ('chrome', 'chromium', 'google-chrome'):
            return _launch_chromium(url, proxy_host, proxy_port, enable_proxy, browser_name)
        elif browser_name == 'edge':
            return _launch_edge(url, proxy_host, proxy_port, enable_proxy)
        elif browser_name == 'safari':
            return _launch_safari(url, proxy_host, proxy_port, enable_proxy)
        else:
            return Response({
                'success': False,
                'error': f'Unsupported browser: {browser_name}. '
                         'Supported browsers: firefox, chrome, chromium, edge, safari'
            }, status=400)

    except Exception as e:
        return Response({'success': False, 'error': str(e)}, status=500)


# ---------------------------------------------------------------------------
# External browser launchers (internal helpers)
# ---------------------------------------------------------------------------

def _is_docker():
    """Return True if the process is running inside a Docker container."""
    if os.environ.get('DOCKER_CONTAINER'):
        return True
    return os.path.isfile('/.dockerenv')


def _client_side_response(url, proxy_host, proxy_port, enable_proxy, browser_name):
    """Return a response instructing the frontend to open the browser client-side."""
    return Response({
        'success': True,
        'mode': 'client-side',
        'browser': browser_name,
        'url': url,
        'proxy_enabled': enable_proxy,
        'proxy_host': proxy_host if enable_proxy else None,
        'proxy_port': proxy_port if enable_proxy else None,
    })


def _launch_firefox(url, proxy_host, proxy_port, enable_proxy):
    """Launch Firefox with an optional mitmproxy configuration."""
    if _is_docker():
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, 'firefox')

    system = platform.system()
    
    # Find Firefox executable
    firefox_candidates = []
    if system == 'Windows':
        firefox_candidates = [
            r'C:\Program Files\Mozilla Firefox\firefox.exe',
            r'C:\Program Files (x86)\Mozilla Firefox\firefox.exe',
        ]
    elif system == 'Darwin':
        firefox_candidates = [
            '/Applications/Firefox.app/Contents/MacOS/firefox',
            shutil.which('firefox'),
        ]
    else:  # Linux / other Unix
        firefox_candidates = [
            shutil.which('firefox'),
            shutil.which('firefox-esr'),
            '/usr/bin/firefox',
            '/usr/bin/firefox-esr',
            '/snap/bin/firefox',
        ]
    
    firefox_path = next(
        (p for p in firefox_candidates if p and os.path.exists(p) and os.access(p, os.X_OK)), None
    )
    
    if not firefox_path:
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, 'firefox')
    
    cmd = [firefox_path]
    
    if enable_proxy:
        # Create a temporary Firefox profile with proxy settings
        profile_dir = tempfile.mkdtemp(prefix='megido_firefox_')
        prefs_js = os.path.join(profile_dir, 'prefs.js')
        with open(prefs_js, 'w') as f:
            f.write(f'user_pref("network.proxy.type", 1);\n')
            f.write(f'user_pref("network.proxy.http", "{proxy_host}");\n')
            f.write(f'user_pref("network.proxy.http_port", {proxy_port});\n')
            f.write(f'user_pref("network.proxy.ssl", "{proxy_host}");\n')
            f.write(f'user_pref("network.proxy.ssl_port", {proxy_port});\n')
            f.write(f'user_pref("network.proxy.ftp", "{proxy_host}");\n')
            f.write(f'user_pref("network.proxy.ftp_port", {proxy_port});\n')
            f.write(f'user_pref("network.proxy.no_proxies_on", "");\n')
            # Accept mitmproxy certificate
            f.write('user_pref("security.cert_pinning.enforcement_level", 0);\n')
        cmd += ['--profile', profile_dir, '--no-remote']
    
    cmd.append(url)
    
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    
    message = (
        f'Firefox launched with proxy {proxy_host}:{proxy_port}. '
        'Install the mitmproxy certificate from http://mitm.it to intercept HTTPS.'
        if enable_proxy
        else 'Firefox launched without proxy.'
    )
    return Response({
        'success': True,
        'browser': 'firefox',
        'message': message,
        'proxy_enabled': enable_proxy,
        'proxy_host': proxy_host if enable_proxy else None,
        'proxy_port': proxy_port if enable_proxy else None,
    })


def _launch_chromium(url, proxy_host, proxy_port, enable_proxy, browser_name='chrome'):
    """Launch Chrome or Chromium with optional proxy settings."""
    if _is_docker():
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, browser_name)

    system = platform.system()
    
    # Find Chrome/Chromium executable
    chrome_candidates = []
    if system == 'Windows':
        chrome_candidates = [
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
            shutil.which('chrome'),
            shutil.which('chromium'),
        ]
    elif system == 'Darwin':
        chrome_candidates = [
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Chromium.app/Contents/MacOS/Chromium',
            shutil.which('google-chrome'),
            shutil.which('chromium'),
        ]
    else:  # Linux
        chrome_candidates = [
            shutil.which('google-chrome'),
            shutil.which('google-chrome-stable'),
            shutil.which('chromium'),
            shutil.which('chromium-browser'),
            '/usr/bin/google-chrome',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
        ]
    
    chrome_path = next(
        (p for p in chrome_candidates if p and os.path.exists(p) and os.access(p, os.X_OK)), None
    )
    
    if not chrome_path:
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, browser_name)
    
    # Create a temporary user data dir to avoid polluting the default profile
    user_data_dir = tempfile.mkdtemp(prefix='megido_chrome_')
    
    cmd = [
        chrome_path,
        f'--user-data-dir={user_data_dir}',
        '--no-first-run',
        '--no-default-browser-check',
    ]
    
    if enable_proxy:
        cmd += [
            f'--proxy-server={proxy_host}:{proxy_port}',
            '--ignore-certificate-errors',
            '--ignore-urlfetcher-cert-requests',
        ]
    
    cmd.append(url)
    
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    
    message = (
        f'Chrome launched with proxy {proxy_host}:{proxy_port}. '
        'Accept the certificate warning or visit http://mitm.it to install the mitmproxy CA.'
        if enable_proxy
        else 'Chrome launched without proxy.'
    )
    return Response({
        'success': True,
        'browser': browser_name,
        'message': message,
        'proxy_enabled': enable_proxy,
        'proxy_host': proxy_host if enable_proxy else None,
        'proxy_port': proxy_port if enable_proxy else None,
    })


def _launch_edge(url, proxy_host, proxy_port, enable_proxy):
    """Launch Microsoft Edge with optional proxy settings."""
    if _is_docker():
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, 'edge')

    system = platform.system()
    
    edge_candidates = []
    if system == 'Windows':
        edge_candidates = [
            r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
            shutil.which('msedge'),
        ]
    elif system == 'Darwin':
        edge_candidates = [
            '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
            shutil.which('microsoft-edge'),
        ]
    else:  # Linux
        edge_candidates = [
            shutil.which('microsoft-edge'),
            shutil.which('microsoft-edge-stable'),
            '/usr/bin/microsoft-edge',
            '/usr/bin/microsoft-edge-stable',
        ]
    
    edge_path = next(
        (p for p in edge_candidates if p and os.path.exists(p) and os.access(p, os.X_OK)), None
    )
    
    if not edge_path:
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, 'edge')
    
    user_data_dir = tempfile.mkdtemp(prefix='megido_edge_')
    
    cmd = [
        edge_path,
        f'--user-data-dir={user_data_dir}',
        '--no-first-run',
        '--no-default-browser-check',
    ]
    
    if enable_proxy:
        cmd += [
            f'--proxy-server={proxy_host}:{proxy_port}',
            '--ignore-certificate-errors',
        ]
    
    cmd.append(url)
    
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    
    message = (
        f'Microsoft Edge launched with proxy {proxy_host}:{proxy_port}.'
        if enable_proxy
        else 'Microsoft Edge launched without proxy.'
    )
    return Response({
        'success': True,
        'browser': 'edge',
        'message': message,
        'proxy_enabled': enable_proxy,
        'proxy_host': proxy_host if enable_proxy else None,
        'proxy_port': proxy_port if enable_proxy else None,
    })


def _launch_safari(url, proxy_host, proxy_port, enable_proxy):
    """Launch Safari (macOS only)."""
    if _is_docker() or platform.system() != 'Darwin':
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, 'safari')
    
    safari_path = '/Applications/Safari.app/Contents/MacOS/Safari'
    if not os.path.exists(safari_path) or not os.access(safari_path, os.X_OK):
        return _client_side_response(url, proxy_host, proxy_port, enable_proxy, 'safari')
    
    if enable_proxy:
        # Safari uses system proxy settings; guide the user
        note = (
            f'Safari opened. To route traffic through mitmproxy, configure your system proxy: '
            f'System Preferences → Network → Advanced → Proxies → '
            f'Web Proxy (HTTP): {proxy_host}:{proxy_port}'
        )
    else:
        note = 'Safari opened without proxy configuration.'
    
    subprocess.Popen(['open', '-a', 'Safari', url],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    return Response({
        'success': True,
        'browser': 'safari',
        'message': note,
        'proxy_enabled': False,  # Not automatically configured
        'proxy_host': None,
        'proxy_port': None,
    })
