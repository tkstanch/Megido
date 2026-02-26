"""
Manifest parsing utilities for the decompiler app.

Handles Chrome manifest.json (v2/v3), Firefox manifest.json and
install.rdf, and permission risk scoring.
"""
import json
import re
from typing import Dict, List, Tuple

try:
    from xml.etree import ElementTree as ET
    _ET_AVAILABLE = True
except ImportError:
    _ET_AVAILABLE = False


# Risk scores for common Chrome/Firefox permissions (0-100)
PERMISSION_RISK_MAP: Dict[str, int] = {
    '<all_urls>': 90,
    'http://*/*': 80,
    'https://*/*': 80,
    'file:///*': 70,
    'tabs': 60,
    'webRequest': 70,
    'webRequestBlocking': 80,
    'cookies': 65,
    'history': 60,
    'bookmarks': 40,
    'downloads': 50,
    'management': 70,
    'proxy': 75,
    'nativeMessaging': 80,
    'debugger': 85,
    'declarativeNetRequest': 60,
    'storage': 30,
    'identity': 50,
    'notifications': 20,
    'contextMenus': 10,
    'activeTab': 25,
    'scripting': 65,
    'clipboardRead': 55,
    'clipboardWrite': 40,
    'geolocation': 55,
    'webNavigation': 50,
    'alarms': 10,
    'background': 40,
}


def _host_permission_risk(pattern: str) -> int:
    """Score a host permission pattern."""
    if pattern in ('<all_urls>', 'http://*/*', 'https://*/*'):
        return 85
    if pattern.startswith('*://'):
        return 60
    return 20


def score_permission(permission: str) -> Tuple[int, str]:
    """
    Return (risk_score, risk_level) for a permission string.
    """
    score = PERMISSION_RISK_MAP.get(permission)
    if score is None:
        score = _host_permission_risk(permission)

    if score >= 80:
        level = 'critical'
    elif score >= 60:
        level = 'high'
    elif score >= 40:
        level = 'medium'
    else:
        level = 'low'
    return score, level


def parse_chrome_manifest(manifest_json: str) -> Dict:
    """
    Parse a Chrome/WebExtension manifest.json.

    Returns a normalised dict with key fields extracted.
    """
    try:
        data = json.loads(manifest_json)
    except (json.JSONDecodeError, TypeError):
        return {'error': 'Invalid JSON'}

    permissions = data.get('permissions', []) + data.get('host_permissions', [])
    optional_permissions = data.get('optional_permissions', [])

    background = data.get('background', {})
    bg_scripts = (background.get('scripts', [])
                  or ([background['service_worker']] if 'service_worker' in background else []))

    content_scripts = []
    for cs in data.get('content_scripts', []):
        content_scripts.append({
            'matches': cs.get('matches', []),
            'js': cs.get('js', []),
            'css': cs.get('css', []),
            'run_at': cs.get('run_at', 'document_idle'),
        })

    csp = (data.get('content_security_policy')
           or data.get('content_security_policy', {}).get('extension_pages', ''))

    return {
        'manifest_version': data.get('manifest_version'),
        'name': data.get('name', ''),
        'version': data.get('version', ''),
        'description': data.get('description', ''),
        'author': data.get('author', ''),
        'homepage_url': data.get('homepage_url', ''),
        'permissions': permissions,
        'optional_permissions': optional_permissions,
        'background_scripts': bg_scripts,
        'content_scripts': content_scripts,
        'web_accessible_resources': data.get('web_accessible_resources', []),
        'content_security_policy': csp if isinstance(csp, str) else '',
        'raw': data,
    }


def parse_install_rdf(rdf_content: str) -> Dict:
    """Parse a Firefox install.rdf file."""
    result = {
        'name': '',
        'version': '',
        'description': '',
        'author': '',
        'homepage_url': '',
        'permissions': [],
        'raw_rdf': rdf_content,
    }
    if not _ET_AVAILABLE:
        return result
    try:
        root = ET.fromstring(rdf_content)
        ns = {
            'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
            'em': 'http://www.mozilla.org/2004/em-rdf#',
        }
        desc = root.find('.//rdf:Description', ns) or root.find('.//em:Description', ns)
        if desc is not None:
            for field in ('name', 'version', 'description', 'creator', 'homepageURL'):
                el = desc.find(f'em:{field}', ns)
                if el is not None and el.text:
                    key = 'author' if field == 'creator' else (
                        'homepage_url' if field == 'homepageURL' else field)
                    result[key] = el.text.strip()
    except ET.ParseError:
        pass
    return result


def analyze_csp(csp: str) -> List[str]:
    """
    Analyse a Content Security Policy string and return issues found.
    """
    issues = []
    if not csp:
        return issues
    if "'unsafe-eval'" in csp:
        issues.append("CSP allows unsafe-eval — extensions can run eval()")
    if "'unsafe-inline'" in csp:
        issues.append("CSP allows unsafe-inline — inline scripts permitted")
    if re.search(r"script-src[^;]*\*", csp):
        issues.append("CSP script-src uses wildcard — any script origin allowed")
    return issues
