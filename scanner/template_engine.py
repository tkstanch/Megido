"""
Nuclei-Style YAML Template Engine

Enables community-contributed vulnerability checks to be defined as YAML
files without writing Python.  Templates are loaded from the
``scanner/templates/`` directory and executed by the ``TemplateScanner``
plugin.

Template format (YAML)::

    id: my-custom-check
    info:
      name: My Custom Check
      severity: medium        # low | medium | high | critical
      description: >
        Detects something interesting.
      tags:
        - custom
        - headers
      cwe: CWE-200

    requests:
      - method: GET
        path: /
        headers:
          X-Custom: test
        matchers:
          - type: status
            status: [200]
          - type: word
            words:
              - 'interesting_token'
            part: body           # body | header | all
          - type: regex
            regex:
              - 'error[:\\s]+[A-Z]+'
            part: body
          - type: time
            condition: gt
            duration: 2.0        # seconds

Matchers are ANDed together by default.  A finding is raised when all
matchers in a request match.

Usage::

    from scanner.template_engine import TemplateEngine
    engine = TemplateEngine()
    engine.load_templates()
    findings = engine.run(url='https://example.com')
"""

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

# Default directory for YAML templates
_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Matcher:
    """A single matcher from a template request."""
    matcher_type: str   # status | word | regex | time
    # status matcher
    status: List[int] = field(default_factory=list)
    # word matcher
    words: List[str] = field(default_factory=list)
    part: str = 'body'
    # regex matcher
    regex: List[str] = field(default_factory=list)
    # time matcher
    condition: str = 'gt'
    duration: float = 2.0


@dataclass
class TemplateRequest:
    """A single request definition from a template."""
    method: str = 'GET'
    path: str = '/'
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ''
    matchers: List[Matcher] = field(default_factory=list)


@dataclass
class Template:
    """A fully parsed YAML template."""
    template_id: str
    name: str
    severity: str
    description: str
    cwe: str
    tags: List[str]
    requests: List[TemplateRequest]
    source_file: str = ''


# ---------------------------------------------------------------------------
# Template loader
# ---------------------------------------------------------------------------

class TemplateEngine:
    """
    Loads YAML templates and executes them against a target URL.

    Args:
        template_dir: Directory to load templates from
            (defaults to ``scanner/templates/``).
        verify_ssl: Whether to verify SSL certificates.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        template_dir: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 10,
    ) -> None:
        self.template_dir = template_dir or _TEMPLATE_DIR
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._templates: List[Template] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_templates(self, directory: Optional[str] = None) -> int:
        """
        Load all ``.yaml`` / ``.yml`` templates from *directory*.

        Args:
            directory: Override the instance ``template_dir``.

        Returns:
            Number of templates successfully loaded.
        """
        if not HAS_YAML:
            logger.warning("PyYAML is required to load templates")
            return 0

        directory = directory or self.template_dir
        if not os.path.isdir(directory):
            logger.info("Template directory does not exist: %s", directory)
            return 0

        count = 0
        for root, _, files in os.walk(directory):
            for fname in files:
                if fname.endswith(('.yaml', '.yml')):
                    path = os.path.join(root, fname)
                    tmpl = self._load_file(path)
                    if tmpl:
                        self._templates.append(tmpl)
                        count += 1

        logger.info("Loaded %d template(s) from %s", count, directory)
        return count

    def load_template_from_string(self, content: str, source: str = '<string>') -> Optional[Template]:
        """
        Parse a YAML template from a string.

        Args:
            content: YAML string.
            source: Label used in error messages.

        Returns:
            Parsed Template or None if parsing fails.
        """
        if not HAS_YAML:
            return None
        try:
            data = yaml.safe_load(content)
            return self._parse_template(data, source)
        except Exception as exc:
            logger.error("Failed to parse template %s: %s", source, exc)
            return None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(
        self,
        url: str,
        templates: Optional[List[Template]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Execute loaded templates against *url*.

        Args:
            url: Target URL.
            templates: Explicit list of templates to run; defaults to all
                loaded templates.
            config: Optional config dict (``verify_ssl``, ``timeout``).

        Returns:
            List of VulnerabilityFinding objects.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library required to run templates")
            return []

        config = config or {}
        verify_ssl = config.get('verify_ssl', self.verify_ssl)
        timeout = int(config.get('timeout', self.timeout))
        templates = templates or self._templates
        findings: List[VulnerabilityFinding] = []

        session = requests.Session()

        for tmpl in templates:
            for req_def in tmpl.requests:
                try:
                    finding = self._execute_request(
                        url, tmpl, req_def, session, verify_ssl, timeout
                    )
                    if finding:
                        findings.append(finding)
                except Exception as exc:
                    logger.debug("Template %s failed: %s", tmpl.template_id, exc)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_file(self, path: str) -> Optional[Template]:
        try:
            with open(path) as fh:
                data = yaml.safe_load(fh)
            return self._parse_template(data, path)
        except Exception as exc:
            logger.warning("Could not load template %s: %s", path, exc)
            return None

    @staticmethod
    def _parse_template(data: Any, source: str) -> Optional[Template]:
        """Parse a dict into a Template object."""
        if not isinstance(data, dict):
            return None
        info = data.get('info', {})
        requests_raw = data.get('requests', [])

        parsed_requests: List[TemplateRequest] = []
        for rq in requests_raw:
            matchers: List[Matcher] = []
            for m in rq.get('matchers', []):
                matchers.append(Matcher(
                    matcher_type=m.get('type', 'word'),
                    status=m.get('status', []),
                    words=m.get('words', []),
                    part=m.get('part', 'body'),
                    regex=m.get('regex', []),
                    condition=m.get('condition', 'gt'),
                    duration=float(m.get('duration', 2.0)),
                ))
            parsed_requests.append(TemplateRequest(
                method=rq.get('method', 'GET').upper(),
                path=rq.get('path', '/'),
                headers=rq.get('headers', {}),
                body=rq.get('body', ''),
                matchers=matchers,
            ))

        return Template(
            template_id=data.get('id', os.path.basename(source)),
            name=info.get('name', data.get('id', 'Unknown')),
            severity=info.get('severity', 'medium').lower(),
            description=info.get('description', ''),
            cwe=info.get('cwe', ''),
            tags=info.get('tags', []),
            requests=parsed_requests,
            source_file=source,
        )

    def _execute_request(
        self,
        base_url: str,
        tmpl: Template,
        req_def: TemplateRequest,
        session: Any,
        verify_ssl: bool,
        timeout: int,
    ) -> Optional[VulnerabilityFinding]:
        """Send a request and check matchers; return a finding if all match."""
        from urllib.parse import urljoin
        full_url = urljoin(base_url, req_def.path)

        start = time.monotonic()
        resp = session.request(
            method=req_def.method,
            url=full_url,
            headers=req_def.headers,
            data=req_def.body if req_def.body else None,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )
        elapsed = time.monotonic() - start

        if not self._all_matchers_match(req_def.matchers, resp, elapsed):
            return None

        return VulnerabilityFinding(
            vulnerability_type='other',
            severity=tmpl.severity,
            url=full_url,
            description=f'[Template: {tmpl.name}] {tmpl.description}',
            evidence=(
                f'Template ID: {tmpl.template_id}\n'
                f'Request: {req_def.method} {full_url}\n'
                f'Response status: {resp.status_code}'
            ),
            remediation='Refer to the template description for remediation guidance.',
            confidence=0.7,
            cwe_id=tmpl.cwe or None,
        )

    @staticmethod
    def _all_matchers_match(
        matchers: List[Matcher], resp: Any, elapsed: float
    ) -> bool:
        """Return True only if every matcher matches."""
        for matcher in matchers:
            if not TemplateEngine._matcher_matches(matcher, resp, elapsed):
                return False
        return True

    @staticmethod
    def _matcher_matches(matcher: Matcher, resp: Any, elapsed: float) -> bool:
        mtype = matcher.matcher_type

        if mtype == 'status':
            return resp.status_code in matcher.status

        target = ''
        if mtype in ('word', 'regex'):
            part = matcher.part
            if part == 'body':
                target = resp.text
            elif part == 'header':
                target = str(dict(resp.headers))
            else:
                target = resp.text + str(dict(resp.headers))

        if mtype == 'word':
            return all(w in target for w in matcher.words)

        if mtype == 'regex':
            return all(re.search(r, target) for r in matcher.regex)

        if mtype == 'time':
            if matcher.condition == 'gt':
                return elapsed > matcher.duration
            if matcher.condition == 'lt':
                return elapsed < matcher.duration
            return elapsed == matcher.duration

        return False


# ---------------------------------------------------------------------------
# TemplateScanner — BaseScanPlugin integration
# ---------------------------------------------------------------------------

class TemplateScannerPlugin(BaseScanPlugin):
    """
    Scan plugin that loads and executes all YAML templates.

    This plugin auto-discovers templates in ``scanner/templates/`` and runs
    them against the target URL, making community-contributed checks
    immediately available to the scan engine.
    """

    def __init__(self) -> None:
        super().__init__()
        self._engine = TemplateEngine()
        self._loaded = False

    @property
    def plugin_id(self) -> str:
        return 'template_scanner'

    @property
    def name(self) -> str:
        return 'YAML Template Scanner'

    @property
    def description(self) -> str:
        return 'Executes community-contributed YAML vulnerability check templates'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['other']

    def scan(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Load templates (once) and run them against *url*.

        Args:
            url: Target URL.
            config: Optional config (``verify_ssl``, ``timeout``,
                ``template_dir``).

        Returns:
            List of VulnerabilityFinding objects from matching templates.
        """
        config = config or {}

        if not self._loaded:
            template_dir = config.get('template_dir', _TEMPLATE_DIR)
            self._engine.template_dir = template_dir
            self._engine.load_templates()
            self._loaded = True

        if not self._engine._templates:
            logger.debug("No templates loaded — skipping template scan of %s", url)
            return []

        try:
            return self._engine.run(url, config=config)
        except Exception as exc:
            logger.error("Template scan of %s failed: %s", url, exc)
            return []
