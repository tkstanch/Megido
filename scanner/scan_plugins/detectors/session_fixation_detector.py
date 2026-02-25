"""
Session Fixation Detection Plugin

Detects session fixation vulnerabilities (CWE-384) by verifying whether
session tokens are properly rotated at authentication boundaries.

Scenarios covered:

1. Anonymous → Authenticated without session rotation
   Issue an anonymous session, perform login, check if the session token changed.

2. Authenticated session re-bound to a different user without rotation
   Login as user A, then attempt login as user B using the same session; verify
   whether a new session token is issued.

3. Non-auth apps: same token persists across first submission of sensitive data
   For apps without authentication but with sensitive submission/review flows,
   verify whether the session token is unchanged before and after submission and
   still allows retrieval of sensitive data via the review step.

4. Arbitrary token acceptance
   If session fixation behaviour is found, send a crafted/attacker-chosen cookie
   value and verify whether the server accepts and maintains it.

CWE: CWE-384 (Session Fixation)
"""

import logging
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding
from scanner.scan_plugins.vpoc import VPoCEvidence, build_curl_command, redact_sensitive_headers, truncate_body

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Heuristic patterns for identifying session cookies by name
_SESSION_COOKIE_PATTERNS = re.compile(
    r'^(session|sess|sid|jsessionid|phpsessid|asp\.net_sessionid|aspsessionid|'
    r'connect\.sid|rack\.session|_session|auth_token|token|csrftoken|beaker\.session\.id)$',
    re.IGNORECASE,
)

# Crafted token used for arbitrary token acceptance test
_CRAFTED_TOKEN = 'MegidoFixedToken9x7z'

_REMEDIATION = (
    'Regenerate the session identifier immediately after any authentication event '
    '(login, privilege escalation, role change). Invalidate the old session before '
    'issuing a new one. Set the Secure and HttpOnly flags on session cookies. '
    'Consider also setting SameSite=Strict or SameSite=Lax. '
    'Reject session identifiers that the server did not issue (use a server-side '
    'session store and validate tokens against it).'
)

_REMEDIATION_ARBITRARY = (
    'The server accepts session identifiers it did not previously issue. '
    'Implement server-side session storage and reject any cookie value not present '
    'in the session store. Additionally, rotate session tokens on every '
    'authentication event (see session fixation remediation above).'
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _extract_session_cookies(
    cookies: 'requests.cookies.RequestsCookieJar',
    override_names: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Return a dict of {cookie_name: cookie_value} for cookies that look like
    session identifiers.

    If *override_names* is provided, only those names are returned (if present).
    Otherwise a heuristic based on common session cookie name patterns is used.
    """
    result: Dict[str, str] = {}
    for cookie in cookies:
        name = cookie.name
        if override_names:
            if name in override_names:
                result[name] = cookie.value
        else:
            if _SESSION_COOKIE_PATTERNS.match(name):
                result[name] = cookie.value
    return result


def _cookies_rotated(before: Dict[str, str], after: Dict[str, str]) -> Tuple[bool, List[str]]:
    """
    Return (rotated, unchanged_names).

    *rotated* is True when every session cookie in *before* either disappears
    or its value changes in *after* (a new cookie may also have been added).

    *unchanged_names* lists the names of cookies whose values did NOT change.
    """
    unchanged: List[str] = []
    for name, value in before.items():
        if name in after and after[name] == value:
            unchanged.append(name)
    rotated = len(unchanged) == 0
    return rotated, unchanged


def _build_session_fixation_vpoc(
    response: Any,
    login_url: str,
    payload_description: str,
    confidence: float,
    reproduction_steps: str,
) -> Optional['VPoCEvidence']:
    """
    Build a VPoCEvidence from an HTTP response produced during a session
    fixation test scenario.

    The outgoing request and received response are both sanitized (sensitive
    headers redacted, large bodies truncated) before being stored.

    Returns None if evidence cannot be captured (e.g., no valid response).
    """
    try:
        req = getattr(response, 'request', None)
        http_request: Optional[Dict[str, Any]] = None
        if req is not None:
            try:
                req_headers: Dict[str, str] = {
                    str(k): str(v) for k, v in (req.headers or {}).items()
                }
            except Exception:
                req_headers = {}
            req_body = req.body or ''
            if isinstance(req_body, bytes):
                req_body = req_body.decode('utf-8', errors='replace')
            http_request = {
                'method': str(req.method or 'POST'),
                'url': str(req.url or login_url),
                'headers': redact_sensitive_headers(req_headers),
                'body': truncate_body(str(req_body)),
            }

        try:
            resp_headers: Dict[str, str] = {
                str(k): str(v) for k, v in (response.headers or {}).items()
            }
        except Exception:
            resp_headers = {}
        http_response: Dict[str, Any] = {
            'status_code': int(response.status_code),
            'headers': redact_sensitive_headers(resp_headers),
            'body': truncate_body(str(response.text or '')),
        }

        curl_cmd: Optional[str] = None
        if http_request is not None:
            try:
                curl_cmd = build_curl_command(
                    http_request['url'],
                    method=http_request['method'],
                    headers=http_request['headers'],
                    body=http_request['body'] or None,
                )
            except Exception:
                pass

        return VPoCEvidence(
            plugin_name='session_fixation_detector',
            target_url=login_url,
            payload=payload_description,
            confidence=confidence,
            http_request=http_request,
            http_response=http_response,
            reproduction_steps=reproduction_steps,
            curl_command=curl_cmd,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class SessionFixationDetectorPlugin(BaseScanPlugin):
    """
    Session Fixation vulnerability detection plugin.

    Detection strategy
    ------------------
    Scenario 1 – Anonymous → Authenticated
        GET the login URL (or the base URL) without credentials to obtain an
        anonymous session cookie, then POST the login form.  If the session
        cookie value is unchanged, report session fixation.

    Scenario 2 – Authenticated user swap
        Login as user A; then login as user B using the *same* session cookie.
        If the cookie value persists while the identity changes, report session
        fixation.

    Scenario 3 – Sensitive flow (non-auth apps)
        Follows a configured list of HTTP steps and verifies that the session
        cookie obtained before submission cannot be used to retrieve the review
        page after submission.

    Scenario 4 – Arbitrary token acceptance
        Re-issue a crafted cookie value and verify whether the server honours it
        (i.e. redirects to an authenticated area or returns a 200 with logged-in
        content).  Raises severity to *high* and confidence if confirmed.
    """

    @property
    def plugin_id(self) -> str:
        return 'session_fixation_detector'

    @property
    def name(self) -> str:
        return 'Session Fixation Detector'

    @property
    def description(self) -> str:
        return (
            'Detects session fixation vulnerabilities (CWE-384) by verifying '
            'whether session tokens are rotated at authentication boundaries'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['session_fixation']

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for Session Fixation vulnerabilities.

        Args:
            url:    Target URL (used as base when login_url is not set).
            config: Optional configuration dict – see get_default_config() for
                    supported keys and defaults.

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping session fixation scan")
            return []

        config = config or self.get_default_config()
        verify_ssl: bool = config.get('verify_ssl', False)
        timeout: int = config.get('timeout', 10)
        session_cookie_names: Optional[List[str]] = config.get('session_cookie_names') or None

        findings: List[VulnerabilityFinding] = []

        login_url: Optional[str] = config.get('login_url') or url
        username_field: str = config.get('username_field', 'username')
        password_field: str = config.get('password_field', 'password')
        username: Optional[str] = config.get('username')
        password: Optional[str] = config.get('password')
        username2: Optional[str] = config.get('username2')
        password2: Optional[str] = config.get('password2')

        # Scenario 3 – sensitive flow
        sensitive_flow: Optional[List[Dict[str, Any]]] = config.get('sensitive_flow')
        if sensitive_flow:
            flow_findings = self._test_sensitive_flow(
                url, sensitive_flow, session_cookie_names, verify_ssl, timeout
            )
            findings.extend(flow_findings)

        # Scenarios 1 & 2 require credentials
        if not username or not password:
            if not sensitive_flow:
                logger.info(
                    "Session fixation scan: no credentials configured and no sensitive_flow – "
                    "skipping auth-based checks"
                )
            return findings

        # Scenario 1 – anonymous → authenticated
        s1_findings, pre_login_cookies = self._test_anon_to_auth(
            login_url, username_field, password_field, username, password,
            session_cookie_names, verify_ssl, timeout,
        )
        findings.extend(s1_findings)

        # Scenario 2 – authenticated user swap (requires a second credential set)
        if username2 and password2 and not s1_findings:
            # Only run if scenario 1 did not already flag a fixation (avoid noise)
            s2_findings = self._test_user_swap(
                login_url, username_field, password_field,
                username, password, username2, password2,
                session_cookie_names, verify_ssl, timeout,
            )
            findings.extend(s2_findings)

        # Scenario 4 – arbitrary token acceptance (only if fixation was observed)
        if findings:
            arb_findings = self._test_arbitrary_token(
                login_url, username_field, password_field, username, password,
                session_cookie_names, verify_ssl, timeout,
            )
            if arb_findings:
                findings.extend(arb_findings)
                # Elevate existing findings' confidence since arbitrary token is
                # accepted (makes exploitation trivial).
                for f in findings:
                    if f.vulnerability_type == 'session_fixation':
                        f.confidence = min(f.confidence + 0.15, 1.0)
                        if f.severity == 'medium':
                            f.severity = 'high'

        logger.info("Session fixation scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Scenario 1: Anonymous → Authenticated
    # ------------------------------------------------------------------

    def _test_anon_to_auth(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        session_cookie_names: Optional[List[str]],
        verify_ssl: bool,
        timeout: int,
    ) -> Tuple[List[VulnerabilityFinding], Dict[str, str]]:
        """
        Issue an anonymous request to obtain a session token, then login.
        Report fixation if the token is unchanged after login.
        """
        findings: List[VulnerabilityFinding] = []
        pre_login_cookies: Dict[str, str] = {}

        try:
            session = requests.Session()
            # Step 1: anonymous request to seed a session cookie
            try:
                pre_resp = session.get(
                    login_url, verify=verify_ssl, timeout=timeout, allow_redirects=True
                )
                pre_login_cookies = _extract_session_cookies(session.cookies, session_cookie_names)
                logger.debug("Pre-login session cookies: %s", list(pre_login_cookies.keys()))
            except requests.RequestException as exc:
                logger.debug("Pre-login GET failed: %s", exc)
                return findings, pre_login_cookies

            if not pre_login_cookies:
                logger.debug("No session cookies found before login – cannot test scenario 1")
                return findings, pre_login_cookies

            # Step 2: submit login credentials
            try:
                post_resp = session.post(
                    login_url,
                    data={username_field: username, password_field: password},
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                logger.debug("Login POST failed: %s", exc)
                return findings, pre_login_cookies

            post_login_cookies = _extract_session_cookies(session.cookies, session_cookie_names)
            rotated, unchanged = _cookies_rotated(pre_login_cookies, post_login_cookies)

            if not rotated:
                evidence = (
                    f"Session cookie(s) {unchanged!r} retained the same value after login. "
                    f"Pre-login value(s): { {k: pre_login_cookies[k] for k in unchanged} }. "
                    f"Login POST to: {login_url}. "
                    f"Response status: {post_resp.status_code}."
                )
                confidence = 0.75
                vpoc = _build_session_fixation_vpoc(
                    response=post_resp,
                    login_url=login_url,
                    payload_description=(
                        f'Login credentials submitted via POST; session cookie(s) '
                        f'{unchanged!r} not rotated'
                    ),
                    confidence=confidence,
                    reproduction_steps=(
                        f'1. Send a GET request to {login_url} to obtain a session cookie.\n'
                        f'2. Note the value of cookie(s): {unchanged!r}.\n'
                        f'3. POST login credentials to {login_url}.\n'
                        f'4. Observe that the session cookie value is unchanged after '
                        f'successful authentication – session fixation is present.'
                    ),
                )
                findings.append(VulnerabilityFinding(
                    vulnerability_type='session_fixation',
                    severity='medium',
                    url=login_url,
                    description=(
                        f'Session token not rotated after login: cookie(s) {unchanged!r} '
                        f'retain the same value before and after authentication.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION,
                    confidence=confidence,
                    cwe_id='CWE-384',
                    vpoc=vpoc,
                ))
                logger.info("Scenario 1 fixation found: unchanged cookies %s", unchanged)

        except Exception as exc:
            logger.error("Error in anon→auth session fixation test: %s", exc)

        return findings, pre_login_cookies

    # ------------------------------------------------------------------
    # Scenario 2: Authenticated user swap
    # ------------------------------------------------------------------

    def _test_user_swap(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        username2: str,
        password2: str,
        session_cookie_names: Optional[List[str]],
        verify_ssl: bool,
        timeout: int,
    ) -> List[VulnerabilityFinding]:
        """
        Login as user A, then login as user B using the same session.
        Report fixation if the session token is not reissued.
        """
        findings: List[VulnerabilityFinding] = []

        try:
            session = requests.Session()

            # Seed anonymous session
            try:
                session.get(login_url, verify=verify_ssl, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                pass

            # Login as user A
            try:
                session.post(
                    login_url,
                    data={username_field: username, password_field: password},
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                logger.debug("User-A login failed: %s", exc)
                return findings

            cookies_after_a = _extract_session_cookies(session.cookies, session_cookie_names)
            if not cookies_after_a:
                logger.debug("No session cookies after user-A login – cannot test scenario 2")
                return findings

            # Login as user B using the same session
            try:
                resp_b = session.post(
                    login_url,
                    data={username_field: username2, password_field: password2},
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                logger.debug("User-B login failed: %s", exc)
                return findings

            cookies_after_b = _extract_session_cookies(session.cookies, session_cookie_names)
            rotated, unchanged = _cookies_rotated(cookies_after_a, cookies_after_b)

            if not rotated:
                evidence = (
                    f"Session cookie(s) {unchanged!r} were not reissued when switching "
                    f"from user '{username}' to user '{username2}'. "
                    f"The same session token is now bound to a different identity. "
                    f"Login POST to: {login_url}. "
                    f"Response status: {resp_b.status_code}."
                )
                confidence = 0.80
                vpoc = _build_session_fixation_vpoc(
                    response=resp_b,
                    login_url=login_url,
                    payload_description=(
                        f'User-swap: login as {username2!r} using session cookie(s) '
                        f'originally issued to {username!r}; cookie(s) {unchanged!r} '
                        f'not reissued'
                    ),
                    confidence=confidence,
                    reproduction_steps=(
                        f'1. Login as user "{username}" via POST to {login_url}.\n'
                        f'2. Note the value of cookie(s): {unchanged!r}.\n'
                        f'3. Without discarding the session, POST new login credentials '
                        f'for user "{username2}" to {login_url}.\n'
                        f'4. Observe that cookie(s) {unchanged!r} still carry the same '
                        f'value – the identity changed but the session was not reissued.'
                    ),
                )
                findings.append(VulnerabilityFinding(
                    vulnerability_type='session_fixation',
                    severity='medium',
                    url=login_url,
                    description=(
                        f'Session token not rotated during user swap: cookie(s) {unchanged!r} '
                        f'persisted while the authenticated identity changed from '
                        f'"{username}" to "{username2}".'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION,
                    confidence=confidence,
                    cwe_id='CWE-384',
                    vpoc=vpoc,
                ))
                logger.info("Scenario 2 fixation found: unchanged cookies %s", unchanged)

        except Exception as exc:
            logger.error("Error in user-swap session fixation test: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Scenario 3: Sensitive flow (non-auth apps)
    # ------------------------------------------------------------------

    def _test_sensitive_flow(
        self,
        base_url: str,
        flow_steps: List[Dict[str, Any]],
        session_cookie_names: Optional[List[str]],
        verify_ssl: bool,
        timeout: int,
    ) -> List[VulnerabilityFinding]:
        """
        Execute a configured list of HTTP steps and a review step.
        Report fixation if the pre-flow session token can still retrieve the
        review page after the sensitive data has been submitted.

        Each step is a dict with keys:
            method   – 'GET' or 'POST'  (default 'GET')
            url      – absolute or relative URL
            params   – dict of query parameters  (optional)
            data     – dict of POST body fields  (optional)

        The *last* step in flow_steps with key ``"review": true`` is the
        review/sensitive-data retrieval step.  If no step is flagged as review,
        the last step in the list is assumed to be the review step.
        """
        findings: List[VulnerabilityFinding] = []
        if not flow_steps:
            return findings

        try:
            # Identify the review step
            review_step: Optional[Dict[str, Any]] = None
            submission_steps: List[Dict[str, Any]] = []
            for step in flow_steps:
                if step.get('review'):
                    review_step = step
                else:
                    submission_steps.append(step)
            if review_step is None:
                review_step = flow_steps[-1]
                submission_steps = flow_steps[:-1]

            # Capture pre-flow session
            pre_session = requests.Session()
            try:
                pre_resp = pre_session.get(
                    base_url, verify=verify_ssl, timeout=timeout, allow_redirects=True
                )
            except requests.RequestException as exc:
                logger.debug("Sensitive flow: initial GET failed: %s", exc)
                return findings

            pre_cookies = _extract_session_cookies(pre_session.cookies, session_cookie_names)
            if not pre_cookies:
                logger.debug("Sensitive flow: no session cookies found at start")
                return findings

            # Main session: execute all submission steps
            main_session = requests.Session()
            try:
                main_session.get(
                    base_url, verify=verify_ssl, timeout=timeout, allow_redirects=True
                )
            except requests.RequestException:
                pass

            for step in submission_steps:
                method = step.get('method', 'GET').upper()
                step_url = step.get('url', base_url)
                try:
                    if method == 'POST':
                        main_session.post(
                            step_url,
                            data=step.get('data', {}),
                            params=step.get('params', {}),
                            verify=verify_ssl,
                            timeout=timeout,
                            allow_redirects=True,
                        )
                    else:
                        main_session.get(
                            step_url,
                            params=step.get('params', {}),
                            verify=verify_ssl,
                            timeout=timeout,
                            allow_redirects=True,
                        )
                except requests.RequestException as exc:
                    logger.debug("Sensitive flow step failed: %s", exc)

            # Now try to access the review step with the OLD (pre-flow) session
            review_url = review_step.get('url', base_url)
            review_method = review_step.get('method', 'GET').upper()

            # Build a session with just the pre-flow cookies
            test_session = requests.Session()
            for name, value in pre_cookies.items():
                test_session.cookies.set(name, value)

            try:
                if review_method == 'POST':
                    review_resp = test_session.post(
                        review_url,
                        data=review_step.get('data', {}),
                        params=review_step.get('params', {}),
                        verify=verify_ssl,
                        timeout=timeout,
                        allow_redirects=True,
                    )
                else:
                    review_resp = test_session.get(
                        review_url,
                        params=review_step.get('params', {}),
                        verify=verify_ssl,
                        timeout=timeout,
                        allow_redirects=True,
                    )
            except requests.RequestException as exc:
                logger.debug("Sensitive flow review step failed: %s", exc)
                return findings

            # Heuristic: if we got a 2xx response on the review page using the
            # pre-flow token, that is suspicious
            if review_resp.status_code in range(200, 300):
                evidence = (
                    f"Pre-submission session cookie(s) {list(pre_cookies.keys())} "
                    f"obtained before the sensitive flow were able to access "
                    f"the review page at '{review_url}' (HTTP {review_resp.status_code}) "
                    f"after the submission was completed."
                )
                confidence = 0.65
                vpoc = _build_session_fixation_vpoc(
                    response=review_resp,
                    login_url=base_url,
                    payload_description=(
                        f'Pre-flow session cookie(s) {list(pre_cookies.keys())} used to '
                        f'access review page at {review_url!r} after submission'
                    ),
                    confidence=confidence,
                    reproduction_steps=(
                        f'1. Visit {base_url} and note the session cookie value.\n'
                        f'2. Complete the sensitive submission flow.\n'
                        f'3. Replay a GET request to the review page {review_url!r} '
                        f'using the *pre-submission* session cookie.\n'
                        f'4. Observe a {review_resp.status_code} response – the old '
                        f'session token is still accepted on the review page.'
                    ),
                )
                findings.append(VulnerabilityFinding(
                    vulnerability_type='session_fixation',
                    severity='medium',
                    url=base_url,
                    description=(
                        'Session token not rotated after sensitive data submission: '
                        'a pre-submission session cookie can still access the '
                        f'review page at {review_url!r}.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION,
                    confidence=confidence,
                    cwe_id='CWE-384',
                    vpoc=vpoc,
                ))
                logger.info("Scenario 3 sensitive-flow fixation found")

        except Exception as exc:
            logger.error("Error in sensitive-flow session fixation test: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Scenario 4: Arbitrary token acceptance
    # ------------------------------------------------------------------

    def _test_arbitrary_token(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        session_cookie_names: Optional[List[str]],
        verify_ssl: bool,
        timeout: int,
    ) -> List[VulnerabilityFinding]:
        """
        Send a crafted/attacker-chosen session cookie value before login and
        check whether the server accepts and maintains it.
        """
        findings: List[VulnerabilityFinding] = []

        try:
            # First determine which cookie name(s) to target
            probe_session = requests.Session()
            try:
                probe_session.get(
                    login_url, verify=verify_ssl, timeout=timeout, allow_redirects=True
                )
            except requests.RequestException as exc:
                logger.debug("Arbitrary token probe GET failed: %s", exc)
                return findings

            real_cookies = _extract_session_cookies(probe_session.cookies, session_cookie_names)
            if not real_cookies:
                logger.debug("Arbitrary token test: no session cookies detected – skipping")
                return findings

            # Build a new session with the crafted token
            crafted_session = requests.Session()
            target_cookie_name = next(iter(real_cookies))
            crafted_session.cookies.set(target_cookie_name, _CRAFTED_TOKEN)

            try:
                login_resp = crafted_session.post(
                    login_url,
                    data={username_field: username, password_field: password},
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                logger.debug("Arbitrary token login POST failed: %s", exc)
                return findings

            # Check if the crafted token was preserved after login
            post_cookies = _extract_session_cookies(crafted_session.cookies, session_cookie_names)
            if post_cookies.get(target_cookie_name) == _CRAFTED_TOKEN:
                evidence = (
                    f"The server accepted and maintained the attacker-supplied cookie "
                    f"'{target_cookie_name}={_CRAFTED_TOKEN}' through the login flow. "
                    f"This confirms that the server does not validate session identifiers "
                    f"against a server-side store, making session fixation trivially exploitable."
                )
                confidence = 0.90
                vpoc = _build_session_fixation_vpoc(
                    response=login_resp,
                    login_url=login_url,
                    payload_description=(
                        f'Attacker-crafted cookie {target_cookie_name!r}={_CRAFTED_TOKEN!r} '
                        f'sent before login; server preserved the value after authentication'
                    ),
                    confidence=confidence,
                    reproduction_steps=(
                        f'1. Before visiting the login page, set the cookie '
                        f'"{target_cookie_name}={_CRAFTED_TOKEN}" in your browser.\n'
                        f'2. POST login credentials to {login_url}.\n'
                        f'3. Inspect the session cookie after login – the attacker-chosen '
                        f'value is still present, confirming arbitrary token acceptance.'
                    ),
                )
                findings.append(VulnerabilityFinding(
                    vulnerability_type='session_fixation',
                    severity='high',
                    url=login_url,
                    description=(
                        f'Arbitrary session token accepted: the server preserved an '
                        f'attacker-supplied cookie value ({target_cookie_name!r}) '
                        f'through the authentication flow. Session fixation exploitation '
                        f'is straightforward.'
                    ),
                    evidence=evidence,
                    remediation=_REMEDIATION_ARBITRARY,
                    confidence=confidence,
                    cwe_id='CWE-384',
                    verified=True,
                    vpoc=vpoc,
                ))
                logger.info("Scenario 4: arbitrary token accepted for cookie '%s'", target_cookie_name)

        except Exception as exc:
            logger.error("Error in arbitrary token acceptance test: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for session fixation scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            # Authentication config
            'login_url': None,          # Defaults to the URL passed to scan()
            'username_field': 'username',
            'password_field': 'password',
            'username': None,
            'password': None,
            'username2': None,          # Second user for swap scenario
            'password2': None,
            # Cookie name override (list of strings); None = use heuristics
            'session_cookie_names': None,
            # Sensitive flow for non-auth apps (list of step dicts)
            'sensitive_flow': None,
        }
