"""
Authentication Manager

Provides authentication support for the scanner engine so that plugins can
scan authenticated endpoints.

Supported authentication types:

* ``basic``     — HTTP Basic Auth (username / password)
* ``bearer``    — Bearer token in ``Authorization`` header
* ``cookie``    — Pre-supplied cookie string or dict
* ``form``      — Form-based login (POST credentials to a login URL)
* ``oauth2``    — OAuth 2.0 Client Credentials grant
* ``headers``   — Arbitrary custom headers (e.g. API keys)

Usage::

    from scanner.auth_manager import AuthManager

    mgr = AuthManager()
    mgr.configure({
        'auth_type': 'form',
        'login_url': 'https://example.com/login',
        'credentials': {'username': 'admin', 'password': 's3cr3t'},
    })
    session = mgr.get_session()
    # pass session to plugins via config['session']
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import requests
    from requests import Session
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    Session = object  # type: ignore[misc,assignment]

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class AuthManager:
    """
    Manages authentication state for vulnerability scanning sessions.

    The manager creates and caches a :class:`requests.Session` that carries
    the appropriate credentials/tokens for all subsequent requests.  Plugins
    receive this session via ``config['session']``.

    Args:
        verify_ssl: Whether to verify SSL certificates (default: False).
        timeout: Default request timeout in seconds (default: 15).
    """

    SUPPORTED_AUTH_TYPES = ('basic', 'bearer', 'cookie', 'form', 'oauth2', 'headers')

    def __init__(self, verify_ssl: bool = False, timeout: int = 15) -> None:
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session: Optional[Any] = None
        self._config: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the authentication manager.

        Args:
            config: Dictionary containing auth settings.  Required keys depend
                on ``auth_type``:

                * ``basic``: ``credentials = {'username': ..., 'password': ...}``
                * ``bearer``: ``token = '<token_string>'``
                * ``cookie``: ``cookies = {'name': 'value', ...}`` or
                              ``cookie_string = 'name=value; name2=value2'``
                * ``form``: ``login_url``, ``credentials``,
                            optionally ``username_field``, ``password_field``
                * ``oauth2``: ``token_url``, ``client_id``, ``client_secret``,
                              optionally ``scope``
                * ``headers``: ``custom_headers = {'X-Api-Key': '...'}``
        """
        self._config = config
        self._session = None  # Reset cached session

    # ------------------------------------------------------------------
    # Session retrieval
    # ------------------------------------------------------------------

    def get_session(self) -> Any:
        """
        Return an authenticated ``requests.Session``.

        The session is created once and cached.  Call :meth:`configure` with
        new credentials to force re-authentication.

        Returns:
            Authenticated requests.Session, or a plain unauthenticated session
            if authentication is not configured or dependency is missing.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return None

        if self._session is not None:
            return self._session

        session = requests.Session()
        session.verify = self.verify_ssl

        auth_type = self._config.get('auth_type', '').lower()

        if not auth_type:
            self._session = session
            return session

        if auth_type not in self.SUPPORTED_AUTH_TYPES:
            logger.warning("Unsupported auth_type: %s", auth_type)
            self._session = session
            return session

        try:
            handler = getattr(self, f'_auth_{auth_type}')
            handler(session)
        except Exception as exc:
            logger.error("Authentication failed (%s): %s", auth_type, exc)

        self._session = session
        return session

    # ------------------------------------------------------------------
    # Auth handlers
    # ------------------------------------------------------------------

    def _auth_basic(self, session: Any) -> None:
        creds = self._config.get('credentials', {})
        username = creds.get('username', '')
        password = creds.get('password', '')
        session.auth = (username, password)
        logger.info("Configured Basic Auth for user '%s'", username)

    def _auth_bearer(self, session: Any) -> None:
        token = self._config.get('token', '')
        session.headers.update({'Authorization': f'Bearer {token}'})
        logger.info("Configured Bearer token authentication")

    def _auth_cookie(self, session: Any) -> None:
        cookies = self._config.get('cookies')
        cookie_string = self._config.get('cookie_string', '')
        if cookies and isinstance(cookies, dict):
            for name, value in cookies.items():
                session.cookies.set(name, value)
        elif cookie_string:
            for pair in cookie_string.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    name, _, value = pair.partition('=')
                    session.cookies.set(name.strip(), value.strip())
        logger.info("Configured cookie-based authentication")

    def _auth_form(self, session: Any) -> None:
        if not HAS_BS4:
            logger.warning("beautifulsoup4 required for form-based auth")
            return

        login_url = self._config.get('login_url', '')
        creds = self._config.get('credentials', {})
        username_field = self._config.get('username_field', 'username')
        password_field = self._config.get('password_field', 'password')

        if not login_url:
            logger.warning("form auth requires login_url")
            return

        # Fetch the login form to extract CSRF token
        resp = session.get(login_url, timeout=self.timeout)
        soup = BeautifulSoup(resp.text, 'html.parser')

        form_data: Dict[str, str] = {}
        for inp in soup.find_all('input'):
            name = inp.get('name')
            value = inp.get('value', '')
            if name:
                form_data[name] = value

        # Override with supplied credentials
        form_data[username_field] = creds.get('username', '')
        form_data[password_field] = creds.get('password', '')

        # Determine form action
        form = soup.find('form')
        if form:
            from urllib.parse import urljoin
            action = form.get('action', login_url)
            post_url = urljoin(login_url, action)
            method = form.get('method', 'post').lower()
        else:
            post_url = login_url
            method = 'post'

        if method == 'post':
            session.post(post_url, data=form_data, timeout=self.timeout)
        else:
            session.get(post_url, params=form_data, timeout=self.timeout)

        logger.info("Form-based login attempted on %s", login_url)

    def _auth_oauth2(self, session: Any) -> None:
        token_url = self._config.get('token_url', '')
        client_id = self._config.get('client_id', '')
        client_secret = self._config.get('client_secret', '')
        scope = self._config.get('scope', '')

        if not token_url:
            logger.warning("oauth2 auth requires token_url")
            return

        payload: Dict[str, str] = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
        }
        if scope:
            payload['scope'] = scope

        resp = requests.post(
            token_url, data=payload, timeout=self.timeout, verify=self.verify_ssl
        )
        resp.raise_for_status()
        token = resp.json().get('access_token', '')
        session.headers.update({'Authorization': f'Bearer {token}'})
        logger.info("OAuth2 Client Credentials token obtained from %s", token_url)

    def _auth_headers(self, session: Any) -> None:
        headers = self._config.get('custom_headers', {})
        session.headers.update(headers)
        logger.info("Configured custom header authentication (%d header(s))", len(headers))

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def refresh_session(self) -> Any:
        """Force re-authentication and return a fresh session."""
        self._session = None
        return self.get_session()

    @property
    def is_configured(self) -> bool:
        """Return True if an auth_type has been configured."""
        return bool(self._config.get('auth_type'))
