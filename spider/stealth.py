"""
Stealth utilities for spider to avoid detection
"""
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Maximum adaptive delay caps for AdaptiveStealthSession to prevent unbounded escalation
MAX_DELAY_MIN = 10.0  # seconds
MAX_DELAY_MAX = 15.0  # seconds


# List of realistic browser user agents
USER_AGENTS = [
    # Chrome on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    
    # Chrome on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    
    # Firefox on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0',
    
    # Firefox on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
    
    # Safari on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    
    # Edge on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    
    # Chrome on Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
]


ACCEPT_LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'en-US,en;q=0.9,es;q=0.8',
    'en-US,en;q=0.9,fr;q=0.8',
]


class StealthSession:
    """
    A stealth-aware requests session that rotates user agents and adds realistic headers
    """
    
    def __init__(self, enable_stealth=True, use_random_user_agents=True, 
                 delay_min=1.0, delay_max=3.0, verify_ssl=False, timeout=30):
        """
        Initialize stealth session
        
        Args:
            enable_stealth: Enable stealth features
            use_random_user_agents: Rotate user agents
            delay_min: Minimum delay between requests in seconds
            delay_max: Maximum delay between requests in seconds
            verify_ssl: Verify SSL certificates
            timeout: Default request timeout in seconds
        """
        import requests
        self.session = requests.Session()
        self.enable_stealth = enable_stealth
        self.use_random_user_agents = use_random_user_agents
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.last_request_time = 0
        self.request_count = 0
        self.referer = None
        
    def get_random_user_agent(self) -> str:
        """Get a random user agent from the list"""
        return random.choice(USER_AGENTS)
    
    def get_stealth_headers(self, referer: Optional[str] = None) -> Dict[str, str]:
        """
        Generate realistic browser headers
        
        Args:
            referer: Optional referer URL
            
        Returns:
            Dictionary of HTTP headers
        """
        headers = {}
        
        if self.enable_stealth:
            # User-Agent
            if self.use_random_user_agents:
                headers['User-Agent'] = self.get_random_user_agent()
            else:
                # Use a common user agent
                headers['User-Agent'] = USER_AGENTS[0]
            
            # Common browser headers
            headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
            headers['Accept-Language'] = random.choice(ACCEPT_LANGUAGES)
            headers['Accept-Encoding'] = 'gzip, deflate, br'
            headers['DNT'] = '1'
            headers['Connection'] = 'keep-alive'
            headers['Upgrade-Insecure-Requests'] = '1'
            headers['Sec-Fetch-Dest'] = 'document'
            headers['Sec-Fetch-Mode'] = 'navigate'
            headers['Sec-Fetch-Site'] = 'none' if not referer else 'same-origin'
            headers['Sec-Fetch-User'] = '?1'
            headers['Cache-Control'] = 'max-age=0'
            
            # Add referer if provided
            if referer:
                headers['Referer'] = referer
        
        return headers
    
    def apply_delay(self):
        """Apply intelligent delay between requests"""
        if not self.enable_stealth:
            return
        
        # Calculate time since last request
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if self.last_request_time > 0:
            # Random delay between min and max
            delay = random.uniform(self.delay_min, self.delay_max)
            
            # Add some randomness to avoid patterns
            # Occasionally add a longer delay (10% chance)
            if random.random() < 0.1:
                delay *= random.uniform(1.5, 2.5)
            
            # Apply delay if needed
            if time_since_last < delay:
                time.sleep(delay - time_since_last)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def get(self, url, **kwargs):
        """Make a GET request with stealth features"""
        self.apply_delay()
        
        # Merge stealth headers with any provided headers
        headers = self.get_stealth_headers(referer=self.referer)
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # Set verify_ssl if not provided
        if 'verify' not in kwargs:
            kwargs['verify'] = self.verify_ssl
        
        # Make request
        response = self.session.get(url, **kwargs)
        
        # Update referer for next request
        self.referer = url
        
        return response
    
    def post(self, url, **kwargs):
        """Make a POST request with stealth features"""
        self.apply_delay()
        
        # Merge stealth headers with any provided headers
        headers = self.get_stealth_headers(referer=self.referer)
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # Set verify_ssl if not provided
        if 'verify' not in kwargs:
            kwargs['verify'] = self.verify_ssl
        
        # Make request
        response = self.session.post(url, **kwargs)
        
        # Update referer for next request
        self.referer = url
        
        return response
    
    def request(self, method, url, **kwargs):
        """Make a request with any HTTP method with stealth features"""
        self.apply_delay()
        
        # Merge stealth headers with any provided headers
        headers = self.get_stealth_headers(referer=self.referer)
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # Set verify_ssl if not provided
        if 'verify' not in kwargs:
            kwargs['verify'] = self.verify_ssl
        
        # Make request
        response = self.session.request(method, url, **kwargs)
        
        # Update referer for next request
        self.referer = url
        
        return response
    
    def options(self, url, **kwargs):
        """Make an OPTIONS request with stealth features"""
        return self.request('OPTIONS', url, **kwargs)
    
    def close(self):
        """Close the session"""
        self.session.close()


@dataclass
class TargetFingerprint:
    """Stores detected characteristics of a target web application"""
    server_type: str = ''               # e.g. 'Apache', 'Nginx', 'IIS', 'Cloudflare'
    has_waf: bool = False               # WAF detected from response headers
    has_rate_limiting: bool = False     # 429 or Retry-After detected
    rate_limit_window: float = 0.0     # seconds from Retry-After header
    uses_captcha: bool = False          # CAPTCHA keywords found in response body
    technology_stack: List[str] = field(default_factory=list)  # X-Powered-By, generators, etc.


def fingerprint_target(url: str, stealth_session: 'StealthSession') -> TargetFingerprint:
    """
    Make an initial request to *url* and analyse the response to build a
    TargetFingerprint.

    Args:
        url: Target URL to fingerprint
        stealth_session: An existing StealthSession used for the request

    Returns:
        TargetFingerprint populated with whatever could be detected
    """
    fp = TargetFingerprint()
    try:
        response = stealth_session.session.get(
            url,
            timeout=stealth_session.timeout,
            verify=stealth_session.verify_ssl,
        )

        headers = response.headers
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # ── Server type ─────────────────────────────────────────────────────
        server_header = headers.get('Server', '')
        fp.server_type = server_header.split('/')[0].strip()

        # ── WAF detection ────────────────────────────────────────────────────
        waf_indicators = [
            'cf-ray',           # Cloudflare
            'x-sucuri-id',      # Sucuri
            'x-waf',            # Generic WAF header
            'x-firewall',
            'x-mod-security',
            'x-shield',
        ]
        if any(ind in lower_headers for ind in waf_indicators):
            fp.has_waf = True
        # Cloudflare can also be detected via Server header
        if 'cloudflare' in server_header.lower():
            fp.has_waf = True

        # ── Rate limiting ────────────────────────────────────────────────────
        if response.status_code == 429 or 'retry-after' in lower_headers:
            fp.has_rate_limiting = True
            retry_after = lower_headers.get('retry-after', '')
            try:
                fp.rate_limit_window = float(retry_after)
            except (ValueError, TypeError):
                fp.rate_limit_window = 0.0

        # ── CAPTCHA detection ────────────────────────────────────────────────
        captcha_keywords = ['captcha', 'recaptcha', 'hcaptcha', 'challenge']
        body_lower = response.text.lower()
        if any(kw in body_lower for kw in captcha_keywords):
            fp.uses_captcha = True

        # ── Technology stack ─────────────────────────────────────────────────
        tech: List[str] = []
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            tech.append(powered_by)
        meta_gen = re.findall(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            response.text,
            _re.IGNORECASE,
        )
        tech.extend(meta_gen)
        fp.technology_stack = tech

        logger.debug(
            "Fingerprinted %s: server=%r waf=%s rate_limit=%s captcha=%s stack=%s",
            url,
            fp.server_type,
            fp.has_waf,
            fp.has_rate_limiting,
            fp.uses_captcha,
            fp.technology_stack,
        )
    except Exception as exc:
        logger.debug("Fingerprinting failed for %s: %s", url, exc)

    return fp


class AdaptiveStealthSession(StealthSession):
    """
    Extends StealthSession with adaptive delay logic based on target behaviour.

    Delays are automatically adjusted:
    - WAF detected          → delays × 2
    - Rate-limiting detected → respect Retry-After; delays × 2
    - No WAF / rate-limit   → delays × 0.5 (faster scanning)
    - 3+ consecutive 429s   → delay range doubled, warning logged
    - 403 after 200s        → delay increased, user-agent rotated
    """

    def __init__(self, target_url: str, **kwargs):
        super().__init__(**kwargs)
        self.target_url = target_url

        # Adaptive tracking
        self._consecutive_429: int = 0
        self._consecutive_403: int = 0
        self._had_200: bool = False
        self._fingerprint: Optional[TargetFingerprint] = None

        # Save base delay values so multipliers are applied only once
        self._base_delay_min = self.delay_min
        self._base_delay_max = self.delay_max

        # Run fingerprinting on creation
        self._fingerprint = fingerprint_target(target_url, self)
        self._apply_fingerprint_multipliers()

    @property
    def fingerprint(self) -> Optional[TargetFingerprint]:
        return self._fingerprint

    def _apply_fingerprint_multipliers(self):
        """Adjust delay range once based on the initial fingerprint."""
        if self._fingerprint is None:
            return
        if self._fingerprint.has_waf or self._fingerprint.has_rate_limiting:
            # More defensive: double the delays
            self.delay_min = self._base_delay_min * 2
            self.delay_max = self._base_delay_max * 2
            logger.info(
                "AdaptiveStealth: WAF/rate-limit detected on %s — delays increased to %.1f–%.1f s",
                self.target_url,
                self.delay_min,
                self.delay_max,
            )
        else:
            # No defences detected: halve the delays for faster scanning
            self.delay_min = self._base_delay_min * 0.5
            self.delay_max = self._base_delay_max * 0.5
            logger.info(
                "AdaptiveStealth: No WAF/rate-limit on %s — delays reduced to %.1f–%.1f s",
                self.target_url,
                self.delay_min,
                self.delay_max,
            )

    def apply_delay(self):
        """Override to respect a Retry-After window when rate-limiting was detected."""
        if not self.enable_stealth:
            return

        fp = self._fingerprint
        if fp and fp.has_rate_limiting and fp.rate_limit_window > 0:
            # Ensure we always wait at least rate_limit_window seconds
            self.delay_min = max(self.delay_min, fp.rate_limit_window)
            self.delay_max = max(self.delay_max, fp.rate_limit_window * 1.2)

        super().apply_delay()

    def track_response(self, response) -> None:
        """
        Call this after each request to let the session adapt based on the
        response status code.

        Args:
            response: requests.Response object (or None on error)
        """
        if response is None:
            return

        status = response.status_code

        # ── Track 200 success ───────────────────────────────────────────────
        if status == 200:
            self._had_200 = True
            self._consecutive_429 = 0
            self._consecutive_403 = 0

        # ── Rate limit handling ──────────────────────────────────────────────
        elif status == 429:
            self._consecutive_429 += 1
            self._consecutive_403 = 0

            # Honour Retry-After if present
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    wait = float(retry_after)
                    logger.warning(
                        "AdaptiveStealth: 429 received; waiting Retry-After=%.1f s", wait
                    )
                    time.sleep(wait)
                except (ValueError, TypeError):
                    pass

            if self._consecutive_429 >= 3:
                self.delay_min = min(self.delay_min * 2, MAX_DELAY_MIN)
                self.delay_max = min(self.delay_max * 2, MAX_DELAY_MAX)
                self._consecutive_429 = 0
                logger.warning(
                    "AdaptiveStealth: 3 consecutive 429s on %s — updated delays to %.1f–%.1f s",
                    self.target_url,
                    self.delay_min,
                    self.delay_max,
                )

        # ── Forbidden / blocked handling ─────────────────────────────────────
        elif status == 403 and self._had_200:
            self._consecutive_403 += 1
            self._consecutive_429 = 0

            # Increase delay and rotate UA to try to recover
            self.delay_min = min(self.delay_min * 1.5, MAX_DELAY_MIN)
            self.delay_max = min(self.delay_max * 1.5, MAX_DELAY_MAX)
            logger.warning(
                "AdaptiveStealth: 403 after previous 200s on %s — increasing delays to "
                "%.1f–%.1f s and rotating user-agent",
                self.target_url,
                self.delay_min,
                self.delay_max,
            )
            # Rotate to a new random UA on the next request
            if self.use_random_user_agents:
                self.session.headers.update(
                    {'User-Agent': self.get_random_user_agent()}
                )

        else:
            self._consecutive_429 = 0
            self._consecutive_403 = 0

    # ── Override HTTP methods to auto-call track_response ───────────────────

    def get(self, url, **kwargs):
        response = super().get(url, **kwargs)
        self.track_response(response)
        return response

    def post(self, url, **kwargs):
        response = super().post(url, **kwargs)
        self.track_response(response)
        return response

    def request(self, method, url, **kwargs):
        response = super().request(method, url, **kwargs)
        self.track_response(response)
        return response


def create_stealth_session(target, verify_ssl=False, adaptive=True):
    """
    Create a stealth session based on target configuration

    Args:
        target: SpiderTarget instance
        verify_ssl: Verify SSL certificates
        adaptive: When True and target.enable_adaptive_stealth is True,
                  create an AdaptiveStealthSession; otherwise create a plain
                  StealthSession.

    Returns:
        StealthSession or AdaptiveStealthSession instance
    """
    use_adaptive = adaptive and getattr(target, 'enable_adaptive_stealth', False)

    if use_adaptive:
        return AdaptiveStealthSession(
            target_url=target.url,
            enable_stealth=target.enable_stealth_mode,
            use_random_user_agents=target.use_random_user_agents,
            delay_min=target.stealth_delay_min,
            delay_max=target.stealth_delay_max,
            verify_ssl=verify_ssl,
            timeout=target.request_timeout,
        )

    return StealthSession(
        enable_stealth=target.enable_stealth_mode,
        use_random_user_agents=target.use_random_user_agents,
        delay_min=target.stealth_delay_min,
        delay_max=target.stealth_delay_max,
        verify_ssl=verify_ssl,
        timeout=target.request_timeout
    )
