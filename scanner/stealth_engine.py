"""
Stealth Engine for Vulnerability Scanner

This module provides advanced stealth features to help scanners evade detection
and mimic real browser traffic patterns. Features include:

- Randomized User-Agent rotation with authentic browser profiles
- HTTP header randomization and variation
- Request timing with jitter and randomized delays
- Session rotation (cookies, identifiers)
- Parameter order randomization
- Payload encoding variations

Usage:
    from scanner.stealth_engine import StealthEngine
    
    stealth = StealthEngine()
    headers = stealth.get_randomized_headers()
    delay = stealth.get_request_delay()
    
    # Use stealth features in requests
    response = requests.get(url, headers=headers)
    time.sleep(delay)
"""

import random
import time
import hashlib
import uuid
import string
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import logging

logger = logging.getLogger(__name__)


class StealthEngine:
    """
    Advanced stealth engine for vulnerability scanners.
    
    Provides methods to randomize and vary request patterns to evade
    detection systems and appear more like legitimate browser traffic.
    """
    
    # Comprehensive list of real browser User-Agents
    USER_AGENTS = [
        # Chrome on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        
        # Chrome on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        
        # Firefox on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0',
        
        # Firefox on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:120.0) Gecko/20100101 Firefox/120.0',
        
        # Safari on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        
        # Edge on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
        
        # Chrome on Linux
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        
        # Firefox on Linux
        'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    ]
    
    # Accept header variations
    ACCEPT_HEADERS = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    ]
    
    # Accept-Language header variations
    ACCEPT_LANGUAGE_HEADERS = [
        'en-US,en;q=0.9',
        'en-US,en;q=0.9,es;q=0.8',
        'en-GB,en;q=0.9,en-US;q=0.8',
        'en-US,en;q=0.8',
        'en,en-US;q=0.9',
        'en-US',
    ]
    
    # Accept-Encoding header variations
    ACCEPT_ENCODING_HEADERS = [
        'gzip, deflate, br',
        'gzip, deflate',
        'gzip, deflate, br, zstd',
    ]
    
    def __init__(self, 
                 min_delay: float = 0.5,
                 max_delay: float = 3.0,
                 jitter_range: float = 0.5,
                 enable_session_rotation: bool = True):
        """
        Initialize the stealth engine.
        
        Args:
            min_delay: Minimum delay between requests (seconds)
            max_delay: Maximum delay between requests (seconds)
            jitter_range: Random jitter to add (+/- seconds)
            enable_session_rotation: Whether to rotate session identifiers
        """
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.jitter_range = jitter_range
        self.enable_session_rotation = enable_session_rotation
        
        # Session state
        self.current_session_id = self._generate_session_id()
        self.request_count = 0
        self.last_request_time = 0
        
        logger.debug(f"StealthEngine initialized (delays: {min_delay}-{max_delay}s, session_rotation: {enable_session_rotation})")
    
    def get_randomized_headers(self, base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Generate randomized HTTP headers that mimic real browser traffic.
        
        Args:
            base_headers: Optional base headers to merge with randomized ones
        
        Returns:
            Dictionary of HTTP headers
        """
        headers = base_headers.copy() if base_headers else {}
        
        # Randomize User-Agent
        headers['User-Agent'] = random.choice(self.USER_AGENTS)
        
        # Randomize Accept headers
        headers['Accept'] = random.choice(self.ACCEPT_HEADERS)
        headers['Accept-Language'] = random.choice(self.ACCEPT_LANGUAGE_HEADERS)
        headers['Accept-Encoding'] = random.choice(self.ACCEPT_ENCODING_HEADERS)
        
        # Add realistic browser headers
        if random.random() > 0.3:  # 70% of the time
            headers['DNT'] = random.choice(['1', '0'])
        
        if random.random() > 0.2:  # 80% of the time
            headers['Upgrade-Insecure-Requests'] = '1'
        
        # Sec-Fetch headers (Chrome/Edge)
        if 'Chrome' in headers['User-Agent'] or 'Edg' in headers['User-Agent']:
            headers['Sec-Fetch-Dest'] = random.choice(['document', 'empty', 'script'])
            headers['Sec-Fetch-Mode'] = random.choice(['navigate', 'cors', 'no-cors'])
            headers['Sec-Fetch-Site'] = random.choice(['none', 'same-origin', 'cross-site'])
            if random.random() > 0.5:
                headers['Sec-Fetch-User'] = '?1'
        
        # Sec-CH-UA headers (Chromium-based)
        if 'Chrome' in headers['User-Agent'] or 'Edg' in headers['User-Agent']:
            if random.random() > 0.4:
                version = headers['User-Agent'].split('Chrome/')[1].split('.')[0]
                headers['Sec-CH-UA'] = f'"Chromium";v="{version}", "Not_A Brand";v="8"'
                headers['Sec-CH-UA-Mobile'] = '?0'
                headers['Sec-CH-UA-Platform'] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
        
        # Connection header
        headers['Connection'] = random.choice(['keep-alive', 'close']) if random.random() > 0.8 else 'keep-alive'
        
        self.request_count += 1
        logger.debug(f"Generated randomized headers (request #{self.request_count})")
        
        return headers
    
    def get_request_delay(self, force_delay: bool = False) -> float:
        """
        Calculate delay before next request with jitter.
        
        Args:
            force_delay: If True, always apply delay regardless of timing
        
        Returns:
            Delay in seconds
        """
        base_delay = random.uniform(self.min_delay, self.max_delay)
        jitter = random.uniform(-self.jitter_range, self.jitter_range)
        total_delay = max(0.1, base_delay + jitter)  # Minimum 0.1s
        
        # If not forcing, check if enough time has passed since last request
        if not force_delay:
            time_since_last = time.time() - self.last_request_time
            if time_since_last < total_delay:
                total_delay = max(0, total_delay - time_since_last)
        
        self.last_request_time = time.time() + total_delay
        
        logger.debug(f"Request delay: {total_delay:.2f}s")
        return total_delay
    
    def wait_before_request(self, force_delay: bool = False) -> None:
        """
        Wait appropriate time before making next request.
        
        Args:
            force_delay: If True, always apply delay regardless of timing
        """
        delay = self.get_request_delay(force_delay)
        if delay > 0:
            time.sleep(delay)
    
    def randomize_parameter_order(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize the order of URL parameters.
        
        Args:
            params: Dictionary of parameters
        
        Returns:
            New dictionary with randomized order
        """
        items = list(params.items())
        random.shuffle(items)
        return dict(items)
    
    def randomize_url_parameters(self, url: str) -> str:
        """
        Randomize the order of parameters in a URL.
        
        Args:
            url: URL with query parameters
        
        Returns:
            URL with randomized parameter order
        """
        parsed = urlparse(url)
        
        if not parsed.query:
            return url
        
        # Parse query parameters
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Flatten to single values (take first if multiple)
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        
        # Randomize order
        randomized = self.randomize_parameter_order(flat_params)
        
        # Rebuild URL
        new_query = urlencode(randomized)
        new_parsed = parsed._replace(query=new_query)
        
        return urlunparse(new_parsed)
    
    def rotate_session(self) -> str:
        """
        Rotate the session identifier.
        
        Returns:
            New session ID
        """
        if self.enable_session_rotation:
            self.current_session_id = self._generate_session_id()
            logger.debug(f"Rotated session ID: {self.current_session_id[:8]}...")
        
        return self.current_session_id
    
    def get_session_cookies(self, domain: str = '') -> Dict[str, str]:
        """
        Generate realistic session cookies.
        
        Args:
            domain: Domain name for context-specific cookies
        
        Returns:
            Dictionary of cookies
        """
        cookies = {}
        
        # Common session cookie names
        session_names = ['PHPSESSID', 'JSESSIONID', 'sessionid', 'session', '_session_id']
        cookie_name = random.choice(session_names)
        
        cookies[cookie_name] = self.current_session_id
        
        # Add some common tracking cookies
        if random.random() > 0.5:
            cookies['_ga'] = f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}"
        
        if random.random() > 0.6:
            cookies['_gid'] = f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}"
        
        if random.random() > 0.7:
            cookies['_gat'] = '1'
        
        return cookies
    
    def encode_payload(self, payload: str, encoding: str = 'auto') -> str:
        """
        Encode payload using various techniques for evasion.
        
        Args:
            payload: Original payload string
            encoding: Encoding type ('url', 'html', 'unicode', 'mixed', 'auto')
        
        Returns:
            Encoded payload
        """
        if encoding == 'auto':
            encoding = random.choice(['url', 'html', 'unicode', 'mixed', 'none'])
        
        if encoding == 'none':
            return payload
        
        elif encoding == 'url':
            # URL encoding
            return ''.join(f'%{ord(c):02x}' if random.random() > 0.3 else c for c in payload)
        
        elif encoding == 'html':
            # HTML entity encoding
            return ''.join(f'&#{ord(c)};' if random.random() > 0.3 else c for c in payload)
        
        elif encoding == 'unicode':
            # Unicode encoding
            return ''.join(f'\\u{ord(c):04x}' if random.random() > 0.3 else c for c in payload)
        
        elif encoding == 'mixed':
            # Mixed encoding
            result = []
            for c in payload:
                rand = random.random()
                if rand > 0.7:
                    result.append(f'%{ord(c):02x}')
                elif rand > 0.4:
                    result.append(f'&#{ord(c)};')
                else:
                    result.append(c)
            return ''.join(result)
        
        return payload
    
    def _generate_session_id(self) -> str:
        """Generate a realistic session identifier."""
        # Mix of different session ID formats
        formats = [
            lambda: hashlib.md5(str(uuid.uuid4()).encode()).hexdigest(),
            lambda: hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32],
            lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            lambda: str(uuid.uuid4()).replace('-', ''),
        ]
        
        return random.choice(formats)()
    
    def get_referer_header(self, current_url: str, previous_url: Optional[str] = None) -> str:
        """
        Generate a realistic Referer header.
        
        Args:
            current_url: Current URL being accessed
            previous_url: Optional previous URL
        
        Returns:
            Referer header value
        """
        if previous_url:
            return previous_url
        
        # Generate a plausible referer from the same domain
        parsed = urlparse(current_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        referers = [
            base_url,
            f"{base_url}/",
            f"{base_url}/index.html",
            f"{base_url}/home",
            f"https://www.google.com/search?q={parsed.netloc}",
        ]
        
        return random.choice(referers)
    
    def should_rotate_session(self, requests_threshold: int = 20) -> bool:
        """
        Determine if session should be rotated based on request count.
        
        Args:
            requests_threshold: Number of requests before considering rotation
        
        Returns:
            True if session should be rotated
        """
        if not self.enable_session_rotation:
            return False
        
        # Rotate with some randomness around the threshold
        if self.request_count >= requests_threshold:
            if random.random() > 0.3:  # 70% chance of rotation
                return True
        
        return False


def get_stealth_engine(config: Optional[Dict[str, Any]] = None) -> StealthEngine:
    """
    Factory function to get a configured StealthEngine instance.
    
    Args:
        config: Optional configuration dictionary with keys:
               - min_delay: Minimum delay between requests
               - max_delay: Maximum delay between requests
               - jitter_range: Jitter range for delays
               - enable_session_rotation: Enable session rotation
    
    Returns:
        Configured StealthEngine instance
    """
    config = config or {}
    
    return StealthEngine(
        min_delay=config.get('min_delay', 0.5),
        max_delay=config.get('max_delay', 3.0),
        jitter_range=config.get('jitter_range', 0.5),
        enable_session_rotation=config.get('enable_session_rotation', True)
    )
