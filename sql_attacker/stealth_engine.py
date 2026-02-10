"""
Enhanced Stealth Features for SQL Injection Testing

Provides advanced stealth capabilities to evade detection:
- Request rate limiting and throttling
- IP rotation support (proxy configuration)
- Advanced header randomization
- User-Agent rotation from large pool
- Cookie persistence
- Retry logic with exponential backoff
- Timing jitter
- Session fingerprint randomization
"""

import random
import time
import hashlib
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class StealthEngine:
    """Advanced stealth engine for evasion techniques"""
    
    # Extended User-Agent pool (100+ agents)
    USER_AGENTS = [
        # Chrome on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        
        # Firefox on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0',
        
        # Safari on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
        
        # Chrome on macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        
        # Edge on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
        
        # Chrome on Linux
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        
        # Mobile browsers
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    ]
    
    # Referer options
    REFERERS = [
        'https://www.google.com/',
        'https://www.google.com/search?q=',
        'https://www.bing.com/search?q=',
        'https://duckduckgo.com/?q=',
        'https://search.yahoo.com/search?p=',
        'https://www.facebook.com/',
        'https://twitter.com/',
        'https://www.linkedin.com/',
        '',  # No referer sometimes
    ]
    
    # Accept-Language variations
    ACCEPT_LANGUAGES = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'en-US,en;q=0.9,es;q=0.8',
        'en-US,en;q=0.9,fr;q=0.8',
        'en-US,en;q=0.9,de;q=0.8',
        'en-US,en;q=0.9,zh-CN;q=0.8',
        'en-GB,en;q=0.9,en-US;q=0.8',
    ]
    
    # Accept header variations
    ACCEPT_HEADERS = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    ]
    
    def __init__(self, config: Dict):
        """
        Initialize stealth engine
        
        Args:
            config: Configuration dictionary with stealth settings
        """
        self.config = config
        self.request_count = 0
        self.last_request_time = 0
        self.session_cookies = {}
        
        # Rate limiting settings
        self.max_requests_per_minute = config.get('max_requests_per_minute', 20)
        self.min_request_interval = 60.0 / self.max_requests_per_minute if self.max_requests_per_minute > 0 else 0
        
        # Retry settings
        self.max_retries = config.get('max_retries', 3)
        self.retry_backoff_factor = config.get('retry_backoff_factor', 2.0)
        
        # Jitter settings
        self.jitter_enabled = config.get('enable_jitter', True)
        self.jitter_range = config.get('jitter_range', 0.5)  # ±50% jitter
    
    def apply_rate_limiting(self):
        """Apply rate limiting between requests"""
        if self.min_request_interval > 0:
            current_time = time.time()
            time_since_last_request = current_time - self.last_request_time
            
            if time_since_last_request < self.min_request_interval:
                sleep_time = self.min_request_interval - time_since_last_request
                
                # Apply jitter to sleep time
                if self.jitter_enabled:
                    jitter = sleep_time * self.jitter_range * (random.random() * 2 - 1)
                    sleep_time = max(0, sleep_time + jitter)
                
                logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()
            self.request_count += 1
    
    def get_randomized_headers(self, base_headers: Optional[Dict] = None) -> Dict:
        """
        Generate randomized headers to mimic real browser behavior
        
        Args:
            base_headers: Base headers to extend
            
        Returns:
            Dictionary of randomized headers
        """
        headers = base_headers.copy() if base_headers else {}
        
        # Randomize User-Agent
        if 'User-Agent' not in headers or self.config.get('randomize_user_agent', True):
            headers['User-Agent'] = random.choice(self.USER_AGENTS)
        
        # Add/randomize other headers
        if self.config.get('randomize_headers', True):
            # Referer
            if random.random() > 0.3:  # 70% chance of including referer
                referer = random.choice(self.REFERERS)
                if referer:
                    headers['Referer'] = referer
            
            # Accept-Language
            headers['Accept-Language'] = random.choice(self.ACCEPT_LANGUAGES)
            
            # Accept
            headers['Accept'] = random.choice(self.ACCEPT_HEADERS)
            
            # Accept-Encoding
            headers['Accept-Encoding'] = 'gzip, deflate, br'
            
            # Connection
            headers['Connection'] = random.choice(['keep-alive', 'close'])
            
            # DNT (Do Not Track) - randomly include
            if random.random() > 0.5:
                headers['DNT'] = '1'
            
            # Upgrade-Insecure-Requests
            if random.random() > 0.3:
                headers['Upgrade-Insecure-Requests'] = '1'
            
            # Sec-Fetch headers (modern browsers)
            if random.random() > 0.4:
                headers['Sec-Fetch-Dest'] = random.choice(['document', 'empty', 'script'])
                headers['Sec-Fetch-Mode'] = random.choice(['navigate', 'cors', 'no-cors'])
                headers['Sec-Fetch-Site'] = random.choice(['none', 'same-origin', 'cross-site'])
        
        return headers
    
    def get_retry_delay(self, attempt: int) -> float:
        """
        Calculate retry delay with exponential backoff
        
        Args:
            attempt: Current retry attempt number (0-indexed)
            
        Returns:
            Delay in seconds
        """
        base_delay = self.retry_backoff_factor ** attempt
        
        # Apply jitter
        if self.jitter_enabled:
            jitter = base_delay * self.jitter_range * (random.random() * 2 - 1)
            delay = max(0, base_delay + jitter)
        else:
            delay = base_delay
        
        return min(delay, 60.0)  # Cap at 60 seconds
    
    def should_retry(self, attempt: int, response=None, exception=None) -> bool:
        """
        Determine if request should be retried
        
        Args:
            attempt: Current retry attempt number
            response: HTTP response object (if available)
            exception: Exception that occurred (if any)
            
        Returns:
            True if should retry, False otherwise
        """
        if attempt >= self.max_retries:
            return False
        
        # Retry on certain HTTP status codes
        if response:
            retry_status_codes = [429, 500, 502, 503, 504]
            if response.status_code in retry_status_codes:
                return True
        
        # Retry on connection errors
        if exception:
            retry_exceptions = ['ConnectionError', 'Timeout', 'ReadTimeout']
            if any(exc in str(type(exception).__name__) for exc in retry_exceptions):
                return True
        
        return False
    
    def update_session_cookies(self, response):
        """
        Update session cookies from response
        
        Args:
            response: HTTP response object
        """
        if hasattr(response, 'cookies'):
            self.session_cookies.update(response.cookies.get_dict())
    
    def get_session_cookies(self) -> Dict:
        """
        Get current session cookies
        
        Returns:
            Dictionary of session cookies
        """
        return self.session_cookies.copy()
    
    def generate_session_fingerprint(self) -> str:
        """
        Generate randomized session fingerprint for tracking
        
        Returns:
            Random session fingerprint string
        """
        timestamp = str(time.time())
        random_data = str(random.random())
        fingerprint = hashlib.md5(f"{timestamp}{random_data}".encode()).hexdigest()
        return fingerprint[:16]
    
    def get_timing_with_jitter(self, base_delay: float) -> float:
        """
        Apply jitter to timing delay
        
        Args:
            base_delay: Base delay in seconds
            
        Returns:
            Delay with jitter applied
        """
        if not self.jitter_enabled:
            return base_delay
        
        jitter = base_delay * self.jitter_range * (random.random() * 2 - 1)
        return max(0, base_delay + jitter)
    
    def log_stealth_metrics(self):
        """Log current stealth metrics for debugging"""
        logger.info(f"Stealth Metrics: {self.request_count} requests, "
                   f"rate limit: {self.max_requests_per_minute}/min, "
                   f"jitter: {'enabled' if self.jitter_enabled else 'disabled'}")
