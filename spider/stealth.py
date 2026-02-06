"""
Stealth utilities for spider to avoid detection
"""
import random
import time
from typing import Dict, Optional


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


def create_stealth_session(target, verify_ssl=False):
    """
    Create a stealth session based on target configuration
    
    Args:
        target: SpiderTarget instance
        verify_ssl: Verify SSL certificates
        
    Returns:
        StealthSession instance
    """
    return StealthSession(
        enable_stealth=target.enable_stealth_mode,
        use_random_user_agents=target.use_random_user_agents,
        delay_min=target.stealth_delay_min,
        delay_max=target.stealth_delay_max,
        verify_ssl=verify_ssl,
        timeout=target.request_timeout
    )
