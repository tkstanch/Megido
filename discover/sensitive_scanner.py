"""
Sensitive Information Scanner Module

This module scans URLs for sensitive information including API keys, tokens, 
credentials, and other potentially exposed data.

SECURITY NOTE: SSL verification is disabled (verify=False) to facilitate 
security testing. This should only be used in controlled testing environments.
"""

import re
import requests
from urllib.parse import urlparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import urllib3

# Configure logging
logger = logging.getLogger(__name__)

# Disable SSL warnings since we're intentionally bypassing SSL verification for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SensitivePatterns:
    """
    Defines regex patterns for detecting sensitive information.
    """
    
    # API Keys
    AWS_KEY = r'AKIA[0-9A-Z]{16}'
    GITHUB_TOKEN = r'ghp_[0-9a-zA-Z]{36}'
    GITHUB_OAUTH = r'gho_[0-9a-zA-Z]{36}'
    SLACK_TOKEN = r'xox[baprs]-[0-9a-zA-Z]{10,48}'
    SLACK_WEBHOOK = r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+'
    STRIPE_KEY = r'sk_live_[0-9a-zA-Z]{24,}'
    GOOGLE_API = r'AIza[0-9A-Za-z\-_]{35}'
    
    # Tokens and Secrets
    GENERIC_SECRET = r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    GENERIC_API_KEY = r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    BEARER_TOKEN = r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*'
    
    # Private Keys and Certificates
    PRIVATE_KEY = r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
    SSH_PRIVATE_KEY = r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'
    PGP_PRIVATE_KEY = r'-----BEGIN PGP PRIVATE KEY BLOCK-----'
    
    # Database Connection Strings
    MYSQL_CONN = r'mysql://[^:]+:[^@]+@[^/]+/\w+'
    POSTGRES_CONN = r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+'
    MONGODB_CONN = r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+'
    
    # Passwords and Credentials
    PASSWORD_FIELD = r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{3,})["\']'
    USERNAME_PASSWORD = r'(?:user|username|login)["\']?\s*[:=]\s*["\']([^"\']+)["\'].*?password["\']?\s*[:=]\s*["\']([^"\']+)["\']'
    
    # Email Addresses
    EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # IP Addresses (Private)
    PRIVATE_IP = r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
    
    # JWT Tokens
    JWT_TOKEN = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
    
    # Credit Card Numbers (basic pattern)
    CREDIT_CARD = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    
    # Social Security Numbers (US)
    SSN = r'\b\d{3}-\d{2}-\d{4}\b'
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, str]:
        """
        Returns all patterns as a dictionary with pattern names and regex.
        """
        return {
            'AWS Access Key': cls.AWS_KEY,
            'GitHub Personal Access Token': cls.GITHUB_TOKEN,
            'GitHub OAuth Token': cls.GITHUB_OAUTH,
            'Slack Token': cls.SLACK_TOKEN,
            'Slack Webhook': cls.SLACK_WEBHOOK,
            'Stripe API Key': cls.STRIPE_KEY,
            'Google API Key': cls.GOOGLE_API,
            'Generic Secret': cls.GENERIC_SECRET,
            'Generic API Key': cls.GENERIC_API_KEY,
            'Bearer Token': cls.BEARER_TOKEN,
            'Private Key': cls.PRIVATE_KEY,
            'SSH Private Key': cls.SSH_PRIVATE_KEY,
            'PGP Private Key': cls.PGP_PRIVATE_KEY,
            'MySQL Connection String': cls.MYSQL_CONN,
            'PostgreSQL Connection String': cls.POSTGRES_CONN,
            'MongoDB Connection String': cls.MONGODB_CONN,
            'Password Field': cls.PASSWORD_FIELD,
            'Username/Password Combo': cls.USERNAME_PASSWORD,
            'Email Address': cls.EMAIL,
            'Private IP Address': cls.PRIVATE_IP,
            'JWT Token': cls.JWT_TOKEN,
            'Credit Card Number': cls.CREDIT_CARD,
            'Social Security Number': cls.SSN,
        }


class SensitiveInfoScanner:
    """
    Scanner class for detecting sensitive information in URLs.
    """
    
    def __init__(self, timeout=10):
        """
        Initialize the scanner.
        
        Args:
            timeout: Request timeout in seconds (default: 10)
        """
        self.timeout = timeout
        self.patterns = SensitivePatterns.get_all_patterns()
    
    @staticmethod
    def luhn_check(card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm (mod 10 check).
        
        Args:
            card_number: The card number to validate (digits only)
            
        Returns:
            True if valid, False otherwise
        """
        # Remove any non-digit characters
        card_number = ''.join(filter(str.isdigit, card_number))
        
        if not card_number:
            return False
        
        # Luhn algorithm
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        
        return checksum % 10 == 0
    
    @staticmethod
    def verify_context_not_numeric_field(context: str, value: str) -> bool:
        """
        Check if the context suggests this is part of a JSON numeric field,
        currency value, or other non-credit-card number.
        
        Args:
            context: The surrounding text
            value: The matched value
            
        Returns:
            True if context looks safe (not a false positive), False otherwise
        """
        # Convert to lowercase for checking
        context_lower = context.lower()
        
        # Check for common false positive indicators
        false_positive_indicators = [
            'usd', 'price', 'amount', 'total', 'cost', 
            'volume', 'sales', '":', '":"', 'native',
            'balance', 'revenue', 'payment', '€', '$', '£'
        ]
        
        for indicator in false_positive_indicators:
            if indicator in context_lower:
                return False
        
        return True
    
    def fetch_url_content(self, url: str) -> str:
        """
        Fetch content from a URL with timeout and error handling.
        
        Args:
            url: The URL to fetch
            
        Returns:
            The content of the URL as a string, or empty string on error
        """
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,  # Disable SSL verification for security testing
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}
            )
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {url}")
            return ""
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching {url}: {e}")
            return ""
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            return ""
    
    def scan_content_for_sensitive_data(self, content: str, url: str) -> List[Dict[str, Any]]:
        """
        Scan content using regex patterns to find sensitive information.
        
        Args:
            content: The content to scan
            url: The URL being scanned (for reference)
            
        Returns:
            List of findings with details
        """
        findings = []
        
        for pattern_name, pattern in self.patterns.items():
            try:
                # Case-insensitive matching
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Get the matched value
                    value = match.group(0)
                    
                    # Extract context (50 chars before and after)
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    
                    # Special validation for credit cards
                    if pattern_name == 'Credit Card Number':
                        # Validate with Luhn algorithm
                        if not self.luhn_check(value):
                            continue  # Skip invalid credit card numbers
                        
                        # Check context to avoid false positives
                        if not self.verify_context_not_numeric_field(context, value):
                            continue  # Skip if it looks like a price/amount
                    
                    findings.append({
                        'type': pattern_name,
                        'value': value,
                        'context': context,
                        'position': match.start(),
                        'url': url
                    })
            except Exception as e:
                logger.error(f"Error scanning for {pattern_name}: {e}")
                continue
        
        return findings
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan a single URL and return findings.
        
        Args:
            url: The URL to scan
            
        Returns:
            Dictionary with URL and findings
        """
        content = self.fetch_url_content(url)
        
        if not content:
            return {
                'url': url,
                'success': False,
                'findings': []
            }
        
        findings = self.scan_content_for_sensitive_data(content, url)
        
        return {
            'url': url,
            'success': True,
            'findings': findings
        }
    
    def scan_urls(self, urls: List[str], max_workers=5) -> List[Dict[str, Any]]:
        """
        Scan multiple URLs concurrently using ThreadPoolExecutor.
        
        Args:
            urls: List of URLs to scan
            max_workers: Maximum number of concurrent workers (default: 5)
            
        Returns:
            List of scan results
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            # Collect results as they complete
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error scanning {url}: {e}")
                    results.append({
                        'url': url,
                        'success': False,
                        'findings': [],
                        'error': str(e)
                    })
        
        return results


def scan_discovered_urls(urls: List[str], max_urls: int = 50) -> Dict[str, Any]:
    """
    Scan discovered URLs for sensitive information.
    
    Args:
        urls: List of URLs to scan
        max_urls: Maximum number of URLs to scan (default: 50)
        
    Returns:
        Dictionary with aggregated findings and statistics
    """
    # Limit URLs to scan
    urls_to_scan = urls[:max_urls]
    
    logger.info(f"Starting sensitive scan for {len(urls_to_scan)} URLs (limited from {len(urls)})")
    
    # Initialize scanner
    scanner = SensitiveInfoScanner(timeout=10)
    
    # Scan URLs concurrently
    scan_results = scanner.scan_urls(urls_to_scan, max_workers=5)
    
    # Aggregate findings by type
    findings_by_type = {}
    all_findings = []
    
    for result in scan_results:
        if result['success'] and result['findings']:
            for finding in result['findings']:
                finding_type = finding['type']
                
                if finding_type not in findings_by_type:
                    findings_by_type[finding_type] = []
                
                findings_by_type[finding_type].append(finding)
                all_findings.append(finding)
    
    # Calculate statistics
    total_findings = len(all_findings)
    total_scanned = len([r for r in scan_results if r['success']])
    total_failed = len([r for r in scan_results if not r['success']])
    
    return {
        'success': True,
        'total_urls_scanned': total_scanned,
        'total_urls_failed': total_failed,
        'total_findings': total_findings,
        'findings_by_type': findings_by_type,
        'all_findings': all_findings,
        'scan_results': scan_results
    }
