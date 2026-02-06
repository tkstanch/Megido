"""
Utility functions for OSINT data collection from various sources.
"""
import requests
from urllib.parse import urlparse
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def extract_domain(target):
    """
    Extract clean domain from URL or domain string.
    
    Args:
        target (str): URL or domain
    
    Returns:
        str: Clean domain name
    """
    # Remove protocol if present
    if '://' in target:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
    else:
        domain = target.split('/')[0]
    
    return domain


def collect_wayback_urls(target, limit=50):
    """
    Collect historical URLs from Wayback Machine.
    
    Args:
        target (str): Target domain or URL
        limit (int): Maximum number of URLs to retrieve
    
    Returns:
        dict: Results with URLs and metadata
    """
    results = {
        'success': False,
        'urls': [],
        'error': None,
        'guidance': (
            "📚 Historical URLs from Wayback Machine can reveal:\n"
            "• Forgotten/removed pages that may still be accessible\n"
            "• Old endpoints that might still work but lack security updates\n"
            "• Exposed sensitive information from past versions\n"
            "• Changes in site structure and functionality over time\n"
            "• Backup files or development artifacts that were removed"
        )
    }
    
    # Check if Wayback Machine is enabled
    if not getattr(settings, 'ENABLE_WAYBACK_MACHINE', True):
        results['error'] = 'Wayback Machine is disabled in settings (ENABLE_WAYBACK_MACHINE=false)'
        logger.info(f"Wayback Machine disabled for {target}")
        return results
    
    # Get timeout and retry settings
    timeout = getattr(settings, 'WAYBACK_MACHINE_TIMEOUT', 10)
    max_retries = getattr(settings, 'WAYBACK_MACHINE_MAX_RETRIES', 2)
    
    try:
        # Try using waybackpy if available
        try:
            from waybackpy import WaybackMachineCDXServerAPI
            
            domain = extract_domain(target)
            user_agent = "Mozilla/5.0 (compatible; DiscoverOSINT/1.0)"
            
            # Pass max_retries to waybackpy's max_tries parameter
            cdx_api = WaybackMachineCDXServerAPI(
                domain, 
                user_agent,
                max_tries=max_retries
            )
            
            # Iterate snapshots - HTTP requests happen during iteration
            urls = []
            count = 0
            for snapshot in cdx_api.snapshots():
                if count >= limit:
                    break
                urls.append({
                    'url': snapshot.archive_url,
                    'timestamp': snapshot.timestamp,
                    'original': snapshot.original
                })
                count += 1
            
            results['urls'] = urls
            results['success'] = True
            
        except ImportError:
            # Fallback to CDX API directly with timeout
            domain = extract_domain(target)
            url = "http://web.archive.org/cdx/search/cdx"
            params = {
                'url': f"{domain}/*",
                'output': 'json',
                'limit': limit
            }
            
            response = requests.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            
            data = response.json()
            if len(data) > 1:  # First row is headers
                urls = []
                for row in data[1:]:  # Skip header
                    if len(row) >= 3:
                        urls.append({
                            'url': f"http://web.archive.org/web/{row[1]}/{row[2]}",
                            'timestamp': row[1],
                            'original': row[2]
                        })
                results['urls'] = urls
                results['success'] = True
    
    except requests.exceptions.ConnectionError as e:
        error_msg = "Unable to connect to web.archive.org. Check your internet connection or disable Wayback Machine in settings."
        results['error'] = error_msg
        logger.warning(f"Connection error for {target}: {str(e)}")
        
    except requests.exceptions.Timeout as e:
        error_msg = f"Request to web.archive.org timed out after {timeout} seconds. Check your network or increase WAYBACK_MACHINE_TIMEOUT."
        results['error'] = error_msg
        logger.warning(f"Timeout error for {target}: {str(e)}")
    
    except Exception as e:
        error_msg = f"Error accessing Wayback Machine: {str(e)}"
        results['error'] = error_msg
        logger.error(f"Unexpected error for {target}: {str(e)}")
    
    return results


def collect_shodan_data(target):
    """
    Collect information from Shodan API.
    
    Args:
        target (str): Target domain or IP
    
    Returns:
        dict: Shodan results and metadata
    """
    results = {
        'success': False,
        'data': {},
        'error': None,
        'guidance': (
            "🔍 Shodan data reveals:\n"
            "• Open ports and services running on the target\n"
            "• Banners and version information (useful for CVE research)\n"
            "• SSL/TLS certificate details\n"
            "• Geographic location of servers\n"
            "• Related hosts and domains\n"
            "• Historical service data"
        )
    }
    
    api_key = getattr(settings, 'SHODAN_API_KEY', None)
    
    if not api_key:
        results['error'] = "Shodan API key not configured in settings"
        return results
    
    try:
        domain = extract_domain(target)
        
        # Resolve domain to IP
        resolve_url = "https://api.shodan.io/dns/resolve"
        resolve_params = {
            'hostnames': domain,
            'key': api_key
        }
        
        response = requests.get(resolve_url, params=resolve_params, timeout=10)
        response.raise_for_status()
        
        ip_data = response.json()
        
        if ip_data and domain in ip_data:
            ip = ip_data[domain]
            
            # Get host information
            host_url = f"https://api.shodan.io/shodan/host/{ip}"
            host_params = {'key': api_key}
            host_response = requests.get(host_url, params=host_params, timeout=10)
            host_response.raise_for_status()
            
            results['data'] = host_response.json()
            results['success'] = True
        else:
            results['error'] = "Could not resolve domain to IP"
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            results['error'] = "Invalid Shodan API key"
        else:
            results['error'] = f"Shodan API error: {str(e)}"
    except Exception as e:
        results['error'] = str(e)
    
    return results


def collect_hunter_emails(target):
    """
    Collect email addresses from Hunter.io API.
    
    Args:
        target (str): Target domain
    
    Returns:
        dict: Email addresses and metadata
    """
    results = {
        'success': False,
        'emails': [],
        'data': {},
        'error': None,
        'guidance': (
            "📧 Email addresses can be used for:\n"
            "• Social engineering and phishing campaigns (ethical testing only)\n"
            "• Identifying key personnel and organizational structure\n"
            "• Password reset enumeration testing\n"
            "• Correlating with data breaches (HaveIBeenPwned)\n"
            "• Building contact lists for security disclosures\n"
            "• Understanding email format patterns"
        )
    }
    
    api_key = getattr(settings, 'HUNTER_IO_KEY', None)
    
    if not api_key:
        results['error'] = "Hunter.io API key not configured in settings"
        return results
    
    try:
        domain = extract_domain(target)
        url = "https://api.hunter.io/v2/domain-search"
        params = {
            'domain': domain,
            'api_key': api_key
        }
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if 'data' in data:
            results['data'] = data['data']
            
            if 'emails' in data['data']:
                results['emails'] = [
                    {
                        'email': email.get('value'),
                        'first_name': email.get('first_name'),
                        'last_name': email.get('last_name'),
                        'position': email.get('position'),
                        'confidence': email.get('confidence')
                    }
                    for email in data['data']['emails']
                ]
            
            results['success'] = True
        else:
            results['error'] = "No data returned from Hunter.io"
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            results['error'] = "Invalid Hunter.io API key"
        else:
            results['error'] = f"Hunter.io API error: {str(e)}"
    except Exception as e:
        results['error'] = str(e)
    
    return results


def group_results(wayback_results, shodan_results, hunter_results, dork_queries):
    """
    Group and organize all results with guidance.
    
    Args:
        wayback_results (dict): Wayback Machine results
        shodan_results (dict): Shodan results
        hunter_results (dict): Hunter.io results
        dork_queries (dict): Google Dorks queries
    
    Returns:
        dict: Grouped results with guidance
    """
    grouped = {
        'wayback_machine': {
            'title': '📚 Wayback Machine - Historical URLs',
            'success': wayback_results['success'],
            'count': len(wayback_results.get('urls', [])),
            'data': wayback_results.get('urls', []),
            'error': wayback_results.get('error'),
            'guidance': wayback_results.get('guidance', '')
        },
        'shodan': {
            'title': '🔍 Shodan - Infrastructure Data',
            'success': shodan_results['success'],
            'data': shodan_results.get('data', {}),
            'error': shodan_results.get('error'),
            'guidance': shodan_results.get('guidance', '')
        },
        'hunter': {
            'title': '📧 Hunter.io - Email Addresses',
            'success': hunter_results['success'],
            'count': len(hunter_results.get('emails', [])),
            'data': hunter_results.get('emails', []),
            'error': hunter_results.get('error'),
            'guidance': hunter_results.get('guidance', '')
        },
        'google_dorks': {
            'title': '🔎 Google Dorks - Search Queries',
            'success': True,
            'data': dork_queries,
            'guidance': (
                "🔎 Google Dorks help find:\n"
                "• Exposed sensitive files and documents\n"
                "• Configuration files with credentials\n"
                "• Directory listings and exposed directories\n"
                "• Error messages revealing system details\n"
                "• Login pages and admin interfaces\n"
                "• Database dumps and backup files\n\n"
                "💡 Usage: Copy each query and search on Google. "
                "Review results for sensitive information disclosure."
            )
        }
    }
    
    return grouped


def search_google_dorks(target, dork_queries):
    """
    Search Google Dorks using Google Custom Search API.
    
    Args:
        target (str): Target domain (not used in search, but for logging)
        dork_queries (dict): Dictionary of categorized dork queries
    
    Returns:
        dict: Structured data with search results organized by category
    """
    try:
        from .google_search import search_dorks, is_api_configured
        
        # Check if API is configured
        if not is_api_configured():
            logger.info(f"Google Custom Search API not configured for target {target}")
            return {
                'search_enabled': False,
                'api_configured': False,
                'categories': {}
            }
        
        # Execute searches with rate limiting
        # Limit to 20 dorks, 5 results per dork, 1 second delay between requests
        logger.info(f"Starting automated Google Dorks search for target {target}")
        results = search_dorks(
            dork_queries, 
            max_dorks=20, 
            results_per_dork=5, 
            delay=1.0
        )
        
        logger.info(f"Completed Google Dorks search for target {target}")
        return results
        
    except Exception as e:
        logger.error(f"Error in search_google_dorks: {str(e)}")
        return {
            'search_enabled': False,
            'api_configured': False,
            'categories': {},
            'error': str(e)
        }
