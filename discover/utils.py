"""
Utility functions for OSINT data collection from various sources.
"""
import requests
from urllib.parse import urlparse
from django.conf import settings


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
    
    try:
        # Try using waybackpy if available
        try:
            from waybackpy import WaybackMachineCDXServerAPI
            
            domain = extract_domain(target)
            user_agent = "Mozilla/5.0 (compatible; DiscoverOSINT/1.0)"
            
            cdx_api = WaybackMachineCDXServerAPI(domain, user_agent)
            snapshots = cdx_api.snapshots()
            
            urls = []
            count = 0
            for snapshot in snapshots:
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
            # Fallback to CDX API directly
            domain = extract_domain(target)
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}"
            
            response = requests.get(url, timeout=10)
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
            
    except Exception as e:
        results['error'] = str(e)
    
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
        url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={api_key}"
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        ip_data = response.json()
        
        if ip_data and domain in ip_data:
            ip = ip_data[domain]
            
            # Get host information
            host_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            host_response = requests.get(host_url, timeout=10)
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
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        
        response = requests.get(url, timeout=10)
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
