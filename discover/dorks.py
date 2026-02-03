"""
Google Dorks library for OSINT and information gathering.
These dorks help find sensitive information, exposed files, and security vulnerabilities.
"""

DORK_CATEGORIES = {
    "files": {
        "name": "Exposed Files",
        "description": "Find exposed sensitive files and documents",
        "dorks": [
            {
                "query": 'site:{target} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx',
                "description": "Find exposed documents (PDF, Word, Excel)"
            },
            {
                "query": 'site:{target} ext:sql | ext:db | ext:dbf | ext:mdb',
                "description": "Find database files"
            },
            {
                "query": 'site:{target} ext:log | ext:txt',
                "description": "Find log files and text documents"
            },
            {
                "query": 'site:{target} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini',
                "description": "Find configuration files"
            },
            {
                "query": 'site:{target} ext:bak | ext:backup | ext:old | ext:temp',
                "description": "Find backup files"
            }
        ]
    },
    "directories": {
        "name": "Directory Listings",
        "description": "Find exposed directory listings and indexes",
        "dorks": [
            {
                "query": 'site:{target} intitle:"index of"',
                "description": "Find directory listings"
            },
            {
                "query": 'site:{target} intitle:"index of" "parent directory"',
                "description": "Find parent directory listings"
            },
            {
                "query": 'site:{target} intitle:"index of" /.git',
                "description": "Find exposed .git directories"
            },
            {
                "query": 'site:{target} intitle:"index of" /backup',
                "description": "Find backup directories"
            }
        ]
    },
    "login_pages": {
        "name": "Login Pages & Authentication",
        "description": "Find login pages and authentication endpoints",
        "dorks": [
            {
                "query": 'site:{target} inurl:login | inurl:signin | inurl:admin',
                "description": "Find login and admin pages"
            },
            {
                "query": 'site:{target} intitle:"Login" | intitle:"Sign In" | intitle:"Admin"',
                "description": "Find pages with login-related titles"
            },
            {
                "query": 'site:{target} inurl:wp-admin | inurl:wp-login',
                "description": "Find WordPress admin pages"
            }
        ]
    },
    "sensitive_info": {
        "name": "Sensitive Information",
        "description": "Find pages containing sensitive information",
        "dorks": [
            {
                "query": 'site:{target} intext:"password" | intext:"passwd" | intext:"pwd"',
                "description": "Find pages mentioning passwords"
            },
            {
                "query": 'site:{target} intext:"api_key" | intext:"apikey" | intext:"api key"',
                "description": "Find pages mentioning API keys"
            },
            {
                "query": 'site:{target} intext:"secret" | intext:"token" | intext:"private key"',
                "description": "Find pages mentioning secrets or tokens"
            },
            {
                "query": 'site:{target} intext:"confidential" | intext:"internal use only"',
                "description": "Find confidential or internal documents"
            }
        ]
    },
    "errors": {
        "name": "Error Messages & Debug Info",
        "description": "Find pages with error messages that may leak information",
        "dorks": [
            {
                "query": 'site:{target} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near"',
                "description": "Find SQL error messages"
            },
            {
                "query": 'site:{target} intext:"Warning: mysql" | intext:"Error: mysqli"',
                "description": "Find MySQL/MySQLi errors"
            },
            {
                "query": 'site:{target} intext:"Fatal error" | intext:"Warning:" | intext:"on line"',
                "description": "Find PHP errors and warnings"
            }
        ]
    },
    "subdomains": {
        "name": "Subdomain Discovery",
        "description": "Find subdomains and related domains",
        "dorks": [
            {
                "query": 'site:*.{target}',
                "description": "Find all subdomains"
            },
            {
                "query": 'site:*.{target} -www',
                "description": "Find subdomains excluding www"
            }
        ]
    }
}


def generate_dorks_for_target(target):
    """
    Generate a list of Google Dork queries for a specific target.
    
    Args:
        target (str): The target domain (e.g., 'example.com')
    
    Returns:
        dict: Dictionary with categorized dork queries
    """
    result = {}
    
    # Clean target - remove protocol if present
    target = target.replace('http://', '').replace('https://', '').split('/')[0]
    
    for category_key, category_data in DORK_CATEGORIES.items():
        result[category_key] = {
            'name': category_data['name'],
            'description': category_data['description'],
            'dorks': []
        }
        
        for dork in category_data['dorks']:
            result[category_key]['dorks'].append({
                'query': dork['query'].format(target=target),
                'description': dork['description']
            })
    
    return result


def get_all_dorks_flat(target):
    """
    Get all dorks for a target as a flat list.
    
    Args:
        target (str): The target domain
    
    Returns:
        list: List of dork dictionaries with query and description
    """
    categorized = generate_dorks_for_target(target)
    all_dorks = []
    
    for category_data in categorized.values():
        all_dorks.extend(category_data['dorks'])
    
    return all_dorks
