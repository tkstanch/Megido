"""
Google Custom Search JSON API integration for automated dork searching.
"""
import requests
import time
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


def is_api_configured():
    """
    Check if Google Custom Search API credentials are configured.
    
    Returns:
        bool: True if both API key and search engine ID are configured
    """
    api_key = getattr(settings, 'GOOGLE_SEARCH_API_KEY', None)
    engine_id = getattr(settings, 'GOOGLE_SEARCH_ENGINE_ID', None)
    return bool(api_key and engine_id)


def search_google(query, num_results=5):
    """
    Execute a Google Custom Search API query.
    
    Args:
        query (str): The search query to execute
        num_results (int): Maximum number of results to return (default: 5)
    
    Returns:
        dict: Search results with the following structure:
            {
                'success': bool,
                'results': list of dicts with 'title', 'url', 'snippet',
                'result_count': int,
                'error': str or None
            }
    """
    result = {
        'success': False,
        'results': [],
        'result_count': 0,
        'error': None
    }
    
    # Check if API is configured
    if not is_api_configured():
        result['error'] = 'API not configured'
        return result
    
    api_key = settings.GOOGLE_SEARCH_API_KEY
    engine_id = settings.GOOGLE_SEARCH_ENGINE_ID
    
    # API endpoint
    url = 'https://www.googleapis.com/customsearch/v1'
    
    # Parameters
    params = {
        'key': api_key,
        'cx': engine_id,
        'q': query,
        'num': min(num_results, 10)  # API max is 10 per request
    }
    
    try:
        # Make API request with timeout
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        # Parse results
        if 'items' in data:
            for item in data['items']:
                result['results'].append({
                    'title': item.get('title', ''),
                    'url': item.get('link', ''),
                    'snippet': item.get('snippet', '')
                })
            
            result['result_count'] = len(result['results'])
            result['success'] = True
        else:
            # No results found
            result['success'] = True
            result['result_count'] = 0
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            result['error'] = 'API quota exceeded'
            logger.warning(f"Google API quota exceeded for query: {query[:50]}")
        elif e.response.status_code == 400:
            result['error'] = 'Invalid query'
            logger.error(f"Invalid query for Google API: {query[:50]}")
        elif e.response.status_code == 403:
            result['error'] = 'Invalid API key or permission denied'
            logger.error("Google API returned 403 - check API key and permissions")
        else:
            result['error'] = f'API error: {e.response.status_code}'
            logger.error(f"Google API HTTP error {e.response.status_code}: {str(e)}")
    except requests.exceptions.Timeout:
        result['error'] = 'Request timeout'
        logger.error(f"Timeout while searching Google for query: {query[:50]}")
    except requests.exceptions.RequestException as e:
        result['error'] = 'Network error'
        logger.error(f"Network error while searching Google: {str(e)}")
    except Exception as e:
        result['error'] = 'Unexpected error'
        logger.error(f"Unexpected error in Google search: {str(e)}")
    
    return result


def search_dorks(dork_queries, max_dorks=20, results_per_dork=5, delay=1.0):
    """
    Execute multiple dork queries with rate limiting.
    
    Args:
        dork_queries (dict): Dictionary of categorized dork queries from generate_dorks_for_target()
        max_dorks (int): Maximum number of dorks to search (default: 20)
        results_per_dork (int): Maximum results per dork (default: 5)
        delay (float): Delay in seconds between requests (default: 1.0)
    
    Returns:
        dict: Structured results matching the required format:
            {
                'search_enabled': bool,
                'api_configured': bool,
                'categories': {
                    'category_key': {
                        'name': str,
                        'description': str,
                        'dorks': [
                            {
                                'query': str,
                                'description': str,
                                'results': list,
                                'result_count': int,
                                'error': str or None
                            }
                        ]
                    }
                }
            }
    """
    output = {
        'search_enabled': True,
        'api_configured': is_api_configured(),
        'categories': {}
    }
    
    # If API is not configured, return early
    if not output['api_configured']:
        logger.info("Google Custom Search API not configured - skipping dork search")
        return output
    
    dork_count = 0
    
    # Process each category
    for category_key, category_data in dork_queries.items():
        output['categories'][category_key] = {
            'name': category_data.get('name', ''),
            'description': category_data.get('description', ''),
            'dorks': []
        }
        
        # Process each dork in the category
        for dork in category_data.get('dorks', []):
            if dork_count >= max_dorks:
                logger.info(f"Reached max dorks limit ({max_dorks}), stopping search")
                break
            
            query = dork.get('query', '')
            description = dork.get('description', '')
            
            logger.info(f"Searching dork {dork_count + 1}/{max_dorks}: {description}")
            
            # Execute search
            search_result = search_google(query, num_results=results_per_dork)
            
            # Add to output
            output['categories'][category_key]['dorks'].append({
                'query': query,
                'description': description,
                'results': search_result.get('results', []),
                'result_count': search_result.get('result_count', 0),
                'error': search_result.get('error')
            })
            
            dork_count += 1
            
            # Rate limiting - delay between requests
            if dork_count < max_dorks and delay > 0:
                time.sleep(delay)
        
        # Break outer loop if we've hit the limit
        if dork_count >= max_dorks:
            break
    
    logger.info(f"Completed searching {dork_count} dorks")
    return output
