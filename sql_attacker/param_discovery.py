"""
Parameter Discovery Engine for SQL Injection Attacker

Automatically discovers all possible parameters from:
- HTML forms (visible and hidden fields)
- Links and URLs on the page
- JavaScript variables and parameters
"""

import re
import logging
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import requests

logger = logging.getLogger(__name__)


class DiscoveredParameter:
    """Represents a discovered parameter"""
    
    def __init__(self, name: str, value: str = '', source: str = 'unknown', 
                 method: str = 'GET', field_type: str = 'text'):
        self.name = name
        self.value = value
        self.source = source  # 'form', 'hidden', 'link', 'js', 'url'
        self.method = method  # 'GET' or 'POST'
        self.field_type = field_type  # 'text', 'hidden', 'password', etc.
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'name': self.name,
            'value': self.value,
            'source': self.source,
            'method': self.method,
            'field_type': self.field_type,
        }
    
    def __repr__(self):
        return f"<DiscoveredParameter {self.name}={self.value} source={self.source}>"


class ParameterDiscoveryEngine:
    """Engine for discovering parameters from web pages"""
    
    # JavaScript patterns for variable extraction
    JS_VAR_PATTERNS = [
        r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\']',  # var name = "value"
        r'let\s+(\w+)\s*=\s*["\']([^"\']+)["\']',  # let name = "value"
        r'const\s+(\w+)\s*=\s*["\']([^"\']+)["\']',  # const name = "value"
        r'(\w+)\s*=\s*["\']([^"\']+)["\']',  # name = "value"
        r'["\'](\w+)["\']\s*:\s*["\']([^"\']+)["\']',  # "name": "value" (JSON)
    ]
    
    # JavaScript patterns for parameter discovery
    JS_PARAM_PATTERNS = [
        r'[\?&](\w+)=',  # ?param= or &param=
        r'\.get\(["\'](\w+)["\']\)',  # .get("param")
        r'\.getParameter\(["\'](\w+)["\']\)',  # .getParameter("param")
        r'params\[["\'](\w+)["\']\]',  # params["param"]
        r'data\[["\'](\w+)["\']\]',  # data["param"]
    ]
    
    def __init__(self, timeout: int = 30, verify_ssl: bool = False):
        """Initialize the discovery engine"""
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
    
    def discover_parameters(self, url: str, method: str = 'GET',
                          headers: Optional[Dict] = None) -> Tuple[Dict, List[DiscoveredParameter]]:
        """
        Discover all parameters from a target URL
        
        Args:
            url: Target URL to analyze
            method: HTTP method to use for fetching
            headers: Optional headers for the request
            
        Returns:
            Tuple of (merged_params_dict, list of DiscoveredParameter objects)
        """
        discovered_params = []
        
        try:
            # Fetch the target page
            response = self.session.get(
                url, 
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            if response.status_code != 200:
                logger.warning(f"Non-200 status code: {response.status_code}")
                return {}, []
            
            html_content = response.text
            
            # Parse HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Discover parameters from various sources
            discovered_params.extend(self._discover_from_forms(soup))
            discovered_params.extend(self._discover_from_links(soup, url))
            discovered_params.extend(self._discover_from_scripts(soup, url))
            discovered_params.extend(self._discover_from_inline_js(soup))
            discovered_params.extend(self._discover_from_url(url))
            
            # Remove duplicates (keep first occurrence)
            unique_params = self._deduplicate_parameters(discovered_params)
            
            # Create merged parameter dictionary
            merged_params = self._create_merged_params(unique_params)
            
            logger.info(f"Discovered {len(unique_params)} unique parameters from {url}")
            
            return merged_params, unique_params
            
        except Exception as e:
            logger.error(f"Error discovering parameters from {url}: {e}", exc_info=True)
            return {}, []
    
    def _discover_from_forms(self, soup: BeautifulSoup) -> List[DiscoveredParameter]:
        """Discover parameters from HTML forms"""
        params = []
        
        # Find all forms
        forms = soup.find_all('form')
        
        for form in forms:
            # Determine form method
            form_method = form.get('method', 'GET').upper()
            
            # Find all input fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            
            for input_field in inputs:
                name = input_field.get('name')
                if not name:
                    continue
                
                # Get field attributes
                value = input_field.get('value', '')
                field_type = input_field.get('type', 'text')
                
                # Determine source based on field type
                if field_type == 'hidden':
                    source = 'hidden'
                else:
                    source = 'form'
                
                params.append(DiscoveredParameter(
                    name=name,
                    value=value,
                    source=source,
                    method=form_method,
                    field_type=field_type
                ))
        
        return params
    
    def _discover_from_links(self, soup: BeautifulSoup, base_url: str) -> List[DiscoveredParameter]:
        """Discover parameters from links and URLs in the page"""
        params = []
        
        # Find all anchor tags
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link.get('href')
            if not href:
                continue
            
            # Make absolute URL
            absolute_url = urljoin(base_url, href)
            
            # Parse URL parameters
            parsed = urlparse(absolute_url)
            query_params = parse_qs(parsed.query)
            
            for param_name, param_values in query_params.items():
                # Use first value if multiple
                value = param_values[0] if param_values else ''
                
                params.append(DiscoveredParameter(
                    name=param_name,
                    value=value,
                    source='link',
                    method='GET',
                    field_type='text'
                ))
        
        # Find script src, img src, iframe src, etc.
        for tag_name in ['script', 'img', 'iframe', 'link']:
            for tag in soup.find_all(tag_name):
                src = tag.get('src') or tag.get('href')
                if not src:
                    continue
                
                # Make absolute URL
                absolute_url = urljoin(base_url, src)
                
                # Parse URL parameters
                parsed = urlparse(absolute_url)
                query_params = parse_qs(parsed.query)
                
                for param_name, param_values in query_params.items():
                    value = param_values[0] if param_values else ''
                    
                    params.append(DiscoveredParameter(
                        name=param_name,
                        value=value,
                        source='url',
                        method='GET',
                        field_type='text'
                    ))
        
        return params
    
    def _discover_from_scripts(self, soup: BeautifulSoup, base_url: str) -> List[DiscoveredParameter]:
        """Discover parameters from external script URLs"""
        params = []
        
        # Already handled in _discover_from_links under 'url' source
        # This is kept separate for clarity but can be merged
        
        return params
    
    def _discover_from_inline_js(self, soup: BeautifulSoup) -> List[DiscoveredParameter]:
        """Discover parameters from inline JavaScript code"""
        params = []
        
        # Find all script tags with inline content
        scripts = soup.find_all('script')
        
        for script in scripts:
            if not script.string:
                continue
            
            js_content = script.string
            
            # Extract variables
            for pattern in self.JS_VAR_PATTERNS:
                matches = re.finditer(pattern, js_content)
                for match in matches:
                    if len(match.groups()) >= 2:
                        var_name = match.group(1)
                        var_value = match.group(2)
                        
                        # Filter out common non-parameter variables
                        if self._is_likely_parameter(var_name):
                            params.append(DiscoveredParameter(
                                name=var_name,
                                value=var_value,
                                source='js',
                                method='GET',  # Default to GET for JS vars
                                field_type='text'
                            ))
            
            # Extract parameter names (without values)
            for pattern in self.JS_PARAM_PATTERNS:
                matches = re.finditer(pattern, js_content)
                for match in matches:
                    param_name = match.group(1)
                    
                    if self._is_likely_parameter(param_name):
                        params.append(DiscoveredParameter(
                            name=param_name,
                            value='',
                            source='js',
                            method='GET',
                            field_type='text'
                        ))
        
        return params
    
    def _discover_from_url(self, url: str) -> List[DiscoveredParameter]:
        """Discover parameters from the target URL itself"""
        params = []
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param_name, param_values in query_params.items():
            value = param_values[0] if param_values else ''
            
            params.append(DiscoveredParameter(
                name=param_name,
                value=value,
                source='url',
                method='GET',
                field_type='text'
            ))
        
        return params
    
    def _is_likely_parameter(self, name: str) -> bool:
        """
        Check if a variable name is likely to be a parameter
        Filters out common non-parameter variables
        """
        # Filter out very short names
        if len(name) < 2:
            return False
        
        # Filter out common JavaScript/DOM variables
        excluded_patterns = [
            r'^(i|j|k|x|y|z)$',  # Loop counters
            r'^(window|document|console|alert)$',  # DOM/Browser objects
            r'^(this|self|that)$',  # Common references
            r'^(error|err|msg|message)$',  # Generic variables
            r'^(true|false|null|undefined)$',  # Literals
            r'^(function|return|if|else|for|while)$',  # Keywords
        ]
        
        for pattern in excluded_patterns:
            if re.match(pattern, name, re.IGNORECASE):
                return False
        
        return True
    
    def _deduplicate_parameters(self, params: List[DiscoveredParameter]) -> List[DiscoveredParameter]:
        """Remove duplicate parameters, keeping the first occurrence"""
        seen = set()
        unique_params = []
        
        for param in params:
            key = (param.name, param.method)
            if key not in seen:
                seen.add(key)
                unique_params.append(param)
        
        return unique_params
    
    def _create_merged_params(self, params: List[DiscoveredParameter]) -> Dict[str, Dict[str, str]]:
        """
        Create a merged parameter dictionary organized by method
        
        Returns:
            Dict with keys 'GET' and 'POST', each containing param dicts
        """
        merged = {
            'GET': {},
            'POST': {}
        }
        
        for param in params:
            if param.method in merged:
                # Use existing value or default to '1' for testing
                test_value = param.value if param.value else '1'
                merged[param.method][param.name] = test_value
        
        return merged
