"""
Generic Vulnerability Detection Plugin

This plugin detects various other vulnerability types not covered by specific detectors.
"""

import logging
import re
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding
from scanner.scan_plugins.vpoc_mixin import VPoCDetectorMixin


logger = logging.getLogger(__name__)


class OtherDetectorPlugin(VPoCDetectorMixin, BaseScanPlugin):
    """Generic vulnerability detection plugin."""
    
    # Generic vulnerability indicators
    INDICATORS = {
        'debug_mode': ['debug=true', 'debug:true', 'DEBUG', 'TRACE'],
        'admin_panel': ['/admin', '/administrator', '/wp-admin', '/phpmyadmin'],
        'backup_files': ['.bak', '.backup', '.old', '.tmp', '~'],
        'default_creds': ['admin:admin', 'root:root', 'admin:password'],
    }

    # Framework-specific debug page patterns that indicate active debug exposure
    _DEBUG_PATTERNS = [
        # Python/Django debug page
        r'django\.core\.exceptions',
        r'Traceback \(most recent call last\)',
        r'django\.template\.exceptions',
        r'Environment:\s*\n\s*Request Method',
        # Python generic traceback
        r'File ".*\.py", line \d+',
        # PHP error details
        r'(?:Fatal error|Parse error|Warning|Notice):\s+.+\s+in\s+/.+\.php',
        r'Stack trace:',
        # Rails debug
        r'ActionController::RoutingError',
        r'ActiveRecord::',
        # ASP.NET yellow screen
        r'Server Error in .* Application',
        r'System\.Web\.HttpException',
        r'<title>Runtime Error</title>',
        # Node.js / Express
        r'Error: Cannot (?:GET|POST|PUT|DELETE)',
        r'at Object\.<anonymous>.*\.js:\d+:\d+',
        # Generic: SQL queries or internal paths in response
        r'SELECT .+ FROM .+ WHERE',
        r'(?:mysql|pgsql|sqlite)_(?:query|error)',
        # Environment variables dump
        r'(?:PATH|HOME|PYTHONPATH|RAILS_ENV)\s*=\s*[^\s]+',
    ]

    # Admin functionality indicators (shows panel is accessible WITHOUT auth)
    _ADMIN_FUNCTIONALITY_INDICATORS = [
        r'(?:create|add|delete|remove|edit|manage)\s+(?:user|account|member)',
        r'user\s+management',
        r'manage\s+users',
        r'system\s+settings',
        r'site\s+settings',
        r'admin\s+dashboard',
        r'control\s+panel',
        r'(?:create|new|add|edit|delete)\s+(?:post|article|page|product)',
        r'content\s+management',
        r'phpmyadmin',
        r'sql\s+query',
        r'table\s+structure',
        r'<a[^>]+href=["\'][^"\']*(?:logout|sign.?out)["\']',
        r'logged\s+in\s+as',
        r'welcome,\s+admin',
    ]

    # Login-form-only indicators (expected behaviour, NOT a vulnerability)
    _LOGIN_FORM_ONLY_INDICATORS = [
        r'<form[^>]*>.*?<input[^>]+type=["\']?password["\']?',
        r'sign\s+in',
        r'log\s+in',
        r'forgot\s+(?:your\s+)?password',
    ]
    
    @property
    def plugin_id(self) -> str:
        return 'other_detector'
    
    @property
    def name(self) -> str:
        return 'Generic Vulnerability Detector'
    
    @property
    def description(self) -> str:
        return 'Detects miscellaneous vulnerabilities'
    
    @property
    def version(self) -> str:
        return '2.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        return ['other']

    def _is_debug_output(self, text: str) -> bool:
        """Return True only when the response contains actual debug output patterns."""
        return any(
            re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            for pattern in self._DEBUG_PATTERNS
        )

    def _is_admin_accessible_without_auth(self, text: str) -> bool:
        """
        Return True only when admin content shows privileged functionality,
        not just a login form (which is expected behaviour).
        If privileged functionality is present (even alongside a login form),
        the panel is considered accessible without authentication.
        """
        has_functionality = any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self._ADMIN_FUNCTIONALITY_INDICATORS
        )
        return has_functionality

    def _is_backup_file_with_sensitive_data(self, response: Any) -> bool:
        """
        Return True only when a backup file response contains actual sensitive data,
        not just a 200 OK that serves the site homepage.
        """
        # Check Content-Type — backup files should NOT be text/html
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type:
            return False

        # Minimum size heuristic: backup files should have some content
        if len(response.content) < 100:
            return False

        # Check for sensitive content indicators in the first 4 KB
        sample = response.text[:4096]
        sensitive_patterns = [
            r'CREATE TABLE',
            r'INSERT INTO',
            r'(?:password|passwd|secret|api.?key|token)\s*[=:]',
            r'BEGIN (?:PGP|RSA) (?:PRIVATE|PUBLIC)',
            r'\[database\]',
            r'DB_(?:HOST|NAME|USER|PASS)',
        ]
        return any(
            re.search(p, sample, re.IGNORECASE) for p in sensitive_patterns
        )
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """Scan for generic vulnerabilities."""
        if not HAS_REQUESTS:
            return []
        
        config = config or self.get_default_config()
        findings = []
        
        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            
            response = requests.get(url, timeout=timeout, verify=verify_ssl)

            # Check for debug mode — only report when actual debug output is present.
            # Simple presence of the word "DEBUG" in HTML is not a vulnerability.
            if self._is_debug_output(response.text):
                finding = VulnerabilityFinding(
                    vulnerability_type='other',
                    severity='medium',
                    url=url,
                    description=(
                        'Debug mode is actively exposing sensitive information '
                        '(stack traces, environment variables, SQL queries, or internal paths)'
                    ),
                    evidence='Framework-specific debug output detected in page response',
                    remediation='Disable debug mode in production and suppress error details from end users',
                    confidence=0.8,
                    cwe_id='CWE-489'
                )
                self._attach_vpoc(finding, response, '', 0.8, reproduction_steps="1. Send GET request to target URL\n2. Observe debug information in response")
                findings.append(finding)

            logger.info(f"Generic scan found {len(findings)} issue(s)")
            
        except Exception as e:
            logger.error(f"Error during generic scan: {e}")
        

        # Adaptive learning: record failure if no findings
        if not findings and hasattr(self, '_adaptive_learner') and self._adaptive_learner:
            self.learn_from_failure(payload='', response=None, target_url=url)
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        return {'verify_ssl': False, 'timeout': 10}
