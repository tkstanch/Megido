"""
Base Scan Plugin Interface

This module defines the base interface for vulnerability detection plugins.
Each plugin implements scanning logic for a specific vulnerability type or category.

Note: This is separate from ExploitPlugin which handles exploitation of known vulns.
      ScanPlugins focus on DETECTION, ExploitPlugins focus on EXPLOITATION.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ScanSeverity(Enum):
    """Severity levels for discovered vulnerabilities"""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class VulnerabilityFinding:
    """
    Represents a vulnerability found during scanning.
    
    This standardized format ensures consistent reporting across all plugins.
    Enhanced with payload tracking and repeater-ready request/response data.
    """
    vulnerability_type: str  # e.g., 'xss', 'sqli', 'csrf', 'info_disclosure'
    severity: str  # 'low', 'medium', 'high', 'critical'
    url: str
    description: str
    evidence: str
    remediation: str
    parameter: Optional[str] = None
    confidence: float = 0.5  # 0.0 to 1.0
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    
    # Enhanced fields for verification and manual testing
    verified: bool = False  # True if exploit confirmed real-world impact
    successful_payloads: Optional[List[str]] = None  # Payloads that succeeded
    repeater_requests: Optional[List[Dict[str, Any]]] = None  # Copy-paste ready request data
    http_traffic: Optional[Dict[str, Any]] = None  # HTTP request/response traffic capture
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'url': self.url,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'parameter': self.parameter,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'verified': self.verified,
        }
        
        # Include enhanced fields if present
        if self.successful_payloads:
            result['successful_payloads'] = self.successful_payloads
        
        if self.repeater_requests:
            result['repeater_requests'] = self.repeater_requests
        
        if self.http_traffic:
            result['http_traffic'] = self.http_traffic
            
        return result


class BaseScanPlugin(ABC):
    """
    Base interface for vulnerability scan plugins.
    
    All scan plugins must inherit from this class and implement the required methods.
    Plugins are automatically discovered by the ScanPluginRegistry.
    
    Attributes:
        plugin_id: Unique identifier for the plugin
        name: Human-readable name
        description: Brief description of what the plugin scans for
        version: Plugin version
    """
    
    def __init__(self):
        """Initialize the scan plugin."""
        pass
    
    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """
        Return a unique identifier for this plugin.
        
        Returns:
            str: Plugin identifier (e.g., 'xss_scanner', 'header_scanner')
        """
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the human-readable name of this plugin.
        
        Returns:
            str: Plugin name (e.g., 'XSS Vulnerability Scanner')
        """
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """
        Return a brief description of what this plugin scans for.
        
        Returns:
            str: Plugin description
        """
        pass
    
    @property
    def version(self) -> str:
        """
        Return the version of this plugin.
        
        Returns:
            str: Version string (default: '1.0.0')
        """
        return '1.0.0'
    
    @property
    def vulnerability_types(self) -> List[str]:
        """
        Return list of vulnerability types this plugin can detect.
        
        Returns:
            List[str]: List of vulnerability type identifiers
        """
        return []
    
    @property
    def supports_async(self) -> bool:
        """
        Indicate if this plugin supports async scanning.
        
        TODO: Implement async support in future phase.
        
        Returns:
            bool: True if plugin supports async, False otherwise
        """
        return False
    
    @abstractmethod
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Perform vulnerability scan on the target URL.
        
        This is the main method that implements the scanning logic.
        It should be safe to call multiple times and should handle errors gracefully.
        
        Args:
            url: Target URL to scan
            config: Optional configuration dictionary:
                   - verify_ssl: bool (default: False)
                   - timeout: int (default: 10)
                   - custom_headers: dict
                   - max_depth: int (for crawling plugins)
                   - Any plugin-specific settings
        
        Returns:
            List[VulnerabilityFinding]: List of vulnerabilities found
        """
        pass
    
    # TODO: Add async_scan method in future phase
    # async def async_scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
    #     """Async version of scan method for non-blocking scans"""
    #     pass
    
    def get_default_config(self) -> Dict[str, Any]:
        """
        Return default configuration for this plugin.
        
        Returns:
            Dict[str, Any]: Default configuration values
        """
        return {
            'verify_ssl': False,
            'timeout': 10,
        }
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate plugin configuration.
        
        Args:
            config: Configuration to validate
        
        Returns:
            bool: True if valid, False otherwise
        """
        return True
    
    def get_required_config_keys(self) -> List[str]:
        """
        Return list of required configuration keys.
        
        Returns:
            List[str]: List of required keys
        """
        return []


def create_repeater_request(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a repeater-ready request dictionary for manual testing.
    
    This formats HTTP request data in a copy-paste ready format compatible
    with Megido's repeater app for manual verification.
    
    Args:
        url: Full URL of the request
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: Dictionary of HTTP headers
        body: Request body (for POST/PUT requests)
        description: Optional description of what this request does
    
    Returns:
        Dict containing repeater-compatible request data
    """
    request_data = {
        'url': url,
        'method': method.upper(),
        'headers': headers or {},
        'body': body or '',
    }
    
    if description:
        request_data['description'] = description
    
    return request_data
