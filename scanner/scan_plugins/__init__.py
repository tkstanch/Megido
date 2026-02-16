"""
Scan Plugin System

This module provides a plugin-based vulnerability scanning architecture.
Unlike the exploit plugins (scanner/plugins/), these plugins focus on DETECTION
of vulnerabilities rather than exploitation.

The scan plugin system enables:
- Modular vulnerability detection
- Easy addition of new vulnerability checks
- Async scanning support
- Consistent reporting format
- Independent plugin testing

Usage:
    from scanner.scan_plugins import get_scan_registry
    
    registry = get_scan_registry()
    plugins = registry.get_all_plugins()
    
    for plugin in plugins:
        results = plugin.scan(url, config)
"""

from .base_scan_plugin import BaseScanPlugin, VulnerabilityFinding, ScanSeverity, create_repeater_request
from .scan_plugin_registry import ScanPluginRegistry, get_scan_registry

__all__ = [
    'BaseScanPlugin',
    'VulnerabilityFinding',
    'ScanSeverity',
    'ScanPluginRegistry',
    'get_scan_registry',
    'create_repeater_request',
]
