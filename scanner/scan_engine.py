"""
Scan Engine

This module provides the main scanning engine that orchestrates vulnerability detection
using the plugin system.

The engine:
- Loads and manages scan plugins
- Executes scans using multiple plugins
- Aggregates results from all plugins
- Provides both sync and async scanning interfaces (async TODO for future)
"""

import logging
from typing import Dict, List, Any, Optional

from scanner.scan_plugins import get_scan_registry, VulnerabilityFinding

# Import models only when needed to avoid dependency issues
try:
    from scanner.models import Scan, Vulnerability
    HAS_MODELS = True
except ImportError:
    HAS_MODELS = False
    logging.debug("Django models not available, database operations disabled")

logger = logging.getLogger(__name__)


class ScanEngine:
    """
    Main scanning engine that orchestrates vulnerability detection.
    
    This engine uses the plugin system to perform modular, extensible scanning.
    
    Usage:
        engine = ScanEngine()
        findings = engine.scan(url, config)
        engine.save_findings_to_db(scan, findings)
    """
    
    def __init__(self):
        """Initialize the scan engine."""
        self.registry = get_scan_registry()
        logger.info(f"ScanEngine initialized with {self.registry.get_plugin_count()} plugin(s)")
    
    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Perform a vulnerability scan using all registered plugins.
        
        Args:
            url: Target URL to scan
            config: Optional configuration for plugins
        
        Returns:
            List[VulnerabilityFinding]: Aggregated findings from all plugins
        """
        config = config or {}
        all_findings = []
        
        plugins = self.registry.get_all_plugins()
        logger.info(f"Starting scan of {url} with {len(plugins)} plugin(s)")
        
        for plugin in plugins:
            try:
                logger.debug(f"Running plugin: {plugin.name}")
                findings = plugin.scan(url, config)
                all_findings.extend(findings)
                logger.debug(f"Plugin {plugin.name} found {len(findings)} issue(s)")
            except Exception as e:
                logger.error(f"Error running plugin {plugin.name}: {e}")
        
        logger.info(f"Scan completed. Total findings: {len(all_findings)}")
        return all_findings
    
    def scan_with_plugins(
        self, 
        url: str, 
        plugin_ids: List[str], 
        config: Optional[Dict[str, Any]] = None
    ) -> List[VulnerabilityFinding]:
        """
        Perform a scan using specific plugins only.
        
        Args:
            url: Target URL to scan
            plugin_ids: List of plugin IDs to use
            config: Optional configuration for plugins
        
        Returns:
            List[VulnerabilityFinding]: Aggregated findings from specified plugins
        """
        config = config or {}
        all_findings = []
        
        logger.info(f"Starting targeted scan of {url} with {len(plugin_ids)} plugin(s)")
        
        for plugin_id in plugin_ids:
            plugin = self.registry.get_plugin(plugin_id)
            if plugin:
                try:
                    logger.debug(f"Running plugin: {plugin.name}")
                    findings = plugin.scan(url, config)
                    all_findings.extend(findings)
                    logger.debug(f"Plugin {plugin.name} found {len(findings)} issue(s)")
                except Exception as e:
                    logger.error(f"Error running plugin {plugin.name}: {e}")
            else:
                logger.warning(f"Plugin not found: {plugin_id}")
        
        logger.info(f"Targeted scan completed. Total findings: {len(all_findings)}")
        return all_findings
    
    def save_findings_to_db(
        self, 
        scan: 'Scan', 
        findings: List[VulnerabilityFinding]
    ) -> List['Vulnerability']:
        """
        Save vulnerability findings to the database.
        
        Args:
            scan: Scan model instance
            findings: List of vulnerability findings
        
        Returns:
            List[Vulnerability]: Created vulnerability model instances
        """
        if not HAS_MODELS:
            logger.warning("Django models not available, skipping database save")
            return []
        
        vulnerabilities = []
        
        for finding in findings:
            vuln = Vulnerability.objects.create(
                scan=scan,
                vulnerability_type=finding.vulnerability_type,
                severity=finding.severity,
                url=finding.url,
                parameter=finding.parameter,
                description=finding.description,
                evidence=finding.evidence,
                remediation=finding.remediation,
                confidence_score=finding.confidence,
            )
            vulnerabilities.append(vuln)
        
        logger.info(f"Saved {len(vulnerabilities)} vulnerability(ies) to database for scan {scan.id}")
        return vulnerabilities
    
    def list_available_plugins(self) -> List[Dict[str, Any]]:
        """
        Get list of available scan plugins.
        
        Returns:
            List of plugin metadata dictionaries
        """
        return self.registry.list_plugins()
    
    # TODO: Implement async scanning in future phase
    # async def async_scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
    #     """
    #     Perform asynchronous vulnerability scan.
    #     
    #     This will be implemented in a future phase with:
    #     - asyncio-based concurrent plugin execution
    #     - Celery task integration
    #     - Progress tracking
    #     - Background scanning
    #     """
    #     pass


def get_scan_engine() -> ScanEngine:
    """
    Get a ScanEngine instance.
    
    Returns:
        ScanEngine: Scan engine instance
    """
    return ScanEngine()
