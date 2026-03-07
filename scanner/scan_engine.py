"""
Scan Engine

This module provides the main scanning engine that orchestrates vulnerability detection
using the plugin system.

The engine:
- Loads and manages scan plugins
- Executes scans using multiple plugins
- Aggregates results from all plugins
- Registers findings with FindingTracker and analyses real impact via ImpactAnalyzer
- Optionally creates issue-tracker tickets via the integrations package
- Provides both sync and async scanning interfaces (async TODO for future)
"""

import logging
import os
from typing import Dict, List, Any, Optional

from scanner.scan_plugins import get_scan_registry, VulnerabilityFinding
from scanner.finding_tracker import FindingTracker, FindingStatus
from scanner.impact_analyzer import ImpactAnalyzer
from scanner.integrations import TrackerConfig

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
    After each scan, findings are:
      1. Registered with a ``FindingTracker`` instance.
      2. Analysed by ``ImpactAnalyzer`` to determine real-world impact.
      3. Optionally submitted to an issue tracker (Jira / Bugzilla) when
         ``auto_create_on_confirmed`` is enabled in ``TrackerConfig``.
    
    Usage:
        engine = ScanEngine()
        findings = engine.scan(url, config)
        engine.save_findings_to_db(scan, findings)
    """
    
    def __init__(self):
        """Initialize the scan engine."""
        self.registry = get_scan_registry()
        self.finding_tracker = FindingTracker()
        self.impact_analyzer = ImpactAnalyzer()
        self._tracker_client = self._init_tracker_client()
        logger.info(f"ScanEngine initialized with {self.registry.get_plugin_count()} plugin(s)")

    # ------------------------------------------------------------------
    # Issue-tracker helpers
    # ------------------------------------------------------------------

    def _init_tracker_client(self):
        """Initialise the issue tracker client from environment config."""
        try:
            config = TrackerConfig.from_env()
            if config.tracker_type == "jira" and config.jira_url:
                from scanner.integrations import JiraTracker
                return JiraTracker(
                    jira_url=config.jira_url,
                    project_key=config.jira_project_key,
                    api_token=config.jira_api_token,
                    email=config.jira_email,
                    issue_type=config.jira_issue_type,
                    priority_mapping=config.priority_mapping,
                )
            if config.tracker_type == "bugzilla" and config.bugzilla_url:
                from scanner.integrations import BugzillaTracker
                return BugzillaTracker(
                    bugzilla_url=config.bugzilla_url,
                    api_key=config.bugzilla_api_key,
                    product=config.bugzilla_product,
                    component=config.bugzilla_component,
                    version=config.bugzilla_version,
                    priority_mapping=config.priority_mapping,
                )
        except Exception as exc:
            logger.debug("Issue tracker not initialised (will run without it): %s", exc)
        return None

    def _post_scan_process(
        self, findings: List[VulnerabilityFinding], config: Dict[str, Any]
    ) -> None:
        """
        Register findings, analyse impact, and create tracker tickets.

        Called automatically at the end of :meth:`scan` and
        :meth:`scan_with_plugins`.
        """
        tracker_config = TrackerConfig.from_env()

        severity_order = ["critical", "high", "medium", "low", "info"]
        threshold_idx = severity_order.index(
            tracker_config.severity_threshold.lower()
            if tracker_config.severity_threshold.lower() in severity_order
            else "medium"
        )

        for vf in findings:
            finding_data = {
                "vulnerability_type": vf.vulnerability_type,
                "target_url": vf.url,
                "parameter": getattr(vf, "parameter", ""),
                "severity": vf.severity,
                "confidence_score": getattr(vf, "confidence", 0.0),
                "detection_evidence": vf.evidence,
            }
            finding = self.finding_tracker.add_finding(finding_data)

            # Analyse real-world impact
            try:
                evidence_dict = vf.http_traffic or {}
                if hasattr(vf, "successful_payloads") and vf.successful_payloads:
                    evidence_dict["payload_executed"] = vf.successful_payloads[0]
                impact = self.impact_analyzer.analyze_impact(
                    vf.vulnerability_type, evidence_dict
                )
                finding.real_impact = impact.to_dict()
            except Exception as exc:
                logger.debug("Impact analysis failed for %s: %s", finding.finding_id, exc)

            # Auto-create tracker tickets
            if (
                self._tracker_client is not None
                and tracker_config.auto_create_on_confirmed
            ):
                sev = vf.severity.lower() if vf.severity else "info"
                sev_idx = severity_order.index(sev) if sev in severity_order else len(severity_order)
                if sev_idx <= threshold_idx:
                    try:
                        result = self._tracker_client.create_issue(finding.to_dict())
                        self.finding_tracker.link_to_tracker(
                            finding.finding_id,
                            result["issue_id"],
                            result["issue_url"],
                        )
                        logger.info(
                            "Created tracker issue %s for finding %s",
                            result["issue_id"],
                            finding.finding_id,
                        )
                    except Exception as exc:
                        logger.warning(
                            "Failed to create tracker issue for %s: %s",
                            finding.finding_id,
                            exc,
                        )

    def _inject_env_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Inject environment-sourced config values if not already present.

        Currently injects:
          - ``test_server``: read from ``RFI_TEST_SERVER`` env var (used by the
            RFI detector plugin).  Explicit ``test_server`` values in *config*
            always take precedence.
        """
        rfi_test_server = os.getenv('RFI_TEST_SERVER')
        if 'test_server' not in config and rfi_test_server:
            config = {**config, 'test_server': rfi_test_server}
        return config
    
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
        # Inject RFI_TEST_SERVER from environment if not already present in config
        config = self._inject_env_config(config)
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
        self._post_scan_process(all_findings, config)
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
        # Inject RFI_TEST_SERVER from environment if not already present in config
        config = self._inject_env_config(config)
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
        self._post_scan_process(all_findings, config)
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
            # Prefer explicit http_traffic; fall back to VPoC evidence if present
            http_traffic = finding.http_traffic or {}
            if not http_traffic and finding.vpoc is not None:
                vpoc = finding.vpoc
                http_traffic = {}
                if vpoc.http_request:
                    http_traffic['request'] = vpoc.http_request
                if vpoc.http_response:
                    http_traffic['response'] = vpoc.http_response
                if vpoc.curl_command:
                    http_traffic['curl_command'] = vpoc.curl_command
                if vpoc.reproduction_steps:
                    http_traffic['reproduction_steps'] = vpoc.reproduction_steps

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
                verified=finding.verified,
                successful_payloads=finding.successful_payloads or [],
                repeater_data=finding.repeater_requests or [],
                http_traffic=http_traffic,
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
