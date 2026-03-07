"""
Scan Engine

This module provides the main scanning engine that orchestrates vulnerability detection
using the plugin system.

The engine:
- Loads and manages scan plugins
- Executes scans using multiple plugins (sequential or concurrent)
- Aggregates and deduplicates results from all plugins
- Integrates stealth features between plugin executions when enabled
- Runs pre-scan reconnaissance to detect WAF and technology stack
- Registers findings with FindingTracker and analyses real impact via ImpactAnalyzer
- Optionally creates issue-tracker tickets via the integrations package
- Provides sync, concurrent, and profile-based scanning interfaces
"""

import logging
import os
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple

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

# Optional stealth engine
try:
    from scanner.stealth_engine import StealthEngine
    _HAS_STEALTH = True
except ImportError:
    _HAS_STEALTH = False

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

    # Predefined scan profiles with tuned defaults
    SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
        'stealth': {
            'enable_stealth': True,
            'stealth_timing': 'paranoid',
            'max_workers': 1,
            'max_retries': 3,
            'description': 'Slow, paranoid timing, minimal payloads, maximum evasion',
        },
        'balanced': {
            'enable_stealth': False,
            'stealth_timing': 'normal',
            'max_workers': 3,
            'max_retries': 2,
            'description': 'Moderate timing, standard payloads',
        },
        'aggressive': {
            'enable_stealth': False,
            'stealth_timing': 'aggressive',
            'max_workers': 10,
            'max_retries': 1,
            'description': 'No delays, maximum payloads, all techniques',
        },
        'quick': {
            'enable_stealth': False,
            'stealth_timing': 'aggressive',
            'max_workers': 5,
            'max_retries': 1,
            'severity_filter': ['critical', 'high'],
            'description': 'Fast, only high-severity checks',
        },
    }

    # Timing profile delays (seconds) for inter-plugin gaps
    _TIMING_DELAYS: Dict[str, Tuple[float, float]] = {
        'paranoid': (60.0, 120.0),
        'sneaky': (5.0, 15.0),
        'polite': (1.0, 3.0),
        'normal': (0.0, 0.0),
        'aggressive': (0.0, 0.0),
    }

    def __init__(self, enable_stealth: bool = False, stealth_timing: str = 'normal'):
        """
        Initialize the scan engine.

        Args:
            enable_stealth: Whether to enable stealth features between plugin
                            executions (UA rotation, timing jitter, etc.).
            stealth_timing: Timing profile name used when stealth is enabled.
                            One of: 'paranoid', 'sneaky', 'polite', 'normal', 'aggressive'.
        """
        self.registry = get_scan_registry()
        self.finding_tracker = FindingTracker()
        self.impact_analyzer = ImpactAnalyzer()
        self._tracker_client = self._init_tracker_client()

        self.enable_stealth = enable_stealth and _HAS_STEALTH
        self.stealth_timing = stealth_timing
        self._stealth_engine: Optional['StealthEngine'] = None
        if self.enable_stealth:
            self._stealth_engine = StealthEngine()
            logger.info(
                "ScanEngine stealth mode enabled (timing: %s)", stealth_timing
            )

        logger.info(
            "ScanEngine initialized with %d plugin(s)", self.registry.get_plugin_count()
        )

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

    # ------------------------------------------------------------------
    # Stealth helpers
    # ------------------------------------------------------------------

    def _apply_stealth_delay(self) -> None:
        """Sleep for a randomised delay based on the configured timing profile.

        Does nothing when stealth is disabled or the timing profile has zero
        delay (e.g. 'normal', 'aggressive').
        """
        if not self.enable_stealth:
            return
        min_d, max_d = self._TIMING_DELAYS.get(self.stealth_timing, (0.0, 0.0))
        if max_d <= 0:
            return
        delay = random.uniform(min_d, max_d)
        logger.debug("Stealth inter-plugin delay: %.2fs (%s)", delay, self.stealth_timing)
        time.sleep(delay)

    def _get_stealth_headers(self) -> Dict[str, str]:
        """Return randomised browser headers from the stealth engine, or {}."""
        if self._stealth_engine is not None:
            try:
                return self._stealth_engine.get_randomized_headers()
            except Exception as exc:
                logger.debug("Failed to get stealth headers: %s", exc)
        return {}

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate_findings(
        self, findings: List[VulnerabilityFinding]
    ) -> List[VulnerabilityFinding]:
        """Remove duplicate findings and merge evidence from duplicates.

        Two findings are considered duplicates when they share the same
        ``(vulnerability_type, url, parameter)`` tuple.  Among duplicates the
        one with the highest confidence is kept; evidence strings from all
        duplicates are concatenated into that winner.

        Args:
            findings: Raw list of findings (may contain duplicates).

        Returns:
            Deduplicated list of :class:`VulnerabilityFinding` instances.
        """
        seen: Dict[Tuple[str, str, Optional[str]], VulnerabilityFinding] = {}

        for finding in findings:
            key = (finding.vulnerability_type, finding.url, finding.parameter)
            if key not in seen:
                seen[key] = finding
            else:
                existing = seen[key]
                # Merge evidence strings
                if finding.evidence and finding.evidence not in existing.evidence:
                    existing.evidence = f"{existing.evidence}; {finding.evidence}"
                # Keep the higher-confidence finding as the canonical record
                if finding.confidence > existing.confidence:
                    # Preserve merged evidence
                    merged_evidence = existing.evidence
                    seen[key] = finding
                    seen[key].evidence = merged_evidence

        unique = list(seen.values())
        removed = len(findings) - len(unique)
        if removed:
            logger.info("Deduplication removed %d duplicate finding(s); %d unique", removed, len(unique))
        return unique

    # ------------------------------------------------------------------
    # Reconnaissance
    # ------------------------------------------------------------------

    def _pre_scan_recon(self, url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform lightweight pre-scan reconnaissance.

        Detects WAF presence and server technologies by inspecting response
        headers.  Results are stored back into *config* under the
        ``'recon'`` key so that plugins can adapt their payloads.

        Args:
            url: Target URL.
            config: Current scan configuration (modified in-place and returned).

        Returns:
            The updated *config* dict with ``config['recon']`` populated.
        """
        recon: Dict[str, Any] = {
            'waf_detected': False,
            'waf_name': None,
            'technologies': [],
            'server_headers': {},
        }

        try:
            import requests as _req
            headers = self._get_stealth_headers() or {
                'User-Agent': 'Mozilla/5.0 (compatible; Scanner/1.0)',
            }
            resp = _req.get(url, headers=headers, timeout=config.get('timeout', 10), verify=False)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            recon['server_headers'] = dict(resp.headers)

            # Technology detection
            technologies: List[str] = []
            server = resp_headers.get('server', '').lower()
            powered_by = resp_headers.get('x-powered-by', '').lower()
            x_generator = resp_headers.get('x-generator', '').lower()
            aspnet = resp_headers.get('x-aspnet-version', '')

            for tech_hint, tech_name in [
                ('nginx', 'nginx'), ('apache', 'apache'), ('iis', 'iis'),
                ('php', 'php'), ('wordpress', 'wordpress'),
                ('drupal', 'drupal'), ('joomla', 'joomla'),
                ('django', 'django'), ('ruby', 'ruby'),
                ('express', 'node.js'), ('node', 'node.js'),
            ]:
                if tech_hint in server or tech_hint in powered_by or tech_hint in x_generator:
                    if tech_name not in technologies:
                        technologies.append(tech_name)
            if aspnet:
                if 'asp.net' not in technologies:
                    technologies.append('asp.net')

            recon['technologies'] = technologies

            # WAF detection via response headers
            try:
                from scanner.scan_plugins.detectors.waf_bypass_detector import WAF_SIGNATURES
                for waf_name, sigs in WAF_SIGNATURES.items():
                    for header_key in sigs.get('headers', []):
                        if header_key.lower() in resp_headers:
                            recon['waf_detected'] = True
                            recon['waf_name'] = waf_name
                            break
                    if recon['waf_detected']:
                        break
            except Exception as exc:
                logger.debug("WAF detection during recon failed: %s", exc)

            if recon['technologies']:
                logger.info("Recon detected technologies: %s", recon['technologies'])
            if recon['waf_detected']:
                logger.info("Recon detected WAF: %s", recon['waf_name'])

        except Exception as exc:
            logger.debug("Pre-scan recon failed for %s: %s", url, exc)

        config['recon'] = recon
        return config

    # ------------------------------------------------------------------
    # Plugin execution with retry
    # ------------------------------------------------------------------

    def _run_plugin_with_retry(
        self,
        plugin: Any,
        url: str,
        config: Dict[str, Any],
        max_retries: int = 3,
    ) -> List[VulnerabilityFinding]:
        """Run a single plugin with exponential back-off retry logic.

        Args:
            plugin: Plugin instance to execute.
            url: Target URL.
            config: Scan configuration.
            max_retries: Maximum number of retry attempts (default 3).

        Returns:
            List of findings; empty list if all retries fail.
        """
        delay = 1.0
        for attempt in range(1, max_retries + 2):
            try:
                return plugin.scan(url, config)
            except Exception as exc:
                if attempt > max_retries:
                    logger.warning(
                        "Plugin %s failed after %d attempt(s); skipping. Error: %s",
                        plugin.name, max_retries + 1, exc,
                    )
                    return []
                logger.warning(
                    "Plugin %s attempt %d/%d failed (%s); retrying in %.1fs",
                    plugin.name, attempt, max_retries + 1, exc, delay,
                )
                time.sleep(delay)
                delay *= 2
        return []  # unreachable but satisfies type checkers

    # ------------------------------------------------------------------
    # Core scan methods
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Perform a vulnerability scan using all registered plugins.

        When stealth is enabled, randomised delays are applied between plugin
        executions and stealth headers are injected into *config*.

        Args:
            url: Target URL to scan
            config: Optional configuration for plugins

        Returns:
            List[VulnerabilityFinding]: Deduplicated aggregated findings from all plugins
        """
        config = config or {}
        config = self._inject_env_config(config)

        # Inject stealth headers so plugins that respect them benefit
        if self.enable_stealth:
            config.setdefault('stealth_headers', self._get_stealth_headers())
            config.setdefault('enable_stealth', True)

        all_findings: List[VulnerabilityFinding] = []

        plugins = self.registry.get_all_plugins()
        logger.info(f"Starting scan of {url} with {len(plugins)} plugin(s)")

        for plugin in plugins:
            logger.debug(f"Running plugin: {plugin.name}")
            findings = self._run_plugin_with_retry(plugin, url, config)
            all_findings.extend(findings)
            logger.debug(f"Plugin {plugin.name} found {len(findings)} issue(s)")
            self._apply_stealth_delay()

        all_findings = self._deduplicate_findings(all_findings)
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
            List[VulnerabilityFinding]: Deduplicated aggregated findings from specified plugins
        """
        config = config or {}
        config = self._inject_env_config(config)

        if self.enable_stealth:
            config.setdefault('stealth_headers', self._get_stealth_headers())
            config.setdefault('enable_stealth', True)

        all_findings: List[VulnerabilityFinding] = []

        logger.info(f"Starting targeted scan of {url} with {len(plugin_ids)} plugin(s)")

        for plugin_id in plugin_ids:
            plugin = self.registry.get_plugin(plugin_id)
            if plugin:
                logger.debug(f"Running plugin: {plugin.name}")
                findings = self._run_plugin_with_retry(plugin, url, config)
                all_findings.extend(findings)
                logger.debug(f"Plugin {plugin.name} found {len(findings)} issue(s)")
                self._apply_stealth_delay()
            else:
                logger.warning(f"Plugin not found: {plugin_id}")

        all_findings = self._deduplicate_findings(all_findings)
        logger.info(f"Targeted scan completed. Total findings: {len(all_findings)}")
        self._post_scan_process(all_findings, config)
        return all_findings

    def scan_concurrent(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
        max_workers: int = 3,
    ) -> List[VulnerabilityFinding]:
        """
        Perform a concurrent vulnerability scan using all registered plugins.

        Plugins are executed in a thread pool.  Each thread manages its own
        stealth session so that UA rotation and session cookies do not bleed
        between concurrent workers.

        Args:
            url: Target URL to scan.
            config: Optional configuration for plugins.
            max_workers: Maximum number of parallel plugin threads (default 3).

        Returns:
            List[VulnerabilityFinding]: Deduplicated aggregated findings.
        """
        import threading
        config = config or {}
        config = self._inject_env_config(config)

        plugins = self.registry.get_all_plugins()
        logger.info(
            "Starting concurrent scan of %s with %d plugin(s), max_workers=%d",
            url, len(plugins), max_workers,
        )

        all_findings: List[VulnerabilityFinding] = []
        lock = threading.Lock()

        def _run_plugin(plugin: Any) -> None:
            # Each thread gets its own stealth headers so sessions don't collide
            thread_config = dict(config)
            if self.enable_stealth:
                thread_config['stealth_headers'] = self._get_stealth_headers()
                thread_config['enable_stealth'] = True

            findings = self._run_plugin_with_retry(plugin, url, thread_config)
            logger.debug("Plugin %s found %d issue(s)", plugin.name, len(findings))
            with lock:
                all_findings.extend(findings)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_run_plugin, plugin): plugin for plugin in plugins}
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Concurrent plugin %s raised: %s", plugin.name, exc)

        deduplicated = self._deduplicate_findings(all_findings)
        logger.info("Concurrent scan completed. Total findings: %d", len(deduplicated))
        self._post_scan_process(deduplicated, config)
        return deduplicated

    def scan_with_profile(
        self,
        url: str,
        profile_name: str,
        extra_config: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Perform a scan using a predefined scan profile.

        Available profiles are defined in :attr:`SCAN_PROFILES`:
        - ``'stealth'``    — slow, paranoid timing, maximum evasion
        - ``'balanced'``   — moderate timing, standard payloads
        - ``'aggressive'`` — no delays, maximum payloads
        - ``'quick'``      — fast, only high-severity checks

        Args:
            url: Target URL to scan.
            profile_name: Name of the scan profile to use.
            extra_config: Additional config values merged on top of the profile.

        Returns:
            List[VulnerabilityFinding]: Findings from the profile-tuned scan.

        Raises:
            ValueError: If *profile_name* is not a recognised profile.
        """
        if profile_name not in self.SCAN_PROFILES:
            raise ValueError(
                f"Unknown scan profile '{profile_name}'. "
                f"Valid profiles: {list(self.SCAN_PROFILES)}"
            )

        profile = dict(self.SCAN_PROFILES[profile_name])
        config: Dict[str, Any] = extra_config.copy() if extra_config else {}
        # Profile keys that are not scan-config fields
        max_workers: int = profile.pop('max_workers', 3)
        max_retries: int = profile.pop('max_retries', 2)
        profile.pop('description', None)

        # Apply profile settings to this engine instance
        self.enable_stealth = profile.pop('enable_stealth', False) and _HAS_STEALTH
        self.stealth_timing = profile.pop('stealth_timing', 'normal')
        if self.enable_stealth and self._stealth_engine is None:
            self._stealth_engine = StealthEngine()

        config.update(profile)
        config['max_retries'] = max_retries

        # Run pre-scan recon
        config = self._pre_scan_recon(url, config)

        logger.info("Starting scan with profile '%s' on %s", profile_name, url)

        if max_workers > 1:
            return self.scan_concurrent(url, config=config, max_workers=max_workers)
        return self.scan(url, config=config)

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


def get_scan_engine() -> ScanEngine:
    """
    Get a ScanEngine instance.
    
    Returns:
        ScanEngine: Scan engine instance
    """
    return ScanEngine()
