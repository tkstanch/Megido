"""
Scan Orchestrator

Top-level orchestrator that ties SmartCrawler, ConcurrentScanEngine,
TechFingerprinter, and ReportGenerator into a complete scanning workflow.

Workflow phases:
1. Reconnaissance  – SmartCrawler discovers attack surface
2. Tech Detection  – TechFingerprinter identifies the tech stack
3. Concurrent Scan – ConcurrentScanEngine runs all plugins over every URL
4. Aggregation     – Deduplicate, score, and rank findings
5. Reporting       – Generate a ScanReport with metrics and recommendations

Usage::

    from scanner.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator()
    report = orchestrator.run({'target_url': 'https://example.com', 'scan_profile': 'standard'})
    print(report.risk_score, report.vulnerabilities_found)
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from scanner.concurrent_scan_engine import ConcurrentScanEngine
from scanner.smart_crawler import SmartCrawler
from scanner.tech_fingerprinter import TechFingerprinter
from scanner.report_generator import ReportGenerator, ScanReport
from scanner.deduplication import deduplicate_and_correlate
from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    'quick': {
        'max_depth': 1,
        'max_urls': 50,
        'max_workers': 5,
        'plugin_timeout': 60,
        'enabled_plugins': [
            'security_headers_scanner',
            'ssl_scanner',
            'cors_scanner',
            'xss_scanner',
        ],
    },
    'standard': {
        'max_depth': 2,
        'max_urls': 200,
        'max_workers': 10,
        'plugin_timeout': 120,
        'enabled_plugins': [],  # empty → all plugins
    },
    'deep': {
        'max_depth': 3,
        'max_urls': 500,
        'max_workers': 15,
        'plugin_timeout': 180,
        'enabled_plugins': [],
    },
    'aggressive': {
        'max_depth': 5,
        'max_urls': 1000,
        'max_workers': 20,
        'plugin_timeout': 300,
        'enabled_plugins': [],
    },
}

_SEVERITY_SCORE: Dict[str, float] = {
    'critical': 25.0,
    'high': 10.0,
    'medium': 4.0,
    'low': 1.0,
}


# ---------------------------------------------------------------------------
# ScanOrchestrator
# ---------------------------------------------------------------------------

class ScanOrchestrator:
    """
    High-level scan orchestrator.

    Accepted *config* keys (all optional):
    - ``target_url`` (str): Target to scan.
    - ``scan_profile`` (str): One of ``quick``, ``standard``, ``deep``, ``aggressive``.
    - ``max_depth`` (int): Crawler recursion depth.
    - ``max_urls`` (int): Maximum URLs to crawl.
    - ``max_workers`` (int): Concurrent plugin threads.
    - ``plugin_timeout`` (int): Per-plugin timeout in seconds.
    - ``enabled_plugins`` (list): Plugin IDs to run (empty → all).
    - ``crawl_delay`` (float): Seconds between crawler requests.
    - ``probe_tech_paths`` (bool): Probe known CMS paths during fingerprinting.

    Args:
        progress_callback: Optional callable ``(phase: str, pct: float) → None``
            called with a phase label and 0–100 percentage as each phase completes.
    """

    def __init__(
        self,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> None:
        self._progress_callback = progress_callback

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, config: Dict[str, Any]) -> ScanReport:
        """
        Execute a complete scan and return a :class:`ScanReport`.

        Args:
            config: Scan configuration dictionary (see class docstring).

        Returns:
            :class:`~scanner.report_generator.ScanReport`
        """
        scan_start = time.monotonic()

        target_url: str = config.get('target_url', '')
        if not target_url:
            raise ValueError("'target_url' is required in config")

        # Merge profile defaults into config
        effective_config = self._resolve_config(config)

        logger.info(
            "ScanOrchestrator: starting scan of %s (profile=%s)",
            target_url,
            effective_config.get('_profile', 'custom'),
        )

        # ── Phase 1: Reconnaissance ────────────────────────────────────
        self._report_progress("reconnaissance", 0.0)
        crawl_result = self._phase_crawl(target_url, effective_config)
        self._report_progress("reconnaissance", 100.0)

        urls_to_scan: List[str] = list({target_url} | set(crawl_result.urls))

        # ── Phase 2: Technology Detection ─────────────────────────────
        self._report_progress("tech_detection", 0.0)
        tech_stack = self._phase_tech_detection(target_url, effective_config)
        self._report_progress("tech_detection", 100.0)

        # ── Phase 3: Concurrent Scanning ──────────────────────────────
        self._report_progress("scanning", 0.0)
        all_findings, scan_metrics = self._phase_scan(
            urls_to_scan, effective_config
        )
        self._report_progress("scanning", 100.0)

        # ── Phase 4: Aggregation ──────────────────────────────────────
        self._report_progress("aggregation", 0.0)
        deduplicated = deduplicate_and_correlate(all_findings)
        risk_score = self._calculate_risk_score(deduplicated)
        recommendations = self._generate_recommendations(deduplicated, tech_stack)
        self._report_progress("aggregation", 100.0)

        # ── Phase 5: Report ───────────────────────────────────────────
        self._report_progress("reporting", 0.0)
        sorted_findings = sorted(
            deduplicated,
            key=lambda f: (
                {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(f.severity.lower(), 4),
                -(f.confidence or 0),
            ),
        )

        total_duration = time.monotonic() - scan_start

        report = ScanReport(
            target=target_url,
            scan_duration=total_duration,
            urls_scanned=len(urls_to_scan),
            vulnerabilities_found=len(deduplicated),
            risk_score=risk_score,
            technology_stack=tech_stack.to_dict() if tech_stack else {},
            findings=sorted_findings,
            scan_metrics=scan_metrics,
            recommendations=recommendations,
        )
        self._report_progress("reporting", 100.0)

        logger.info(
            "ScanOrchestrator: scan complete — %d findings, risk=%.0f, duration=%.1fs",
            len(deduplicated),
            risk_score,
            total_duration,
        )
        return report

    # ------------------------------------------------------------------
    # Phase implementations
    # ------------------------------------------------------------------

    def _phase_crawl(self, url: str, config: Dict[str, Any]):
        """Phase 1: Crawl the target and return a CrawlResult."""
        crawler = SmartCrawler(
            max_depth=config.get('max_depth', 2),
            max_urls=config.get('max_urls', 200),
            delay=config.get('crawl_delay', 0.1),
            timeout=config.get('timeout', 10),
            verify_ssl=config.get('verify_ssl', False),
        )
        try:
            result = crawler.crawl(url)
            logger.info(
                "Phase 1 (Recon): found %d URLs, %d forms, %d API endpoints",
                len(result.urls),
                len(result.forms),
                len(result.api_endpoints),
            )
            return result
        except Exception as exc:  # noqa: BLE001
            logger.error("Phase 1 (Recon) failed: %s", exc)
            # Return minimal result so scan can continue
            from scanner.smart_crawler import CrawlResult
            return CrawlResult(urls=[url])

    def _phase_tech_detection(self, url: str, config: Dict[str, Any]):
        """Phase 2: Fingerprint the tech stack of the target."""
        fp = TechFingerprinter(
            timeout=config.get('timeout', 10),
            verify_ssl=config.get('verify_ssl', False),
            probe_paths=config.get('probe_tech_paths', False),
        )
        try:
            stack = fp.fingerprint(url)
            return stack
        except Exception as exc:  # noqa: BLE001
            logger.error("Phase 2 (Tech Detection) failed: %s", exc)
            from scanner.tech_fingerprinter import TechStack
            return TechStack()

    def _phase_scan(
        self,
        urls: List[str],
        config: Dict[str, Any],
    ):
        """Phase 3: Run concurrent plugins over all discovered URLs."""
        engine = ConcurrentScanEngine(
            max_workers=config.get('max_workers', 10),
            plugin_timeout=config.get('plugin_timeout', 120),
        )

        enabled_plugins: List[str] = config.get('enabled_plugins', [])
        all_findings: List[VulnerabilityFinding] = []

        for i, url in enumerate(urls):
            try:
                if enabled_plugins:
                    findings = engine.scan_with_plugins(url, enabled_plugins, config)
                else:
                    findings = engine.scan(url, config)
                all_findings.extend(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("Phase 3 scan error for %s: %s", url, exc)

        metrics_obj = engine.get_scan_metrics()
        metrics_dict: Dict[str, Any] = {}
        if metrics_obj:
            metrics_dict = {
                'total_duration_seconds': metrics_obj.total_duration_seconds,
                'plugin_count': metrics_obj.plugin_count,
                'total_findings_before_dedup': metrics_obj.total_findings_before_dedup,
                'total_findings_after_dedup': metrics_obj.total_findings_after_dedup,
                'dedup_reduction': metrics_obj.dedup_reduction,
                'failed_plugins': [
                    {'plugin_id': m.plugin_id, 'error': m.error}
                    for m in metrics_obj.failed_plugins
                ],
            }

        return all_findings, metrics_dict

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge profile defaults with user-supplied config."""
        profile_name = config.get('scan_profile', 'standard')
        profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES['standard']).copy()
        profile['_profile'] = profile_name
        # User-supplied values override profile defaults
        profile.update({k: v for k, v in config.items() if k != 'scan_profile'})
        return profile

    def _calculate_risk_score(self, findings: List[VulnerabilityFinding]) -> float:
        """Calculate a 0–100 aggregate risk score from all findings."""
        raw = sum(_SEVERITY_SCORE.get(f.severity.lower(), 0) for f in findings)
        return min(raw, 100.0)

    def _generate_recommendations(
        self,
        findings: List[VulnerabilityFinding],
        tech_stack,
    ) -> List[str]:
        """Return prioritised, deduplicated remediation recommendations."""
        seen: Dict[str, int] = {}
        for f in findings:
            key = f.vulnerability_type
            seen[key] = seen.get(key, 0) + 1

        # Sort by frequency × severity
        def _score(item: tuple) -> float:
            vtype, count = item
            severity_weight = max(
                _SEVERITY_SCORE.get(f.severity.lower(), 0)
                for f in findings
                if f.vulnerability_type == vtype
            )
            return count * severity_weight

        sorted_types = sorted(seen.items(), key=_score, reverse=True)

        recs: List[str] = []
        for vtype, count in sorted_types[:10]:
            # Use the remediation text from the most severe finding of this type
            best = max(
                (f for f in findings if f.vulnerability_type == vtype),
                key=lambda f: _SEVERITY_SCORE.get(f.severity.lower(), 0),
            )
            recs.append(
                f"[{vtype.upper()} × {count}] {best.remediation}"
            )

        return recs

    def _report_progress(self, phase: str, pct: float) -> None:
        if self._progress_callback:
            try:
                self._progress_callback(phase, pct)
            except Exception:  # noqa: BLE001
                pass
