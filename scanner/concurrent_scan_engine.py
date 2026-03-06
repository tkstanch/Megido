"""
Concurrent Scan Engine

Extends the base ScanEngine to run vulnerability detection plugins in parallel
using a thread pool, dramatically reducing scan time for large targets.

Features:
- Concurrent plugin execution via ``concurrent.futures.ThreadPoolExecutor``
- Per-plugin timeout enforcement
- Isolated error handling (one plugin crash never stops the rest)
- Per-plugin execution metrics (duration, finding count, errors)
- Automatic deduplication of findings via ``scanner.deduplication``
- Drop-in replacement for ``ScanEngine``

Usage::

    from scanner.concurrent_scan_engine import ConcurrentScanEngine

    engine = ConcurrentScanEngine(max_workers=10, plugin_timeout=120)
    findings = engine.scan('https://example.com')
    metrics  = engine.get_scan_metrics()
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from scanner.scan_engine import ScanEngine
from scanner.scan_plugins import VulnerabilityFinding
from scanner.deduplication import deduplicate_and_correlate

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class PluginMetric:
    """Execution metrics for a single plugin run."""
    plugin_id: str
    plugin_name: str
    duration_seconds: float
    finding_count: int
    error: Optional[str] = None


@dataclass
class ScanMetrics:
    """Aggregated performance metrics for a concurrent scan."""
    total_duration_seconds: float
    plugin_count: int
    total_findings_before_dedup: int
    total_findings_after_dedup: int
    plugins: List[PluginMetric] = field(default_factory=list)

    @property
    def dedup_reduction(self) -> int:
        """Number of duplicate findings removed."""
        return self.total_findings_before_dedup - self.total_findings_after_dedup

    @property
    def failed_plugins(self) -> List[PluginMetric]:
        """Return metrics for plugins that raised errors or timed out."""
        return [m for m in self.plugins if m.error is not None]


# ---------------------------------------------------------------------------
# ConcurrentScanEngine
# ---------------------------------------------------------------------------

class ConcurrentScanEngine(ScanEngine):
    """
    Concurrent vulnerability scan engine.

    Runs all registered scan plugins in parallel using a thread pool.
    Results from all plugins are deduplicated automatically.

    Args:
        max_workers: Maximum number of concurrent plugin threads (default: 10).
        plugin_timeout: Per-plugin execution timeout in seconds (default: 120).
    """

    def __init__(self, max_workers: int = 10, plugin_timeout: int = 120) -> None:
        super().__init__()
        self.max_workers = max_workers
        self.plugin_timeout = plugin_timeout
        self._last_metrics: Optional[ScanMetrics] = None
        logger.info(
            "ConcurrentScanEngine initialized (max_workers=%d, plugin_timeout=%ds)",
            max_workers,
            plugin_timeout,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Run all registered plugins concurrently and return deduplicated findings.

        This is a drop-in replacement for ``ScanEngine.scan()``.

        Args:
            url: Target URL to scan.
            config: Optional plugin configuration dictionary.

        Returns:
            Deduplicated list of :class:`~scanner.scan_plugins.VulnerabilityFinding`.
        """
        plugins = self.registry.get_all_plugins()
        plugin_ids = [p.plugin_id for p in plugins]
        return self._run_concurrent(url, plugin_ids, config or {})

    def scan_with_plugins(
        self,
        url: str,
        plugin_ids: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Run a specific subset of plugins concurrently.

        Args:
            url: Target URL to scan.
            plugin_ids: List of plugin IDs to execute.
            config: Optional plugin configuration dictionary.

        Returns:
            Deduplicated list of :class:`~scanner.scan_plugins.VulnerabilityFinding`.
        """
        return self._run_concurrent(url, plugin_ids, config or {})

    def get_scan_metrics(self) -> Optional[ScanMetrics]:
        """
        Return timing and performance data from the most recent scan.

        Returns:
            :class:`ScanMetrics` if a scan has been performed, otherwise ``None``.
        """
        return self._last_metrics

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_concurrent(
        self,
        url: str,
        plugin_ids: List[str],
        config: Dict[str, Any],
    ) -> List[VulnerabilityFinding]:
        """Execute the given plugin IDs concurrently and return deduplicated findings."""
        scan_start = time.monotonic()
        all_findings: List[VulnerabilityFinding] = []
        plugin_metrics: List[PluginMetric] = []

        logger.info(
            "ConcurrentScanEngine: starting scan of %s with %d plugin(s)",
            url,
            len(plugin_ids),
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_plugin = {
                executor.submit(self._run_plugin, plugin_id, url, config): plugin_id
                for plugin_id in plugin_ids
            }

            for future in as_completed(future_to_plugin):
                plugin_id = future_to_plugin[future]
                try:
                    findings, metric = future.result(timeout=self.plugin_timeout)
                    all_findings.extend(findings)
                    plugin_metrics.append(metric)
                except FuturesTimeoutError:
                    plugin = self.registry.get_plugin(plugin_id)
                    pname = plugin.name if plugin else plugin_id
                    logger.error("Plugin %s timed out after %ds", pname, self.plugin_timeout)
                    plugin_metrics.append(
                        PluginMetric(
                            plugin_id=plugin_id,
                            plugin_name=pname,
                            duration_seconds=float(self.plugin_timeout),
                            finding_count=0,
                            error=f"Timed out after {self.plugin_timeout}s",
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    plugin = self.registry.get_plugin(plugin_id)
                    pname = plugin.name if plugin else plugin_id
                    logger.error("Plugin %s raised an unexpected error: %s", pname, exc)
                    plugin_metrics.append(
                        PluginMetric(
                            plugin_id=plugin_id,
                            plugin_name=pname,
                            duration_seconds=0.0,
                            finding_count=0,
                            error=str(exc),
                        )
                    )

        raw_count = len(all_findings)
        deduplicated = deduplicate_and_correlate(all_findings)

        total_duration = time.monotonic() - scan_start
        self._last_metrics = ScanMetrics(
            total_duration_seconds=total_duration,
            plugin_count=len(plugin_ids),
            total_findings_before_dedup=raw_count,
            total_findings_after_dedup=len(deduplicated),
            plugins=plugin_metrics,
        )

        logger.info(
            "ConcurrentScanEngine: scan complete in %.2fs — %d findings (%d after dedup)",
            total_duration,
            raw_count,
            len(deduplicated),
        )
        return deduplicated

    def _run_plugin(
        self,
        plugin_id: str,
        url: str,
        config: Dict[str, Any],
    ):
        """
        Run a single plugin and return (findings, metric).

        Designed to be called inside a thread-pool worker.
        """
        plugin = self.registry.get_plugin(plugin_id)
        if plugin is None:
            logger.warning("Plugin not found: %s", plugin_id)
            return [], PluginMetric(
                plugin_id=plugin_id,
                plugin_name=plugin_id,
                duration_seconds=0.0,
                finding_count=0,
                error="Plugin not found in registry",
            )

        start = time.monotonic()
        try:
            findings = plugin.scan(url, config)
            duration = time.monotonic() - start
            logger.debug(
                "Plugin %s completed in %.2fs with %d finding(s)",
                plugin.name,
                duration,
                len(findings),
            )
            return findings, PluginMetric(
                plugin_id=plugin_id,
                plugin_name=plugin.name,
                duration_seconds=duration,
                finding_count=len(findings),
            )
        except Exception as exc:  # noqa: BLE001
            duration = time.monotonic() - start
            logger.error("Plugin %s raised an error: %s", plugin.name, exc)
            return [], PluginMetric(
                plugin_id=plugin_id,
                plugin_name=plugin.name,
                duration_seconds=duration,
                finding_count=0,
                error=str(exc),
            )
