"""
Async Scan Engine

Provides an async-capable scan engine that runs plugins concurrently using
asyncio and (optionally) aiohttp.  Falls back gracefully to synchronous
execution if async dependencies are unavailable or if called from a non-async
context.

Usage (sync wrapper — drop-in replacement for ScanEngine):

    from scanner.async_scan_engine import AsyncScanEngine
    engine = AsyncScanEngine()
    findings = engine.scan(url, config)
    engine.save_findings_to_db(scan, findings)

Usage (async — from an asyncio context):

    engine = AsyncScanEngine()
    findings = await engine.async_scan(url, config)
"""

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional

from scanner.scan_engine import ScanEngine
from scanner.scan_plugins import VulnerabilityFinding

logger = logging.getLogger(__name__)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    logger.debug("aiohttp not available — async HTTP requests will use sync fallback")


class AsyncScanEngine(ScanEngine):
    """
    Async-capable scan engine that runs detector plugins concurrently.

    Extends :class:`scanner.scan_engine.ScanEngine` so it is a drop-in
    replacement wherever ``ScanEngine`` is used.

    Configuration keys (in addition to per-plugin config):
        - ``max_concurrent_plugins`` (int, default 5): how many plugins to run
          in parallel via asyncio.gather.
        - ``max_concurrent_requests`` (int, default 10): semaphore limit for
          aiohttp sessions (used by plugins that opt-in to async HTTP).
        - ``progress_callback`` (callable, optional): called after each plugin
          completes with ``(plugin_id, findings_count, total_plugins)``.

    If asyncio is unavailable or called outside an event loop the engine
    falls back to sequential synchronous execution identical to ScanEngine.
    """

    def __init__(
        self,
        max_concurrent_plugins: int = 5,
        max_concurrent_requests: int = 10,
    ) -> None:
        super().__init__()
        self.max_concurrent_plugins = max_concurrent_plugins
        self.max_concurrent_requests = max_concurrent_requests
        logger.info(
            "AsyncScanEngine initialised (max_concurrent_plugins=%d, "
            "max_concurrent_requests=%d, aiohttp=%s)",
            max_concurrent_plugins,
            max_concurrent_requests,
            HAS_AIOHTTP,
        )

    # ------------------------------------------------------------------
    # Public sync interface (overrides ScanEngine.scan)
    # ------------------------------------------------------------------

    def scan(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Run all plugins concurrently and return aggregated findings.

        Attempts to run inside an existing event loop or creates one.
        Falls back to sequential sync execution on failure.

        Args:
            url: Target URL.
            config: Shared config dict passed to every plugin.
            progress_callback: Optional ``(plugin_id, count, total) -> None``
                called after each plugin finishes.

        Returns:
            Aggregated list of VulnerabilityFinding objects.
        """
        config = config or {}
        if progress_callback:
            config = dict(config)
            config['progress_callback'] = progress_callback

        try:
            # Try to run in an existing event loop (e.g. Django ASGI worker)
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Schedule as a coroutine in the running loop
                import concurrent.futures
                future = asyncio.run_coroutine_threadsafe(
                    self.async_scan(url, config), loop
                )
                return future.result(timeout=300)
            else:
                return loop.run_until_complete(self.async_scan(url, config))
        except RuntimeError:
            # No event loop available — create one
            return asyncio.run(self.async_scan(url, config))
        except Exception as e:
            logger.warning(
                "Async execution failed (%s); falling back to sync scan", e
            )
            return super().scan(url, config)

    # ------------------------------------------------------------------
    # Async interface
    # ------------------------------------------------------------------

    async def async_scan(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Coroutine that runs all plugins concurrently.

        Args:
            url: Target URL.
            config: Shared plugin config.

        Returns:
            Aggregated list of VulnerabilityFinding objects.
        """
        config = config or {}
        plugins = self.registry.get_all_plugins()
        total = len(plugins)
        progress_callback = config.get('progress_callback')
        semaphore = asyncio.Semaphore(self.max_concurrent_plugins)
        all_findings: List[VulnerabilityFinding] = []

        logger.info(
            "AsyncScanEngine: starting async scan of %s with %d plugin(s)", url, total
        )

        async def run_plugin(plugin):
            async with semaphore:
                loop = asyncio.get_event_loop()
                try:
                    # Run sync plugin in executor to avoid blocking
                    findings = await loop.run_in_executor(
                        None, plugin.scan, url, config
                    )
                    logger.debug(
                        "Plugin %s found %d issue(s)", plugin.name, len(findings)
                    )
                except Exception as exc:
                    logger.error("Plugin %s raised: %s", plugin.name, exc)
                    findings = []
                if progress_callback:
                    try:
                        progress_callback(plugin.plugin_id, len(findings), total)
                    except Exception:
                        pass
                return findings

        tasks = [run_plugin(p) for p in plugins]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)

        logger.info(
            "AsyncScanEngine: scan complete — %d finding(s)", len(all_findings)
        )
        return all_findings

    async def async_scan_with_plugins(
        self,
        url: str,
        plugin_ids: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Run a specific subset of plugins concurrently.

        Args:
            url: Target URL.
            plugin_ids: List of plugin IDs to run.
            config: Shared plugin config.

        Returns:
            Aggregated findings from the selected plugins.
        """
        config = config or {}
        plugins = [
            p for p in self.registry.get_all_plugins()
            if p.plugin_id in plugin_ids
        ]
        if not plugins:
            logger.warning("No plugins matched plugin_ids=%s", plugin_ids)
            return []

        semaphore = asyncio.Semaphore(self.max_concurrent_plugins)
        all_findings: List[VulnerabilityFinding] = []

        async def run_plugin(plugin):
            async with semaphore:
                loop = asyncio.get_event_loop()
                try:
                    return await loop.run_in_executor(None, plugin.scan, url, config)
                except Exception as exc:
                    logger.error("Plugin %s raised: %s", plugin.name, exc)
                    return []

        tasks = [run_plugin(p) for p in plugins]
        results = await asyncio.gather(*tasks)
        for result in results:
            all_findings.extend(result)
        return all_findings


def get_async_scan_engine() -> AsyncScanEngine:
    """
    Factory function that returns a configured AsyncScanEngine.

    Returns:
        AsyncScanEngine instance.
    """
    return AsyncScanEngine()
