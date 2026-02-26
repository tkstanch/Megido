"""
OSINT Scan Orchestrator

Central orchestrator that manages all OSINT engines with:
  - Configurable module selection
  - Parallel execution via ThreadPoolExecutor
  - Built-in rate limiting per source
  - Dependency-aware execution order
  - Real-time progress tracking
  - Error isolation (one engine failure never aborts the scan)
  - Result caching and deduplication
"""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from django.utils import timezone

from .osint_engines import ENGINE_REGISTRY, EngineResult
from .models import Scan, ScanModule

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    'quick_recon': {
        'description': 'Fast passive reconnaissance — DNS, WHOIS, subdomains, certificates',
        'engines': ['dns', 'whois', 'subdomains', 'certificates'],
        'max_workers': 4,
    },
    'full_scan': {
        'description': 'Comprehensive scan using all available engines',
        'engines': list(ENGINE_REGISTRY.keys()),
        'max_workers': 6,
    },
    'stealth_mode': {
        'description': 'Passive-only sources that do not touch the target directly',
        'engines': ['dns', 'whois', 'subdomains', 'certificates', 'email', 'threat_intel'],
        'max_workers': 3,
    },
    'infrastructure_only': {
        'description': 'Infrastructure and network focus',
        'engines': ['dns', 'whois', 'subdomains', 'certificates', 'cloud_enum', 'threat_intel'],
        'max_workers': 4,
    },
    'people_and_social': {
        'description': 'People and social media intelligence',
        'engines': ['email', 'social_media'],
        'max_workers': 2,
    },
    'web_recon': {
        'description': 'Web application focused reconnaissance',
        'engines': ['technology', 'web_crawler', 'certificates'],
        'max_workers': 3,
    },
}

# Engines that must complete before others can start (dependency chain).
# Key = engine that has prerequisites; value = list of required engine names.
ENGINE_DEPENDENCIES: Dict[str, List[str]] = {
    'technology': ['dns'],
    'web_crawler': ['dns'],
    'cloud_enum': ['dns', 'subdomains'],
}


class ScanOrchestrator:
    """
    Central OSINT scan orchestrator.

    Usage::

        orchestrator = ScanOrchestrator(scan_id=42, config={...})
        results = orchestrator.run('example.com', profile='quick_recon')
    """

    def __init__(
        self,
        scan_id: int,
        config: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[str, str, int, int], None]] = None,
    ):
        """
        Args:
            scan_id: Database ID of the ``Scan`` model instance.
            config: Per-engine configuration (API keys, limits, etc.).
            progress_callback: Called when an engine completes.
                Signature: ``callback(engine_name, status, items_found, total_engines)``.
        """
        self.scan_id = scan_id
        self.config = config or {}
        self.progress_callback = progress_callback
        self.results: Dict[str, EngineResult] = {}
        self._lock = threading.Lock()
        self._completed_engines: List[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        target: str,
        profile: str = 'quick_recon',
        engines: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the scan.

        Args:
            target: Domain or IP to scan.
            profile: Preset scan profile name (see ``SCAN_PROFILES``).
            engines: Override the profile's engine list.

        Returns:
            Aggregated results dict keyed by engine name.
        """
        profile_config = SCAN_PROFILES.get(profile, SCAN_PROFILES['quick_recon'])
        engine_names = engines or profile_config['engines']
        max_workers = profile_config.get('max_workers', 4)

        logger.info(
            "Orchestrator starting scan %d for '%s' using profile '%s' (%d engines)",
            self.scan_id, target, profile, len(engine_names),
        )

        # Separate engines into groups based on dependencies
        independent, dependent = self._partition_engines(engine_names)

        # Run independent engines in parallel
        self._run_parallel(target, independent, max_workers)

        # Run dependent engines after their prerequisites complete
        if dependent:
            self._run_parallel(target, dependent, max_workers)

        aggregated = {name: result.to_dict() for name, result in self.results.items()}
        logger.info("Scan %d completed — %d engines finished", self.scan_id, len(aggregated))
        return aggregated

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _partition_engines(self, engine_names: List[str]):
        """Return (independent_engines, dependent_engines)."""
        independent = []
        dependent = []
        for name in engine_names:
            deps = ENGINE_DEPENDENCIES.get(name, [])
            if deps:
                # Only put in dependent if the prerequisites are actually running
                active_deps = [d for d in deps if d in engine_names]
                if active_deps:
                    dependent.append(name)
                    continue
            independent.append(name)
        return independent, dependent

    def _run_parallel(
        self,
        target: str,
        engine_names: List[str],
        max_workers: int,
    ) -> None:
        """Run a set of engines in parallel using a thread pool."""
        if not engine_names:
            return

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_name = {
                executor.submit(self._run_engine, target, name): name
                for name in engine_names
                if name in ENGINE_REGISTRY
            }
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result()
                    with self._lock:
                        self.results[name] = result
                        self._completed_engines.append(name)
                    self._update_scan_module(name, result)
                    if self.progress_callback:
                        self.progress_callback(
                            name,
                            'completed' if result.success else 'failed',
                            result.items_found,
                            len(future_to_name),
                        )
                except Exception as exc:
                    logger.exception("Engine %s raised an unhandled exception: %s", name, exc)

    def _run_engine(self, target: str, engine_name: str) -> EngineResult:
        """Instantiate and run a single engine, updating DB module status."""
        engine_cls = ENGINE_REGISTRY.get(engine_name)
        if not engine_cls:
            logger.warning("Unknown engine: %s", engine_name)
            return EngineResult(engine_name=engine_name, success=False, errors=[f'Engine not found: {engine_name}'])

        engine_config = self.config.get(engine_name, {})
        engine_config.update({k: v for k, v in self.config.items() if not isinstance(v, dict)})
        engine = engine_cls(config=engine_config)

        self._mark_module_running(engine_name)
        return engine.run(target)

    def _mark_module_running(self, engine_name: str) -> None:
        try:
            ScanModule.objects.update_or_create(
                scan_id=self.scan_id,
                module_name=engine_name,
                defaults={'status': 'running', 'started_at': timezone.now()},
            )
        except Exception as exc:
            logger.debug("Could not update ScanModule for %s: %s", engine_name, exc)

    def _update_scan_module(self, engine_name: str, result: EngineResult) -> None:
        try:
            ScanModule.objects.update_or_create(
                scan_id=self.scan_id,
                module_name=engine_name,
                defaults={
                    'status': 'completed' if result.success else 'failed',
                    'completed_at': timezone.now(),
                    'duration_seconds': result.duration_seconds,
                    'items_found': result.items_found,
                    'error_message': '; '.join(result.errors),
                },
            )
        except Exception as exc:
            logger.debug("Could not update ScanModule for %s: %s", engine_name, exc)


def run_osint_scan(
    scan: Scan,
    target: str,
    profile: str = 'quick_recon',
    engines: Optional[List[str]] = None,
    config: Optional[Dict[str, Any]] = None,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Convenience function to run an OSINT scan and return all engine results.

    Args:
        scan: The ``Scan`` model instance.
        target: Domain or IP to investigate.
        profile: Scan profile (see ``SCAN_PROFILES``).
        engines: Override engine list (optional).
        config: Per-engine / global API key configuration.
        progress_callback: Called after each engine finishes.

    Returns:
        Dictionary of ``{engine_name: result_dict}`` pairs.
    """
    orchestrator = ScanOrchestrator(
        scan_id=scan.pk,
        config=config or {},
        progress_callback=progress_callback,
    )
    return orchestrator.run(target, profile=profile, engines=engines)
