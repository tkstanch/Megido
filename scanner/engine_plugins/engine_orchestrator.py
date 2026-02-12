"""
Engine Orchestrator

Orchestrates running multiple scanner engines and aggregates their results.
Handles configuration, execution order, and result formatting.
"""

import logging
import time
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime

from .base_engine import BaseEngine, EngineResult
from .engine_registry import EngineRegistry
from .config_manager import ConfigManager

logger = logging.getLogger(__name__)


@dataclass
class ScanSummary:
    """Summary of a multi-engine scan"""
    total_engines: int
    successful_engines: int
    failed_engines: int
    total_findings: int
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    findings_by_engine: Dict[str, int] = field(default_factory=dict)
    execution_time: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_engines': self.total_engines,
            'successful_engines': self.successful_engines,
            'failed_engines': self.failed_engines,
            'total_findings': self.total_findings,
            'findings_by_severity': self.findings_by_severity,
            'findings_by_category': self.findings_by_category,
            'findings_by_engine': self.findings_by_engine,
            'execution_time': self.execution_time,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
        }


@dataclass
class EngineExecutionResult:
    """Result of executing a single engine"""
    engine_id: str
    engine_name: str
    success: bool
    findings: List[EngineResult] = field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0


class EngineOrchestrator:
    """
    Orchestrates execution of multiple scanner engines.
    
    This class:
    - Loads configuration from config file
    - Manages which engines to run
    - Executes engines in parallel or sequential order
    - Aggregates results from all engines
    - Provides comprehensive logging
    
    Usage:
        orchestrator = EngineOrchestrator()
        results = orchestrator.run_scan('/path/to/target')
        print(f"Found {results['summary']['total_findings']} issues")
    """
    
    def __init__(self, config_path: Optional[str] = None, registry: Optional[EngineRegistry] = None):
        """
        Initialize the orchestrator.
        
        Args:
            config_path: Optional path to configuration file
            registry: Optional engine registry (uses global if not provided)
        """
        self.config_manager = ConfigManager(config_path)
        self.registry = registry if registry else None
        self._initialize_registry()
    
    def _initialize_registry(self):
        """Initialize the engine registry"""
        if self.registry is None:
            from .engine_registry import get_engine_registry
            self.registry = get_engine_registry()
    
    def run_scan(self, target: str, categories: Optional[List[str]] = None,
                 engine_ids: Optional[List[str]] = None,
                 parallel: bool = True, max_workers: int = 4) -> Dict[str, Any]:
        """
        Run a multi-engine scan on the target.
        
        Args:
            target: Target to scan (path or URL depending on engines)
            categories: Optional list of categories to run (sast, dast, sca, etc.)
            engine_ids: Optional list of specific engine IDs to run
            parallel: Whether to run engines in parallel (default: True)
            max_workers: Maximum number of parallel workers (default: 4)
        
        Returns:
            Dict containing:
            - summary: ScanSummary object
            - findings: List of all EngineResult objects
            - engine_results: List of EngineExecutionResult objects
        """
        start_time = datetime.now()
        logger.info(f"Starting multi-engine scan on target: {target}")
        
        # Determine which engines to run
        engines_to_run = self._get_engines_to_run(categories, engine_ids)
        
        if not engines_to_run:
            logger.warning("No engines selected to run")
            return {
                'summary': ScanSummary(
                    total_engines=0,
                    successful_engines=0,
                    failed_engines=0,
                    total_findings=0,
                    start_time=start_time,
                    end_time=datetime.now()
                ),
                'findings': [],
                'engine_results': []
            }
        
        logger.info(f"Selected {len(engines_to_run)} engine(s) to run: {[e.engine_id for e in engines_to_run]}")
        
        # Execute engines
        if parallel:
            engine_results = self._run_engines_parallel(engines_to_run, target, max_workers)
        else:
            engine_results = self._run_engines_sequential(engines_to_run, target)
        
        # Aggregate results
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        all_findings = []
        for result in engine_results:
            all_findings.extend(result.findings)
        
        # Create summary
        summary = self._create_summary(engine_results, all_findings, start_time, end_time, execution_time)
        
        logger.info(f"Scan complete. Found {summary.total_findings} findings across {summary.successful_engines} engines")
        logger.info(f"Total execution time: {execution_time:.2f}s")
        
        return {
            'summary': summary,
            'findings': all_findings,
            'engine_results': engine_results
        }
    
    def _get_engines_to_run(self, categories: Optional[List[str]] = None,
                           engine_ids: Optional[List[str]] = None) -> List[BaseEngine]:
        """
        Determine which engines to run based on config and parameters.
        
        Args:
            categories: Optional list of categories to filter
            engine_ids: Optional list of specific engine IDs
        
        Returns:
            List[BaseEngine]: Engines to run
        """
        # Get enabled engines from config
        enabled_engines = self.config_manager.get_enabled_engines()
        
        # Get all available engines
        all_engines = self.registry.get_all_engines()
        
        # Filter engines
        engines_to_run = []
        for engine in all_engines:
            # Check if engine is enabled in config
            if enabled_engines and engine.engine_id not in enabled_engines:
                logger.debug(f"Skipping disabled engine: {engine.engine_id}")
                continue
            
            # Check if engine is available
            if not engine.is_available():
                logger.warning(f"Engine {engine.engine_id} is not available, skipping")
                continue
            
            # Filter by categories if specified
            if categories and engine.category not in categories:
                logger.debug(f"Skipping engine {engine.engine_id} (category {engine.category} not in filter)")
                continue
            
            # Filter by engine IDs if specified
            if engine_ids and engine.engine_id not in engine_ids:
                logger.debug(f"Skipping engine {engine.engine_id} (not in engine_ids filter)")
                continue
            
            engines_to_run.append(engine)
        
        return engines_to_run
    
    def _run_engines_parallel(self, engines: List[BaseEngine], target: str, max_workers: int) -> List[EngineExecutionResult]:
        """
        Run engines in parallel using ThreadPoolExecutor.
        
        Args:
            engines: List of engines to run
            target: Target to scan
            max_workers: Maximum number of parallel workers
        
        Returns:
            List[EngineExecutionResult]: Results from all engines
        """
        logger.info(f"Running {len(engines)} engines in parallel with {max_workers} workers")
        
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all engine tasks
            future_to_engine = {
                executor.submit(self._run_single_engine, engine, target): engine
                for engine in engines
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_engine):
                engine = future_to_engine[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Exception running engine {engine.engine_id}: {e}", exc_info=True)
                    results.append(EngineExecutionResult(
                        engine_id=engine.engine_id,
                        engine_name=engine.name,
                        success=False,
                        error=str(e)
                    ))
        
        return results
    
    def _run_engines_sequential(self, engines: List[BaseEngine], target: str) -> List[EngineExecutionResult]:
        """
        Run engines sequentially one after another.
        
        Args:
            engines: List of engines to run
            target: Target to scan
        
        Returns:
            List[EngineExecutionResult]: Results from all engines
        """
        logger.info(f"Running {len(engines)} engines sequentially")
        
        results = []
        for engine in engines:
            result = self._run_single_engine(engine, target)
            results.append(result)
        
        return results
    
    def _run_single_engine(self, engine: BaseEngine, target: str) -> EngineExecutionResult:
        """
        Run a single engine and capture its results.
        
        Args:
            engine: Engine to run
            target: Target to scan
        
        Returns:
            EngineExecutionResult: Result from the engine
        """
        logger.info(f"Running engine: {engine.name} (id: {engine.engine_id})")
        
        start_time = time.time()
        try:
            # Get engine-specific config
            engine_config = self.config_manager.get_engine_config(engine.engine_id)
            
            # Run the scan
            findings = engine.scan(target, engine_config)
            
            execution_time = time.time() - start_time
            
            logger.info(
                f"Engine {engine.engine_id} completed successfully. "
                f"Found {len(findings)} findings in {execution_time:.2f}s"
            )
            
            return EngineExecutionResult(
                engine_id=engine.engine_id,
                engine_name=engine.name,
                success=True,
                findings=findings,
                execution_time=execution_time
            )
        
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Engine {engine.engine_id} failed: {e}", exc_info=True)
            
            return EngineExecutionResult(
                engine_id=engine.engine_id,
                engine_name=engine.name,
                success=False,
                error=str(e),
                execution_time=execution_time
            )
    
    def _create_summary(self, engine_results: List[EngineExecutionResult],
                       all_findings: List[EngineResult],
                       start_time: datetime, end_time: datetime,
                       execution_time: float) -> ScanSummary:
        """
        Create a summary of the scan results.
        
        Args:
            engine_results: Results from all engines
            all_findings: All findings from all engines
            start_time: Scan start time
            end_time: Scan end time
            execution_time: Total execution time in seconds
        
        Returns:
            ScanSummary: Summary object
        """
        successful_engines = sum(1 for r in engine_results if r.success)
        failed_engines = sum(1 for r in engine_results if not r.success)
        
        # Count findings by severity
        findings_by_severity = {}
        for finding in all_findings:
            severity = finding.severity
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
        
        # Count findings by category
        findings_by_category = {}
        for finding in all_findings:
            if finding.category:
                category = finding.category
                findings_by_category[category] = findings_by_category.get(category, 0) + 1
        
        # Count findings by engine
        findings_by_engine = {}
        for result in engine_results:
            if result.success:
                findings_by_engine[result.engine_id] = len(result.findings)
        
        return ScanSummary(
            total_engines=len(engine_results),
            successful_engines=successful_engines,
            failed_engines=failed_engines,
            total_findings=len(all_findings),
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
            findings_by_engine=findings_by_engine,
            execution_time=execution_time,
            start_time=start_time,
            end_time=end_time
        )
    
    def get_enabled_engines(self) -> List[str]:
        """
        Get list of enabled engine IDs from config.
        
        Returns:
            List[str]: List of enabled engine IDs
        """
        return self.config_manager.get_enabled_engines()
    
    def list_available_engines(self) -> List[Dict[str, Any]]:
        """
        List all available engines.
        
        Returns:
            List[Dict]: Engine information
        """
        return self.registry.list_engines()
