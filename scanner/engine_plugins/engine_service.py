"""
Engine Service Layer

Integrates the multi-engine plugin architecture with Django models and persistence.
Provides high-level API for running scans and storing results.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from django.utils import timezone
from django.db import transaction

from scanner.models import EngineScan, EngineExecution, EngineFinding
from scanner.engine_plugins import EngineOrchestrator, get_engine_registry
from scanner.engine_plugins.base_engine import EngineResult

logger = logging.getLogger(__name__)


class EngineService:
    """
    Service class for managing multi-engine vulnerability scans.
    
    Provides:
    - Scan execution with database persistence
    - Result storage and retrieval
    - Historical tracking
    - Deduplication
    """
    
    def __init__(self):
        """Initialize the engine service"""
        self.orchestrator = EngineOrchestrator()
        self.registry = get_engine_registry()
    
    def create_scan(
        self,
        target_path: str,
        target_type: str = 'path',
        engine_ids: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        parallel: bool = True,
        max_workers: int = 4,
        created_by: Optional[str] = None
    ) -> EngineScan:
        """
        Create a new engine scan in the database.
        
        Args:
            target_path: Path or URL to scan
            target_type: Type of target (path, url, git)
            engine_ids: Optional list of specific engine IDs to run
            categories: Optional list of categories to filter
            parallel: Whether to run engines in parallel
            max_workers: Maximum parallel workers
            created_by: User who created the scan
        
        Returns:
            EngineScan: Created scan object
        """
        # Determine enabled engines
        if engine_ids:
            enabled_engines = engine_ids
        elif categories:
            # Get all engines in specified categories
            enabled_engines = []
            for cat in categories:
                engines = self.registry.get_engines_by_category(cat)
                enabled_engines.extend([e.engine_id for e in engines])
        else:
            enabled_engines = self.orchestrator.get_enabled_engines()
        
        # Create scan record
        scan = EngineScan.objects.create(
            target_path=target_path,
            target_type=target_type,
            status='pending',
            enabled_engines=enabled_engines,
            engine_categories=categories or [],
            parallel_execution=parallel,
            max_workers=max_workers,
            created_by=created_by,
            config_snapshot={
                'engine_ids': engine_ids,
                'categories': categories,
                'parallel': parallel,
                'max_workers': max_workers,
            }
        )
        
        logger.info(f"Created engine scan {scan.id} for target: {target_path}")
        return scan
    
    @transaction.atomic
    def execute_scan(
        self,
        scan: EngineScan,
        engine_ids: Optional[List[str]] = None,
        categories: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute a scan and persist results to database.
        
        Args:
            scan: EngineScan object to execute
            engine_ids: Optional list of specific engines to run
            categories: Optional list of categories to filter
        
        Returns:
            Dict: Execution results with summary
        """
        try:
            # Update scan status
            scan.status = 'running'
            scan.save(update_fields=['status'])
            
            logger.info(f"Starting execution of scan {scan.id}")
            
            # Run the scan
            results = self.orchestrator.run_scan(
                target=scan.target_path,
                categories=categories or scan.engine_categories,
                engine_ids=engine_ids or scan.enabled_engines,
                parallel=scan.parallel_execution,
                max_workers=scan.max_workers
            )
            
            # Store results
            self._store_results(scan, results)
            
            # Update scan with summary
            summary = results['summary']
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.execution_time = summary.execution_time
            scan.total_engines_run = summary.total_engines
            scan.successful_engines = summary.successful_engines
            scan.failed_engines = summary.failed_engines
            scan.total_findings = summary.total_findings
            scan.findings_by_severity = summary.findings_by_severity
            scan.save()
            
            logger.info(
                f"Scan {scan.id} completed. "
                f"Engines: {summary.successful_engines}/{summary.total_engines}, "
                f"Findings: {summary.total_findings}"
            )
            
            return {
                'scan_id': scan.id,
                'status': 'completed',
                'summary': summary.to_dict(),
                'findings_count': summary.total_findings
            }
        
        except Exception as e:
            logger.error(f"Scan {scan.id} failed: {e}", exc_info=True)
            
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.save(update_fields=['status', 'completed_at'])
            
            raise
    
    def _store_results(self, scan: EngineScan, results: Dict[str, Any]) -> None:
        """
        Store scan results in database.
        
        Args:
            scan: EngineScan object
            results: Results from orchestrator
        """
        # Store engine executions
        for engine_result in results['engine_results']:
            execution = EngineExecution.objects.create(
                engine_scan=scan,
                engine_id=engine_result.engine_id,
                engine_name=engine_result.engine_name,
                engine_category=self._get_engine_category(engine_result.engine_id),
                status='success' if engine_result.success else 'failed',
                completed_at=timezone.now(),
                execution_time=engine_result.execution_time,
                findings_count=len(engine_result.findings) if engine_result.success else 0,
                error_message=engine_result.error if not engine_result.success else None,
            )
            
            # Store findings for successful executions
            if engine_result.success:
                self._store_findings(scan, execution, engine_result.findings)
        
        # Perform deduplication
        self._deduplicate_findings(scan)
    
    def _store_findings(
        self,
        scan: EngineScan,
        execution: EngineExecution,
        findings: List[EngineResult]
    ) -> None:
        """
        Store findings in database.
        
        Args:
            scan: EngineScan object
            execution: EngineExecution object
            findings: List of EngineResult objects
        """
        for finding in findings:
            EngineFinding.objects.create(
                engine_scan=scan,
                engine_execution=execution,
                engine_id=finding.engine_id,
                engine_name=finding.engine_name,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                confidence=finding.confidence,
                file_path=finding.file_path,
                line_number=finding.line_number,
                url=finding.url,
                category=finding.category,
                cwe_id=finding.cwe_id,
                cve_id=finding.cve_id,
                owasp_category=finding.owasp_category,
                evidence=finding.evidence,
                remediation=finding.remediation,
                references=finding.references,
                raw_output=finding.raw_output or {},
                discovered_at=finding.timestamp if finding.timestamp else timezone.now()
            )
    
    def _get_engine_category(self, engine_id: str) -> str:
        """Get engine category from registry"""
        engine = self.registry.get_engine(engine_id)
        return engine.category if engine else 'custom'
    
    def _deduplicate_findings(self, scan: EngineScan) -> None:
        """
        Deduplicate findings within a scan.
        
        Args:
            scan: EngineScan object
        """
        findings = EngineFinding.objects.filter(engine_scan=scan)
        
        # Group by hash
        hash_groups = {}
        for finding in findings:
            hash_key = finding.finding_hash
            if hash_key not in hash_groups:
                hash_groups[hash_key] = []
            hash_groups[hash_key].append(finding)
        
        # Mark duplicates
        for hash_key, group in hash_groups.items():
            if len(group) > 1:
                # Keep the first one as original
                original = group[0]
                for duplicate in group[1:]:
                    duplicate.is_duplicate = True
                    duplicate.duplicate_of = original
                    duplicate.save(update_fields=['is_duplicate', 'duplicate_of'])
                
                logger.info(f"Marked {len(group) - 1} duplicates for hash {hash_key}")
    
    def get_scan_summary(self, scan_id: int) -> Dict[str, Any]:
        """
        Get summary of a scan.
        
        Args:
            scan_id: Scan ID
        
        Returns:
            Dict: Scan summary
        """
        try:
            scan = EngineScan.objects.get(id=scan_id)
            
            return {
                'id': scan.id,
                'target_path': scan.target_path,
                'target_type': scan.target_type,
                'status': scan.status,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'execution_time': scan.execution_time,
                'total_engines_run': scan.total_engines_run,
                'successful_engines': scan.successful_engines,
                'failed_engines': scan.failed_engines,
                'total_findings': scan.total_findings,
                'findings_by_severity': scan.findings_by_severity,
                'enabled_engines': scan.enabled_engines,
            }
        except EngineScan.DoesNotExist:
            return {'error': f'Scan {scan_id} not found'}
    
    def get_scan_findings(
        self,
        scan_id: int,
        severity: Optional[str] = None,
        engine_id: Optional[str] = None,
        exclude_duplicates: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get findings for a scan.
        
        Args:
            scan_id: Scan ID
            severity: Optional severity filter
            engine_id: Optional engine ID filter
            exclude_duplicates: Whether to exclude duplicate findings
        
        Returns:
            List[Dict]: List of findings
        """
        queryset = EngineFinding.objects.filter(engine_scan_id=scan_id)
        
        if severity:
            queryset = queryset.filter(severity=severity)
        
        if engine_id:
            queryset = queryset.filter(engine_id=engine_id)
        
        if exclude_duplicates:
            queryset = queryset.filter(is_duplicate=False)
        
        findings = []
        for finding in queryset:
            findings.append({
                'id': finding.id,
                'title': finding.title,
                'description': finding.description,
                'severity': finding.severity,
                'confidence': finding.confidence,
                'engine_name': finding.engine_name,
                'file_path': finding.file_path,
                'line_number': finding.line_number,
                'url': finding.url,
                'category': finding.category,
                'cwe_id': finding.cwe_id,
                'cve_id': finding.cve_id,
                'evidence': finding.evidence,
                'remediation': finding.remediation,
                'status': finding.status,
            })
        
        return findings
    
    def list_available_engines(self) -> List[Dict[str, Any]]:
        """
        List all available engines.
        
        Returns:
            List[Dict]: Engine information
        """
        return self.orchestrator.list_available_engines()
    
    def get_scan_history(
        self,
        limit: int = 10,
        target_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get scan history.
        
        Args:
            limit: Number of scans to return
            target_path: Optional target path filter
        
        Returns:
            List[Dict]: Scan history
        """
        queryset = EngineScan.objects.all()[:limit]
        
        if target_path:
            queryset = queryset.filter(target_path=target_path)
        
        history = []
        for scan in queryset:
            history.append({
                'id': scan.id,
                'target_path': scan.target_path,
                'status': scan.status,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'total_findings': scan.total_findings,
                'successful_engines': scan.successful_engines,
            })
        
        return history
