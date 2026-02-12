"""
Semgrep SAST Engine

Integration with Semgrep - a fast, open-source static analysis tool.
Semgrep finds bugs and enforces code standards with custom rules.

This engine requires the 'semgrep' package to be installed:
    pip install semgrep
    or: https://semgrep.dev/docs/getting-started/
"""

import os
import json
import subprocess
import tempfile
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..base_engine import BaseEngine, EngineResult

logger = logging.getLogger(__name__)


class SemgrepEngine(BaseEngine):
    """
    Semgrep SAST (Static Application Security Testing) Engine.
    
    Runs Semgrep rules to find security vulnerabilities, bugs, and code quality issues.
    Supports multiple languages and custom rulesets.
    
    Features:
    - Multi-language support (Python, JS, Java, Go, C, etc.)
    - Extensive security rule library
    - Custom rule support
    - Fast incremental scanning
    - OWASP Top 10 coverage
    """
    
    @property
    def engine_id(self) -> str:
        return 'semgrep'
    
    @property
    def name(self) -> str:
        return 'Semgrep SAST Scanner'
    
    @property
    def description(self) -> str:
        return 'Fast static analysis for finding bugs and security issues across multiple languages'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def category(self) -> str:
        return 'sast'
    
    @property
    def requires_target_path(self) -> bool:
        return True
    
    @property
    def supports_incremental_scan(self) -> bool:
        return True  # Semgrep supports diff scanning
    
    def is_available(self) -> bool:
        """Check if Semgrep is installed and available."""
        try:
            result = subprocess.run(
                ['semgrep', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of Semgrep."""
        available = self.is_available()
        
        details = {}
        if available:
            try:
                result = subprocess.run(
                    ['semgrep', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                details['version'] = result.stdout.strip()
            except Exception as e:
                details['error'] = str(e)
        
        return {
            'available': available,
            'message': 'Semgrep is installed and ready' if available else 'Semgrep is not installed (pip install semgrep)',
            'details': details
        }
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Scan with Semgrep.
        
        Args:
            target: Path to scan (file or directory)
            config: Optional configuration:
                   - config_name: Ruleset to use (auto, p/security-audit, p/owasp-top-ten, etc.)
                   - severity: Minimum severity (ERROR, WARNING, INFO)
                   - timeout: Scan timeout in seconds
                   - max_memory: Maximum memory in MB
                   - exclude_patterns: Patterns to exclude
        
        Returns:
            List[EngineResult]: Security findings
        """
        if not self.is_available():
            raise RuntimeError("Semgrep is not installed. Install with: pip install semgrep")
        
        config = config or self.get_default_config()
        timeout = config.get('timeout', 300)
        
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        logger.info(f"Starting Semgrep scan on: {target}")
        
        # Create temporary file for results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_file = f.name
        
        try:
            # Build semgrep command
            cmd = [
                'semgrep',
                'scan',
                '--json',
                '--output', report_file,
                '--quiet',
                '--no-git-ignore',  # Scan all files
            ]
            
            # Add config/ruleset
            config_name = config.get('config_name', 'auto')
            cmd.extend(['--config', config_name])
            
            # Add severity filter
            severity = config.get('severity')
            if severity:
                cmd.extend(['--severity', severity])
            
            # Add max memory
            max_memory = config.get('max_memory')
            if max_memory:
                cmd.extend(['--max-memory', str(max_memory)])
            
            # Add exclusions
            exclude_patterns = config.get('exclude_patterns', [])
            for pattern in exclude_patterns:
                cmd.extend(['--exclude', pattern])
            
            # Add target
            cmd.append(str(target_path))
            
            # Run Semgrep
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Semgrep returns exit code based on findings, which is expected
            if result.returncode > 1:
                logger.warning(f"Semgrep exited with code {result.returncode}")
                if result.stderr:
                    logger.debug(f"Stderr: {result.stderr}")
            
            # Parse results
            findings = self._parse_semgrep_output(report_file)
            
            logger.info(f"Semgrep scan complete. Found {len(findings)} issues.")
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out after {timeout} seconds")
            raise RuntimeError(f"Semgrep scan timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}", exc_info=True)
            raise RuntimeError(f"Semgrep scan failed: {e}")
        finally:
            # Clean up temporary report file
            try:
                os.unlink(report_file)
            except (OSError, FileNotFoundError):
                pass
    
    def _parse_semgrep_output(self, report_file: str) -> List[EngineResult]:
        """
        Parse Semgrep JSON output into EngineResult objects.
        
        Args:
            report_file: Path to Semgrep JSON report
        
        Returns:
            List[EngineResult]: Parsed findings
        """
        findings = []
        
        try:
            with open(report_file, 'r') as f:
                data = json.load(f)
            
            # Semgrep output structure: {"results": [...]}
            results = data.get('results', [])
            
            for item in results:
                # Map Semgrep severity
                severity_map = {
                    'ERROR': 'high',
                    'WARNING': 'medium',
                    'INFO': 'low',
                }
                semgrep_severity = item.get('extra', {}).get('severity', 'WARNING')
                severity = severity_map.get(semgrep_severity, 'medium')
                
                # Extract metadata
                check_id = item.get('check_id', 'unknown')
                message = item.get('extra', {}).get('message', '')
                
                # File location
                file_path = item.get('path', '')
                line_start = item.get('start', {}).get('line')
                line_end = item.get('end', {}).get('line')
                
                # Build title from check_id
                title = check_id.split('.')[-1].replace('-', ' ').title()
                if not title:
                    title = 'Security Issue'
                
                # Extract code snippet
                code_lines = item.get('extra', {}).get('lines', '')
                
                # Get metadata
                metadata = item.get('extra', {}).get('metadata', {})
                cwe = metadata.get('cwe', [])[0] if metadata.get('cwe') else None
                owasp = metadata.get('owasp', [])[0] if metadata.get('owasp') else None
                
                # Confidence based on metadata
                confidence = 0.8
                if metadata.get('confidence', '').upper() == 'HIGH':
                    confidence = 0.9
                elif metadata.get('confidence', '').upper() == 'LOW':
                    confidence = 0.5
                
                # References
                references = metadata.get('references', [])
                if metadata.get('source_rule_url'):
                    references.append(metadata.get('source_rule_url'))
                
                finding = EngineResult(
                    engine_id=self.engine_id,
                    engine_name=self.name,
                    title=title,
                    description=message,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_number=line_start,
                    category=metadata.get('category', 'security'),
                    cwe_id=f'CWE-{cwe}' if cwe else None,
                    owasp_category=owasp,
                    evidence=code_lines,
                    remediation=metadata.get('fix') or f"Review and fix the issue in {file_path}:{line_start}",
                    references=references[:5] if references else [],
                    raw_output=item
                )
                
                findings.append(finding)
        
        except FileNotFoundError:
            logger.warning(f"Semgrep report file not found: {report_file}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
        except Exception as e:
            logger.error(f"Error parsing Semgrep results: {e}", exc_info=True)
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Semgrep."""
        return {
            'timeout': 300,
            'config_name': 'auto',  # Auto-detect or use 'p/security-audit', 'p/owasp-top-ten', etc.
            'severity': None,  # Report all severities
            'max_memory': 8000,  # 8GB max
            'exclude_patterns': [
                '*/tests/*',
                '*/test/*',
                '*/node_modules/*',
                '*/vendor/*',
                '*/.venv/*',
                '*/venv/*',
            ]
        }
