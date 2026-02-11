"""
Bandit SAST Engine

Integration with Bandit - a Python security linter.
Bandit analyzes Python code for common security issues.

This engine requires the 'bandit' package to be installed:
    pip install bandit
"""

import os
import json
import subprocess
import tempfile
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..base_engine import BaseEngine, EngineResult, EngineSeverity

logger = logging.getLogger(__name__)


class BanditEngine(BaseEngine):
    """
    Bandit SAST (Static Application Security Testing) Engine.
    
    Scans Python source code for security vulnerabilities using Bandit.
    Bandit identifies common security issues in Python code.
    
    Features:
    - Static analysis of Python code
    - Confidence and severity ratings
    - CWE mappings
    - Configurable exclusions
    """
    
    @property
    def engine_id(self) -> str:
        return 'bandit'
    
    @property
    def name(self) -> str:
        return 'Bandit SAST Scanner'
    
    @property
    def description(self) -> str:
        return 'Static security analysis for Python code using Bandit'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def category(self) -> str:
        return 'sast'
    
    @property
    def requires_target_path(self) -> bool:
        return True
    
    def is_available(self) -> bool:
        """Check if Bandit is installed and available."""
        try:
            result = subprocess.run(
                ['bandit', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of Bandit."""
        available = self.is_available()
        
        details = {}
        if available:
            try:
                result = subprocess.run(
                    ['bandit', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                details['version'] = result.stdout.strip()
            except Exception as e:
                details['error'] = str(e)
        
        return {
            'available': available,
            'message': 'Bandit is installed and ready' if available else 'Bandit is not installed (pip install bandit)',
            'details': details
        }
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Scan Python code with Bandit.
        
        Args:
            target: Path to Python file or directory to scan
            config: Optional configuration:
                   - severity_threshold: Minimum severity (low, medium, high)
                   - confidence_threshold: Minimum confidence (low, medium, high)
                   - exclude_patterns: List of path patterns to exclude
                   - timeout: Scan timeout in seconds
        
        Returns:
            List[EngineResult]: Security findings
        """
        if not self.is_available():
            raise RuntimeError("Bandit is not installed. Install with: pip install bandit")
        
        config = config or self.get_default_config()
        timeout = config.get('timeout', 180)
        
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        logger.info(f"Starting Bandit scan on: {target}")
        
        # Build bandit command
        cmd = ['bandit']
        if target_path.is_dir():
            cmd.append('-r')
        cmd.extend([target, '-f', 'json'])
        
        # Add severity filter
        severity_threshold = config.get('severity_threshold', 'low')
        if severity_threshold == 'medium':
            cmd.append('-l')
        elif severity_threshold == 'high':
            cmd.append('-ll')
        
        # Add confidence filter
        confidence_threshold = config.get('confidence_threshold', 'low')
        if confidence_threshold == 'medium':
            cmd.append('-i')
        elif confidence_threshold == 'high':
            cmd.append('-ii')
        
        # Add exclusions
        exclude_patterns = config.get('exclude_patterns', [])
        for pattern in exclude_patterns:
            cmd.extend(['--exclude', pattern])
        
        # Run Bandit
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Bandit returns exit code 1 if issues are found, which is expected
            if result.returncode not in [0, 1]:
                logger.warning(f"Bandit exited with code {result.returncode}")
            
            # Parse results
            findings = self._parse_bandit_output(result.stdout)
            
            logger.info(f"Bandit scan complete. Found {len(findings)} issues.")
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error(f"Bandit scan timed out after {timeout} seconds")
            raise RuntimeError(f"Bandit scan timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}", exc_info=True)
            raise RuntimeError(f"Bandit scan failed: {e}")
    
    def _parse_bandit_output(self, output: str) -> List[EngineResult]:
        """
        Parse Bandit JSON output into EngineResult objects.
        
        Args:
            output: JSON output from Bandit
        
        Returns:
            List[EngineResult]: Parsed findings
        """
        findings = []
        
        try:
            data = json.loads(output)
            results = data.get('results', [])
            
            for item in results:
                # Map Bandit severity to our severity
                severity_map = {
                    'LOW': 'low',
                    'MEDIUM': 'medium',
                    'HIGH': 'high',
                }
                severity = severity_map.get(item.get('issue_severity', 'MEDIUM'), 'medium')
                
                # Calculate confidence (Bandit has LOW, MEDIUM, HIGH confidence)
                confidence_map = {
                    'LOW': 0.3,
                    'MEDIUM': 0.6,
                    'HIGH': 0.9,
                }
                confidence = confidence_map.get(item.get('issue_confidence', 'MEDIUM'), 0.6)
                
                finding = EngineResult(
                    engine_id=self.engine_id,
                    engine_name=self.name,
                    title=item.get('test_name', 'Security Issue'),
                    description=item.get('issue_text', ''),
                    severity=severity,
                    confidence=confidence,
                    file_path=item.get('filename'),
                    line_number=item.get('line_number'),
                    category='code_security',
                    cwe_id=item.get('cwe', {}).get('id') if isinstance(item.get('cwe'), dict) else None,
                    evidence=item.get('code', ''),
                    remediation=f"Review the code at {item.get('filename')}:{item.get('line_number')} "
                               f"and apply Bandit's recommendation: {item.get('test_name')}",
                    references=[
                        item.get('more_info', '')
                    ] if item.get('more_info') else [],
                    raw_output=item
                )
                
                findings.append(finding)
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Bandit output: {e}")
            # Try to extract any useful information from plain text
            if output:
                logger.debug(f"Raw output: {output[:500]}")
        except Exception as e:
            logger.error(f"Error parsing Bandit results: {e}", exc_info=True)
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Bandit."""
        return {
            'timeout': 180,
            'severity_threshold': 'low',
            'confidence_threshold': 'low',
            'exclude_patterns': [
                '*/tests/*',
                '*/venv/*',
                '*/.venv/*',
                '*/node_modules/*'
            ]
        }
