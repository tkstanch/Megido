"""
Safety Engine

Integration with Safety - Python dependency vulnerability scanner.
Safety checks Python dependencies against a database of known security vulnerabilities.

Requires: pip install safety
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


class SafetyEngine(BaseEngine):
    """
    Safety Python Dependency Scanner Engine.
    
    Scans Python dependencies for known security vulnerabilities.
    Checks requirements.txt, Pipfile, pyproject.toml, and installed packages.
    
    Features:
    - Known vulnerability detection in Python packages
    - CVE mappings
    - Severity ratings
    - Remediation advice (update versions)
    """
    
    @property
    def engine_id(self) -> str:
        return 'safety'
    
    @property
    def name(self) -> str:
        return 'Safety Python Dependency Scanner'
    
    @property
    def description(self) -> str:
        return 'Checks Python dependencies for known security vulnerabilities'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def category(self) -> str:
        return 'sca'
    
    @property
    def requires_target_path(self) -> bool:
        return True
    
    def is_available(self) -> bool:
        """Check if Safety is installed"""
        try:
            result = subprocess.run(
                ['safety', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of Safety"""
        available = self.is_available()
        
        details = {}
        if available:
            try:
                result = subprocess.run(
                    ['safety', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                details['version'] = result.stdout.strip()
            except Exception as e:
                details['error'] = str(e)
        
        return {
            'available': available,
            'message': 'Safety is installed and ready' if available else 'Safety is not installed (pip install safety)',
            'details': details
        }
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Scan with Safety.
        
        Args:
            target: Path to scan (directory with requirements.txt or Python project)
            config: Optional configuration:
                   - timeout: Scan timeout in seconds
                   - check_dependencies: List of dependency files to check
        
        Returns:
            List[EngineResult]: Vulnerability findings
        """
        if not self.is_available():
            raise RuntimeError("Safety is not installed. Install with: pip install safety")
        
        config = config or self.get_default_config()
        timeout = config.get('timeout', 180)
        
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        logger.info(f"Starting Safety scan on: {target}")
        
        findings = []
        
        # Find dependency files
        dep_files = self._find_dependency_files(target_path)
        
        if not dep_files:
            logger.warning(f"No Python dependency files found in {target}")
            return findings
        
        # Scan each dependency file
        for dep_file in dep_files:
            try:
                file_findings = self._scan_file(dep_file, timeout)
                findings.extend(file_findings)
            except Exception as e:
                logger.error(f"Error scanning {dep_file}: {e}")
        
        logger.info(f"Safety scan complete. Found {len(findings)} vulnerabilities.")
        return findings
    
    def _find_dependency_files(self, target_path: Path) -> List[Path]:
        """Find Python dependency files"""
        dep_files = []
        
        # Check for common dependency files
        candidates = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements-prod.txt',
            'Pipfile',
            'pyproject.toml',
        ]
        
        if target_path.is_file():
            if target_path.name in candidates:
                dep_files.append(target_path)
        else:
            for candidate in candidates:
                file_path = target_path / candidate
                if file_path.exists():
                    dep_files.append(file_path)
        
        return dep_files
    
    def _scan_file(self, dep_file: Path, timeout: int) -> List[EngineResult]:
        """Scan a single dependency file"""
        findings = []
        
        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_file = f.name
        
        try:
            # Run Safety check
            cmd = [
                'safety',
                'check',
                '--file', str(dep_file),
                '--json',
                '--output', report_file
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Safety returns exit code 64 when vulnerabilities are found
            if result.returncode not in [0, 64]:
                logger.warning(f"Safety exited with code {result.returncode}")
            
            # Parse results
            findings = self._parse_safety_output(report_file, dep_file)
        
        except subprocess.TimeoutExpired:
            logger.error(f"Safety scan timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"Safety scan failed: {e}", exc_info=True)
        finally:
            # Clean up
            try:
                os.unlink(report_file)
            except (OSError, FileNotFoundError):
                pass
        
        return findings
    
    def _parse_safety_output(self, report_file: str, dep_file: Path) -> List[EngineResult]:
        """Parse Safety JSON output"""
        findings = []
        
        try:
            with open(report_file, 'r') as f:
                data = json.load(f)
            
            # Safety output format: list of vulnerability objects
            for vuln in data:
                # Extract package info
                package_name = vuln.get('package', 'Unknown')
                installed_version = vuln.get('installed_version', '')
                affected_version = vuln.get('affected_version', '')
                
                # Extract vulnerability info
                vuln_id = vuln.get('vulnerability_id', vuln.get('id', 'Unknown'))
                cve_id = vuln.get('cve')
                
                # Severity mapping
                severity_map = {
                    'critical': 'critical',
                    'high': 'high',
                    'medium': 'medium',
                    'low': 'low',
                }
                severity = severity_map.get(
                    vuln.get('severity', 'medium').lower(),
                    'medium'
                )
                
                # Build description
                title = vuln.get('advisory', f'Vulnerability in {package_name}')
                description = vuln.get('description', title)
                
                # Build remediation
                safe_version = vuln.get('safe_version')
                if safe_version:
                    remediation = f"Update {package_name} from {installed_version} to {safe_version} or higher"
                else:
                    remediation = f"Review and update {package_name} (current: {installed_version})"
                
                # References
                references = []
                if vuln.get('more_info_url'):
                    references.append(vuln.get('more_info_url'))
                
                finding = EngineResult(
                    engine_id=self.engine_id,
                    engine_name=self.name,
                    title=title[:200],  # Limit title length
                    description=description,
                    severity=severity,
                    confidence=0.9,  # Safety data is reliable
                    file_path=str(dep_file),
                    category='dependency_vulnerability',
                    cve_id=cve_id,
                    evidence=f"Package: {package_name} v{installed_version}, Affected: {affected_version}",
                    remediation=remediation,
                    references=references,
                    raw_output=vuln
                )
                
                findings.append(finding)
        
        except FileNotFoundError:
            logger.warning(f"Safety report file not found: {report_file}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Safety output: {e}")
        except Exception as e:
            logger.error(f"Error parsing Safety results: {e}", exc_info=True)
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Safety"""
        return {
            'timeout': 180,
            'check_dependencies': ['requirements.txt', 'Pipfile', 'pyproject.toml']
        }
