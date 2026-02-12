"""
NPM Audit Engine

Integration with NPM Audit - Node.js dependency vulnerability scanner.
NPM Audit checks Node.js dependencies against a database of known security vulnerabilities.

Requires: npm (comes with Node.js)
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..base_engine import BaseEngine, EngineResult

logger = logging.getLogger(__name__)


class NPMAuditEngine(BaseEngine):
    """
    NPM Audit Node.js Dependency Scanner Engine.
    
    Scans Node.js dependencies for known security vulnerabilities.
    Checks package.json and package-lock.json files.
    
    Features:
    - Known vulnerability detection in npm packages
    - CVE mappings
    - Severity ratings
    - Remediation advice (update versions)
    - Support for workspaces
    """
    
    @property
    def engine_id(self) -> str:
        return 'npm_audit'
    
    @property
    def name(self) -> str:
        return 'NPM Audit Dependency Scanner'
    
    @property
    def description(self) -> str:
        return 'Checks Node.js dependencies for known security vulnerabilities using npm audit'
    
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
        """Check if NPM is installed"""
        try:
            result = subprocess.run(
                ['npm', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of NPM"""
        available = self.is_available()
        
        details = {}
        if available:
            try:
                result = subprocess.run(
                    ['npm', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                details['npm_version'] = result.stdout.strip()
                
                # Check Node version too
                node_result = subprocess.run(
                    ['node', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                details['node_version'] = node_result.stdout.strip()
            except Exception as e:
                details['error'] = str(e)
        
        return {
            'available': available,
            'message': 'NPM is installed and ready' if available else 'NPM is not installed (install Node.js)',
            'details': details
        }
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Scan with NPM Audit.
        
        Args:
            target: Path to scan (directory with package.json)
            config: Optional configuration:
                   - timeout: Scan timeout in seconds
                   - audit_level: Minimum severity level (info, low, moderate, high, critical)
                   - production_only: Only check production dependencies
        
        Returns:
            List[EngineResult]: Vulnerability findings
        """
        if not self.is_available():
            raise RuntimeError("NPM is not installed. Install Node.js from: https://nodejs.org/")
        
        config = config or self.get_default_config()
        timeout = config.get('timeout', 180)
        
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        logger.info(f"Starting NPM Audit scan on: {target}")
        
        # Find package.json files
        package_files = self._find_package_files(target_path)
        
        if not package_files:
            logger.warning(f"No package.json files found in {target}")
            return []
        
        findings = []
        
        # Scan each package.json
        for package_file in package_files:
            try:
                file_findings = self._scan_package(package_file, config, timeout)
                findings.extend(file_findings)
            except Exception as e:
                logger.error(f"Error scanning {package_file}: {e}")
        
        logger.info(f"NPM Audit scan complete. Found {len(findings)} vulnerabilities.")
        return findings
    
    def _find_package_files(self, target_path: Path) -> List[Path]:
        """Find package.json files"""
        package_files = []
        
        if target_path.is_file():
            if target_path.name == 'package.json':
                package_files.append(target_path)
        else:
            # Find all package.json files recursively
            for package_file in target_path.rglob('package.json'):
                # Skip node_modules
                if 'node_modules' not in package_file.parts:
                    package_files.append(package_file)
        
        return package_files
    
    def _scan_package(self, package_file: Path, config: Dict[str, Any], timeout: int) -> List[EngineResult]:
        """Scan a single package.json"""
        findings = []
        
        # Change to package directory
        package_dir = package_file.parent
        
        try:
            # Build npm audit command
            cmd = ['npm', 'audit', '--json']
            
            # Add production-only flag if configured
            if config.get('production_only', False):
                cmd.append('--production')
            
            # Add audit level if configured
            audit_level = config.get('audit_level')
            if audit_level:
                cmd.extend(['--audit-level', audit_level])
            
            # Run npm audit
            result = subprocess.run(
                cmd,
                cwd=str(package_dir),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # npm audit returns non-zero when vulnerabilities are found
            # Parse the JSON output
            findings = self._parse_npm_audit_output(result.stdout, package_file)
        
        except subprocess.TimeoutExpired:
            logger.error(f"NPM Audit scan timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"NPM Audit scan failed: {e}", exc_info=True)
        
        return findings
    
    def _parse_npm_audit_output(self, output: str, package_file: Path) -> List[EngineResult]:
        """Parse NPM Audit JSON output"""
        findings = []
        
        try:
            data = json.loads(output)
            
            # NPM audit v7+ format: vulnerabilities object
            vulnerabilities = data.get('vulnerabilities', {})
            
            for package_name, vuln_data in vulnerabilities.items():
                # Extract vulnerability info
                severity = vuln_data.get('severity', 'moderate').lower()
                
                # Map NPM severity to our severity
                severity_map = {
                    'critical': 'critical',
                    'high': 'high',
                    'moderate': 'medium',
                    'low': 'low',
                    'info': 'info',
                }
                mapped_severity = severity_map.get(severity, 'medium')
                
                # Get via (dependency chain)
                via = vuln_data.get('via', [])
                
                # Build description from via entries
                descriptions = []
                cve_ids = []
                references = []
                
                for via_item in via:
                    if isinstance(via_item, dict):
                        if via_item.get('title'):
                            descriptions.append(via_item.get('title'))
                        if via_item.get('cve'):
                            cve_ids.extend(via_item.get('cve', []))
                        if via_item.get('url'):
                            references.append(via_item.get('url'))
                
                title = f"Vulnerability in {package_name}"
                if descriptions:
                    title = descriptions[0][:200]
                
                description = "; ".join(descriptions) if descriptions else title
                
                # Get fix info
                fix_available = vuln_data.get('fixAvailable', {})
                if isinstance(fix_available, dict):
                    fix_name = fix_available.get('name', package_name)
                    fix_version = fix_available.get('version', 'latest')
                    remediation = f"Update {fix_name} to version {fix_version}"
                elif fix_available:
                    remediation = f"Update {package_name} to fix vulnerability"
                else:
                    remediation = f"No automatic fix available for {package_name}. Manual review required."
                
                # Get range (affected versions)
                version_range = vuln_data.get('range', 'unknown')
                
                finding = EngineResult(
                    engine_id=self.engine_id,
                    engine_name=self.name,
                    title=title,
                    description=description,
                    severity=mapped_severity,
                    confidence=0.9,  # NPM Audit data is reliable
                    file_path=str(package_file),
                    category='dependency_vulnerability',
                    cve_id=cve_ids[0] if cve_ids else None,
                    evidence=f"Package: {package_name}, Affected versions: {version_range}",
                    remediation=remediation,
                    references=references[:5] if references else [],
                    raw_output=vuln_data
                )
                
                findings.append(finding)
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse NPM Audit output: {e}")
        except Exception as e:
            logger.error(f"Error parsing NPM Audit results: {e}", exc_info=True)
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for NPM Audit"""
        return {
            'timeout': 180,
            'audit_level': 'low',  # Report all severities
            'production_only': False
        }
