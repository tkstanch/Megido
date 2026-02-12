"""
Trivy SCA Engine

Integration with Trivy - a comprehensive vulnerability scanner for containers and dependencies.
Trivy can scan:
- Container images
- Filesystem dependencies
- Git repositories
- SBOM files

This engine requires the 'trivy' binary to be installed:
    https://github.com/aquasecurity/trivy
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


class TrivyEngine(BaseEngine):
    """
    Trivy SCA (Software Composition Analysis) Engine.
    
    Scans for vulnerabilities in dependencies, containers, and code.
    Provides CVE information, severity ratings, and remediation advice.
    
    Features:
    - Dependency vulnerability scanning
    - Container image scanning  
    - License detection
    - Secret scanning
    - Configuration scanning
    """
    
    @property
    def engine_id(self) -> str:
        return 'trivy'
    
    @property
    def name(self) -> str:
        return 'Trivy SCA Scanner'
    
    @property
    def description(self) -> str:
        return 'Comprehensive vulnerability scanner for containers, dependencies, and code'
    
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
        """Check if Trivy is installed and available."""
        try:
            result = subprocess.run(
                ['trivy', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of Trivy."""
        available = self.is_available()
        
        details = {}
        if available:
            try:
                result = subprocess.run(
                    ['trivy', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                details['version'] = result.stdout.strip()
            except Exception as e:
                details['error'] = str(e)
        
        return {
            'available': available,
            'message': 'Trivy is installed and ready' if available else 'Trivy is not installed (https://github.com/aquasecurity/trivy)',
            'details': details
        }
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Scan with Trivy.
        
        Args:
            target: Path to scan (directory, file, or container image)
            config: Optional configuration:
                   - scan_types: List of scan types (vuln, config, secret, license)
                   - severity_levels: List of severities to report (CRITICAL, HIGH, MEDIUM, LOW)
                   - timeout: Scan timeout in seconds
                   - skip_db_update: Skip vulnerability database update
        
        Returns:
            List[EngineResult]: Vulnerability findings
        """
        if not self.is_available():
            raise RuntimeError("Trivy is not installed. See: https://github.com/aquasecurity/trivy")
        
        config = config or self.get_default_config()
        timeout = config.get('timeout', 300)
        
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        logger.info(f"Starting Trivy scan on: {target}")
        
        # Create temporary file for results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_file = f.name
        
        try:
            # Build trivy command
            cmd = [
                'trivy',
                'fs',  # Filesystem scan
                '--format', 'json',
                '--output', report_file,
                '--quiet',
            ]
            
            # Add scan types
            scan_types = config.get('scan_types', ['vuln'])
            if scan_types:
                cmd.extend(['--scanners', ','.join(scan_types)])
            
            # Add severity filter
            severity_levels = config.get('severity_levels', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
            if severity_levels:
                cmd.extend(['--severity', ','.join(severity_levels)])
            
            # Skip DB update if configured
            if config.get('skip_db_update', False):
                cmd.append('--skip-db-update')
            
            # Add target
            cmd.append(str(target_path))
            
            # Run Trivy
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode not in [0, 1]:
                logger.warning(f"Trivy exited with code {result.returncode}")
                logger.debug(f"Stderr: {result.stderr}")
            
            # Parse results
            findings = self._parse_trivy_output(report_file)
            
            logger.info(f"Trivy scan complete. Found {len(findings)} vulnerabilities.")
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy scan timed out after {timeout} seconds")
            raise RuntimeError(f"Trivy scan timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}", exc_info=True)
            raise RuntimeError(f"Trivy scan failed: {e}")
        finally:
            # Clean up temporary report file
            try:
                os.unlink(report_file)
            except (OSError, FileNotFoundError):
                pass
    
    def _parse_trivy_output(self, report_file: str) -> List[EngineResult]:
        """
        Parse Trivy JSON output into EngineResult objects.
        
        Args:
            report_file: Path to Trivy JSON report
        
        Returns:
            List[EngineResult]: Parsed findings
        """
        findings = []
        
        try:
            with open(report_file, 'r') as f:
                data = json.load(f)
            
            # Trivy output structure: {"Results": [{"Target": "...", "Vulnerabilities": [...]}]}
            results = data.get('Results', [])
            
            for result in results:
                target = result.get('Target', '')
                vulnerabilities = result.get('Vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    # Map Trivy severity to our severity
                    severity_map = {
                        'CRITICAL': 'critical',
                        'HIGH': 'high',
                        'MEDIUM': 'medium',
                        'LOW': 'low',
                        'UNKNOWN': 'info',
                    }
                    severity = severity_map.get(vuln.get('Severity', 'UNKNOWN'), 'medium')
                    
                    # Extract package and version info
                    pkg_name = vuln.get('PkgName', 'Unknown')
                    installed_version = vuln.get('InstalledVersion', '')
                    fixed_version = vuln.get('FixedVersion', 'Not available')
                    
                    # Build description
                    title = vuln.get('Title') or vuln.get('VulnerabilityID', 'Unknown Vulnerability')
                    description = vuln.get('Description', '')
                    
                    # Build remediation
                    remediation = f"Update {pkg_name} from {installed_version} to {fixed_version}"
                    if vuln.get('Description'):
                        remediation += f"\n\nDetails: {vuln.get('Description')}"
                    
                    # References
                    references = vuln.get('References', [])
                    if vuln.get('PrimaryURL'):
                        references.insert(0, vuln.get('PrimaryURL'))
                    
                    finding = EngineResult(
                        engine_id=self.engine_id,
                        engine_name=self.name,
                        title=title,
                        description=description or f"{pkg_name} has a known vulnerability",
                        severity=severity,
                        confidence=0.9,  # Trivy has high accuracy
                        file_path=target,
                        category='dependency_vulnerability',
                        cve_id=vuln.get('VulnerabilityID'),
                        evidence=f"Package: {pkg_name}, Installed: {installed_version}, Fixed: {fixed_version}",
                        remediation=remediation,
                        references=references[:5] if references else [],  # Limit to 5 refs
                        raw_output=vuln
                    )
                    
                    findings.append(finding)
        
        except FileNotFoundError:
            logger.warning(f"Trivy report file not found: {report_file}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy output: {e}")
        except Exception as e:
            logger.error(f"Error parsing Trivy results: {e}", exc_info=True)
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Trivy."""
        return {
            'timeout': 300,
            'scan_types': ['vuln', 'secret', 'config'],
            'severity_levels': ['CRITICAL', 'HIGH', 'MEDIUM'],
            'skip_db_update': False
        }
