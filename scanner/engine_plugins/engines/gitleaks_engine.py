"""
GitLeaks Secrets Scanner Engine

Integration with GitLeaks - a SAST tool for detecting hardcoded secrets.
GitLeaks scans code, git history, and files for secrets like API keys, passwords, etc.

This engine requires the 'gitleaks' binary to be installed:
    brew install gitleaks  (macOS)
    or download from: https://github.com/gitleaks/gitleaks
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


class GitLeaksEngine(BaseEngine):
    """
    GitLeaks Secrets Detection Engine.
    
    Scans source code and git repositories for hardcoded secrets like:
    - API keys
    - Passwords
    - Tokens
    - Private keys
    - Database credentials
    
    Features:
    - Regex-based secret detection
    - Entropy analysis
    - Git history scanning
    - Custom rules support
    """
    
    @property
    def engine_id(self) -> str:
        return 'gitleaks'
    
    @property
    def name(self) -> str:
        return 'GitLeaks Secrets Scanner'
    
    @property
    def description(self) -> str:
        return 'Detects hardcoded secrets, API keys, and credentials in source code'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def category(self) -> str:
        return 'secrets'
    
    @property
    def requires_target_path(self) -> bool:
        return True
    
    def is_available(self) -> bool:
        """Check if GitLeaks is installed and available."""
        try:
            result = subprocess.run(
                ['gitleaks', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of GitLeaks."""
        available = self.is_available()
        
        details = {}
        if available:
            try:
                result = subprocess.run(
                    ['gitleaks', 'version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                details['version'] = result.stdout.strip()
            except Exception as e:
                details['error'] = str(e)
        
        return {
            'available': available,
            'message': 'GitLeaks is installed and ready' if available else 'GitLeaks is not installed (https://github.com/gitleaks/gitleaks)',
            'details': details
        }
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Scan for secrets with GitLeaks.
        
        Args:
            target: Path to file or directory to scan
            config: Optional configuration:
                   - timeout: Scan timeout in seconds
                   - exclude_patterns: List of path patterns to exclude
                   - scan_git_history: Whether to scan git history (default: False)
        
        Returns:
            List[EngineResult]: Secret findings
        """
        if not self.is_available():
            raise RuntimeError("GitLeaks is not installed. See: https://github.com/gitleaks/gitleaks")
        
        config = config or self.get_default_config()
        timeout = config.get('timeout', 300)
        
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        logger.info(f"Starting GitLeaks scan on: {target}")
        
        # Create temporary file for results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_file = f.name
        
        try:
            # Build gitleaks command
            cmd = [
                'gitleaks',
                'detect',
                '--source', str(target_path),
                '--report-format', 'json',
                '--report-path', report_file,
                '--no-banner',
                '--exit-code', '0'  # Don't fail on findings
            ]
            
            # Add verbose flag for debugging
            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--verbose')
            
            # Run GitLeaks
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # GitLeaks returns exit code 1 if leaks are found, which is expected
            # We use --exit-code 0 to always get 0 on success
            if result.returncode != 0:
                logger.warning(f"GitLeaks exited with code {result.returncode}")
                logger.debug(f"Stderr: {result.stderr}")
            
            # Parse results
            findings = self._parse_gitleaks_output(report_file)
            
            logger.info(f"GitLeaks scan complete. Found {len(findings)} secrets.")
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error(f"GitLeaks scan timed out after {timeout} seconds")
            raise RuntimeError(f"GitLeaks scan timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"GitLeaks scan failed: {e}", exc_info=True)
            raise RuntimeError(f"GitLeaks scan failed: {e}")
        finally:
            # Clean up temporary report file
            try:
                os.unlink(report_file)
            except:
                pass
    
    def _parse_gitleaks_output(self, report_file: str) -> List[EngineResult]:
        """
        Parse GitLeaks JSON output into EngineResult objects.
        
        Args:
            report_file: Path to GitLeaks JSON report
        
        Returns:
            List[EngineResult]: Parsed findings
        """
        findings = []
        
        try:
            with open(report_file, 'r') as f:
                data = json.load(f)
            
            # GitLeaks output is an array of finding objects
            if not isinstance(data, list):
                logger.warning("GitLeaks report is not a list")
                return findings
            
            for item in data:
                # All secrets are considered HIGH severity by default
                severity = 'high'
                
                # Adjust severity based on entropy (if available)
                entropy = item.get('Entropy', 0)
                if entropy < 3.0:
                    severity = 'medium'
                elif entropy < 2.0:
                    severity = 'low'
                
                finding = EngineResult(
                    engine_id=self.engine_id,
                    engine_name=self.name,
                    title=f"Hardcoded Secret: {item.get('RuleID', 'Unknown')}",
                    description=item.get('Description', 'Potential hardcoded secret detected'),
                    severity=severity,
                    confidence=0.8,  # GitLeaks has good detection accuracy
                    file_path=item.get('File'),
                    line_number=item.get('StartLine'),
                    category='secrets',
                    evidence=item.get('Secret', '***REDACTED***')[:50] + '...' if item.get('Secret') else None,
                    remediation=(
                        f"Remove the hardcoded secret from {item.get('File')}:{item.get('StartLine')}. "
                        "Store secrets in environment variables or a secure secrets management system. "
                        "Rotate the exposed secret immediately if this code is in production."
                    ),
                    references=[
                        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'
                    ],
                    raw_output=item
                )
                
                findings.append(finding)
        
        except FileNotFoundError:
            logger.warning(f"GitLeaks report file not found: {report_file}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse GitLeaks output: {e}")
        except Exception as e:
            logger.error(f"Error parsing GitLeaks results: {e}", exc_info=True)
        
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for GitLeaks."""
        return {
            'timeout': 300,
            'exclude_patterns': [
                '*/node_modules/*',
                '*/.git/*',
                '*/vendor/*'
            ],
            'scan_git_history': False
        }
