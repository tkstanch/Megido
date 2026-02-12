"""
Dummy Scanner Engine

A simple demonstration engine that generates sample findings.
Useful for testing the multi-engine architecture without external dependencies.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..base_engine import BaseEngine, EngineResult

logger = logging.getLogger(__name__)


class DummyScannerEngine(BaseEngine):
    """
    Dummy Scanner Engine for demonstration and testing.
    
    This engine doesn't perform real security analysis but demonstrates
    the plugin architecture by generating sample findings.
    
    Useful for:
    - Testing the multi-engine architecture
    - Demonstrating plugin development
    - Quick validation of the orchestrator
    """
    
    @property
    def engine_id(self) -> str:
        return 'dummy_scanner'
    
    @property
    def name(self) -> str:
        return 'Dummy Scanner (Demo)'
    
    @property
    def description(self) -> str:
        return 'Demonstration scanner that generates sample findings for testing'
    
    @property
    def version(self) -> str:
        return '1.0.0'
    
    @property
    def category(self) -> str:
        return 'custom'
    
    @property
    def requires_target_path(self) -> bool:
        return True
    
    def is_available(self) -> bool:
        """Dummy scanner is always available."""
        return True
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Generate sample findings for demonstration.
        
        Args:
            target: Path to scan (validated but not actually scanned)
            config: Optional configuration:
                   - generate_sample_findings: Whether to generate findings (default: True)
                   - num_findings: Number of sample findings to generate (default: 3)
        
        Returns:
            List[EngineResult]: Sample findings
        """
        config = config or self.get_default_config()
        
        # Validate target exists
        target_path = Path(target)
        if not target_path.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        logger.info(f"Running dummy scanner on: {target}")
        
        # Check if we should generate findings
        if not config.get('generate_sample_findings', True):
            logger.info("Sample finding generation is disabled")
            return []
        
        num_findings = config.get('num_findings', 3)
        
        # Generate sample findings
        findings = []
        
        # Sample finding 1: SQL Injection
        findings.append(EngineResult(
            engine_id=self.engine_id,
            engine_name=self.name,
            title='Potential SQL Injection Vulnerability',
            description='Unsanitized user input is used in SQL query construction',
            severity='high',
            confidence=0.85,
            file_path=str(target_path / 'sample_file.py'),
            line_number=42,
            category='injection',
            cwe_id='CWE-89',
            owasp_category='A03:2021-Injection',
            evidence='query = "SELECT * FROM users WHERE id = " + user_input',
            remediation='Use parameterized queries or an ORM to prevent SQL injection',
            references=[
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
            ]
        ))
        
        if num_findings >= 2:
            # Sample finding 2: XSS
            findings.append(EngineResult(
                engine_id=self.engine_id,
                engine_name=self.name,
                title='Cross-Site Scripting (XSS) Vulnerability',
                description='User input is rendered without proper encoding',
                severity='medium',
                confidence=0.75,
                file_path=str(target_path / 'template.html'),
                line_number=15,
                category='xss',
                cwe_id='CWE-79',
                owasp_category='A03:2021-Injection',
                evidence='<div>{{ user_comment }}</div>',
                remediation='Use proper output encoding/escaping for user-controlled data',
                references=[
                    'https://owasp.org/www-community/attacks/xss/',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                ]
            ))
        
        if num_findings >= 3:
            # Sample finding 3: Weak Crypto
            findings.append(EngineResult(
                engine_id=self.engine_id,
                engine_name=self.name,
                title='Use of Weak Cryptographic Algorithm',
                description='MD5 hash function is cryptographically broken',
                severity='low',
                confidence=1.0,
                file_path=str(target_path / 'crypto.py'),
                line_number=28,
                category='crypto',
                cwe_id='CWE-327',
                owasp_category='A02:2021-Cryptographic Failures',
                evidence='import hashlib; hash = hashlib.md5(data)',
                remediation='Use SHA-256 or SHA-3 instead of MD5 for cryptographic purposes',
                references=[
                    'https://owasp.org/www-community/vulnerabilities/Using_a_broken_or_risky_cryptographic_algorithm'
                ]
            ))
        
        logger.info(f"Dummy scanner complete. Generated {len(findings)} sample findings.")
        return findings
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'timeout': 10,
            'generate_sample_findings': True,
            'num_findings': 3
        }
