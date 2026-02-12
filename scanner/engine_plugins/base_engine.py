"""
Base Engine Interface

Defines the standard interface that all scanner engines must implement.
This ensures consistency across SAST, DAST, SCA, secrets, and custom engines.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class EngineSeverity(Enum):
    """Severity levels for findings"""
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


class EngineCategory(Enum):
    """Categories of analysis engines"""
    SAST = 'sast'  # Static Application Security Testing
    DAST = 'dast'  # Dynamic Application Security Testing
    SCA = 'sca'    # Software Composition Analysis
    SECRETS = 'secrets'  # Secrets Detection
    CONTAINER = 'container'  # Container Security
    CLOUD = 'cloud'  # Cloud Security
    CUSTOM = 'custom'  # Custom Analysis


@dataclass
class EngineResult:
    """
    Standardized result format for all engines.
    
    This ensures consistent output across all analysis engines,
    making it easy to aggregate and report results.
    """
    # Core identification
    engine_id: str  # ID of the engine that generated this result
    engine_name: str  # Human-readable engine name
    
    # Finding details
    title: str  # Brief title of the finding
    description: str  # Detailed description
    severity: str  # Severity level (info, low, medium, high, critical)
    confidence: float = 1.0  # Confidence level 0.0-1.0
    
    # Location information
    file_path: Optional[str] = None  # File where issue was found
    line_number: Optional[int] = None  # Line number in file
    url: Optional[str] = None  # URL for DAST findings
    
    # Additional context
    category: Optional[str] = None  # Category (e.g., 'injection', 'crypto', etc.)
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    cve_id: Optional[str] = None  # Common Vulnerabilities and Exposures ID
    owasp_category: Optional[str] = None  # OWASP Top 10 category
    
    # Evidence and remediation
    evidence: Optional[str] = None  # Evidence/proof of the finding
    remediation: Optional[str] = None  # How to fix the issue
    references: List[str] = field(default_factory=list)  # Reference URLs
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    raw_output: Optional[Dict[str, Any]] = None  # Original engine output
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'engine_id': self.engine_id,
            'engine_name': self.engine_name,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'url': self.url,
            'category': self.category,
            'cwe_id': self.cwe_id,
            'cve_id': self.cve_id,
            'owasp_category': self.owasp_category,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'raw_output': self.raw_output,
        }


class BaseEngine(ABC):
    """
    Base interface for all scanner engines.
    
    All engines (SAST, DAST, SCA, secrets, etc.) must inherit from this class
    and implement the required methods. This provides a consistent interface
    for the orchestrator to manage and execute different types of scanners.
    
    Attributes:
        engine_id: Unique identifier for the engine
        name: Human-readable name
        description: Brief description of what the engine does
        version: Engine version
        category: Engine category (SAST, DAST, SCA, etc.)
    """
    
    def __init__(self):
        """Initialize the engine."""
        pass
    
    @property
    @abstractmethod
    def engine_id(self) -> str:
        """
        Return unique identifier for this engine.
        
        Returns:
            str: Engine identifier (e.g., 'bandit', 'trivy', 'gitleaks')
        """
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return human-readable name of this engine.
        
        Returns:
            str: Engine name (e.g., 'Bandit SAST Scanner')
        """
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """
        Return brief description of what this engine does.
        
        Returns:
            str: Engine description
        """
        pass
    
    @property
    def version(self) -> str:
        """
        Return version of this engine.
        
        Returns:
            str: Version string (default: '1.0.0')
        """
        return '1.0.0'
    
    @property
    @abstractmethod
    def category(self) -> str:
        """
        Return the category of this engine.
        
        Returns:
            str: Category (sast, dast, sca, secrets, container, cloud, custom)
        """
        pass
    
    @property
    def requires_target_path(self) -> bool:
        """
        Indicate if this engine requires a target path (for SAST, SCA).
        
        Returns:
            bool: True if requires path, False if requires URL (for DAST)
        """
        return True
    
    @property
    def supports_incremental_scan(self) -> bool:
        """
        Indicate if this engine supports incremental scanning.
        
        Returns:
            bool: True if supports incremental scans, False otherwise
        """
        return False
    
    @abstractmethod
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        """
        Perform security scan on the target.
        
        This is the main method that implements the scanning logic.
        The target can be a file path, directory, URL, or other target
        depending on the engine type.
        
        Args:
            target: Target to scan (path for SAST/SCA, URL for DAST, etc.)
            config: Optional configuration dictionary:
                   - timeout: int (scan timeout in seconds)
                   - exclude_patterns: List[str] (patterns to exclude)
                   - severity_threshold: str (minimum severity to report)
                   - custom options: Engine-specific settings
        
        Returns:
            List[EngineResult]: List of findings from the scan
        
        Raises:
            Exception: If scan fails or configuration is invalid
        """
        pass
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate the configuration for this engine.
        
        Args:
            config: Configuration dictionary to validate
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        return True
    
    def get_default_config(self) -> Dict[str, Any]:
        """
        Return default configuration for this engine.
        
        Returns:
            Dict[str, Any]: Default configuration values
        """
        return {
            'timeout': 300,  # 5 minutes default
            'severity_threshold': 'low',
        }
    
    def get_required_config_keys(self) -> List[str]:
        """
        Return list of required configuration keys for this engine.
        
        Returns:
            List[str]: List of required configuration key names
        """
        return []
    
    def is_available(self) -> bool:
        """
        Check if this engine is available and properly configured.
        
        This can be used to check if required tools are installed,
        API keys are configured, etc.
        
        Returns:
            bool: True if engine is available, False otherwise
        """
        return True
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get health status of this engine.
        
        Returns:
            Dict[str, Any]: Health status information including:
                          - available: bool
                          - message: str
                          - details: Dict[str, Any]
        """
        return {
            'available': self.is_available(),
            'message': 'Engine is operational' if self.is_available() else 'Engine is not available',
            'details': {}
        }
