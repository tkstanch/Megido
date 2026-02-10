"""
Enterprise Scanner Configuration Module

Provides easy-to-use configuration interfaces for customizing scanner behavior:
- File-based configuration (YAML/JSON)
- Environment variable configuration
- Programmatic API configuration
- UI-friendly configuration builder
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict


@dataclass
class ScannerConfig:
    """
    Configuration dataclass for Enterprise Scanner.
    
    All settings with sensible defaults for easy customization.
    """
    # Core Features
    enable_cve_integration: bool = True
    enable_advanced_ml: bool = True
    enable_auto_remediation: bool = True
    enable_container_scanning: bool = False
    enable_distributed_scanning: bool = False
    
    # Advanced Features (from parent scanners)
    enable_ai_ml: bool = True
    enable_risk_scoring: bool = True
    enable_compliance_mapping: bool = True
    enable_dashboard_generation: bool = True
    enable_sarif_output: bool = True
    enable_graph_analysis: bool = False
    enable_cloud_scanning: bool = False
    enable_realtime_monitoring: bool = False
    
    # Performance Settings
    max_workers: int = 5
    num_distributed_workers: int = 4
    cache_duration_hours: int = 24
    timeout: int = 10
    
    # Scanning Scope
    file_extensions: List[str] = field(default_factory=lambda: [
        '.py', '.js', '.java', '.go', '.rb', '.php', 
        '.env', '.config', '.yml', '.yaml', '.json',
        '.xml', '.properties', '.conf'
    ])
    
    exclude_patterns: List[str] = field(default_factory=lambda: [
        '*/node_modules/*',
        '*/venv/*',
        '*/dist/*',
        '*/build/*',
        '*/.git/*',
        '*/__pycache__/*',
        '*.min.js',
        '*.bundle.js'
    ])
    
    # Severity Filters
    min_severity: str = 'low'  # low, medium, high, critical
    
    # Output Settings
    output_dir: str = './scan_results'
    generate_json: bool = True
    generate_html: bool = True
    generate_sarif: bool = True
    generate_csv: bool = False
    
    # CVE Settings
    cve_fetch_days: int = 30
    cve_keywords: List[str] = field(default_factory=lambda: [])
    
    # Remediation Settings
    auto_generate_pr: bool = False
    pr_branch_prefix: str = 'security-fix'
    
    # Reporting
    verbose: bool = False
    log_level: str = 'INFO'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert config to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def save(self, path: str):
        """Save configuration to file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logging.info(f"Configuration saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'ScannerConfig':
        """Load configuration from file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)
    
    @classmethod
    def from_env(cls) -> 'ScannerConfig':
        """Load configuration from environment variables."""
        config = cls()
        
        # Core features
        if os.getenv('SCANNER_CVE_INTEGRATION'):
            config.enable_cve_integration = os.getenv('SCANNER_CVE_INTEGRATION', 'true').lower() == 'true'
        
        if os.getenv('SCANNER_ADVANCED_ML'):
            config.enable_advanced_ml = os.getenv('SCANNER_ADVANCED_ML', 'true').lower() == 'true'
        
        if os.getenv('SCANNER_AUTO_REMEDIATION'):
            config.enable_auto_remediation = os.getenv('SCANNER_AUTO_REMEDIATION', 'true').lower() == 'true'
        
        # Performance
        if os.getenv('SCANNER_MAX_WORKERS'):
            config.max_workers = int(os.getenv('SCANNER_MAX_WORKERS', '5'))
        
        # Output
        if os.getenv('SCANNER_OUTPUT_DIR'):
            config.output_dir = os.getenv('SCANNER_OUTPUT_DIR', './scan_results')
        
        # Logging
        if os.getenv('SCANNER_LOG_LEVEL'):
            config.log_level = os.getenv('SCANNER_LOG_LEVEL', 'INFO')
        
        return config


class ConfigurationBuilder:
    """
    Fluent interface for building scanner configurations.
    
    Example:
        config = (ConfigurationBuilder()
                  .enable_all_features()
                  .set_workers(8)
                  .set_output_dir('./results')
                  .build())
    """
    
    def __init__(self):
        """Initialize builder with default config."""
        self._config = ScannerConfig()
    
    def enable_all_features(self) -> 'ConfigurationBuilder':
        """Enable all scanner features."""
        self._config.enable_cve_integration = True
        self._config.enable_advanced_ml = True
        self._config.enable_auto_remediation = True
        self._config.enable_container_scanning = True
        self._config.enable_distributed_scanning = True
        self._config.enable_ai_ml = True
        self._config.enable_risk_scoring = True
        self._config.enable_compliance_mapping = True
        self._config.enable_dashboard_generation = True
        self._config.enable_sarif_output = True
        return self
    
    def disable_all_features(self) -> 'ConfigurationBuilder':
        """Disable all optional features (minimal scan)."""
        self._config.enable_cve_integration = False
        self._config.enable_advanced_ml = False
        self._config.enable_auto_remediation = False
        self._config.enable_container_scanning = False
        self._config.enable_distributed_scanning = False
        self._config.enable_ai_ml = False
        self._config.enable_graph_analysis = False
        self._config.enable_cloud_scanning = False
        return self
    
    def set_performance_mode(self, mode: str) -> 'ConfigurationBuilder':
        """
        Set performance mode.
        
        Args:
            mode: 'fast', 'balanced', or 'thorough'
        """
        if mode == 'fast':
            self._config.max_workers = 10
            self._config.enable_distributed_scanning = True
            self._config.num_distributed_workers = 8
            self._config.enable_advanced_ml = False
            self._config.enable_cve_integration = False
        elif mode == 'balanced':
            self._config.max_workers = 5
            self._config.enable_distributed_scanning = False
            self._config.enable_advanced_ml = True
            self._config.enable_cve_integration = True
        elif mode == 'thorough':
            self._config.max_workers = 3
            self._config.enable_distributed_scanning = False
            self._config.enable_advanced_ml = True
            self._config.enable_cve_integration = True
            self._config.enable_graph_analysis = True
            self._config.enable_cloud_scanning = True
        return self
    
    def set_workers(self, num_workers: int) -> 'ConfigurationBuilder':
        """Set number of workers."""
        self._config.max_workers = num_workers
        self._config.num_distributed_workers = num_workers
        return self
    
    def set_output_dir(self, output_dir: str) -> 'ConfigurationBuilder':
        """Set output directory."""
        self._config.output_dir = output_dir
        return self
    
    def set_severity_filter(self, min_severity: str) -> 'ConfigurationBuilder':
        """Set minimum severity filter."""
        self._config.min_severity = min_severity
        return self
    
    def add_file_extensions(self, extensions: List[str]) -> 'ConfigurationBuilder':
        """Add file extensions to scan."""
        self._config.file_extensions.extend(extensions)
        return self
    
    def add_exclude_patterns(self, patterns: List[str]) -> 'ConfigurationBuilder':
        """Add exclude patterns."""
        self._config.exclude_patterns.extend(patterns)
        return self
    
    def enable_cve_integration(self, days: int = 30) -> 'ConfigurationBuilder':
        """Enable CVE integration."""
        self._config.enable_cve_integration = True
        self._config.cve_fetch_days = days
        return self
    
    def enable_auto_pr(self, branch_prefix: str = 'security-fix') -> 'ConfigurationBuilder':
        """Enable automatic PR generation."""
        self._config.auto_generate_pr = True
        self._config.pr_branch_prefix = branch_prefix
        return self
    
    def set_log_level(self, level: str) -> 'ConfigurationBuilder':
        """Set logging level."""
        self._config.log_level = level
        return self
    
    def build(self) -> ScannerConfig:
        """Build and return the configuration."""
        return self._config


def create_default_config() -> ScannerConfig:
    """Create default configuration."""
    return ScannerConfig()


def create_ci_config() -> ScannerConfig:
    """Create CI/CD optimized configuration."""
    return (ConfigurationBuilder()
            .enable_all_features()
            .set_performance_mode('fast')
            .set_workers(8)
            .enable_auto_pr()
            .set_log_level('WARNING')
            .build())


def create_security_audit_config() -> ScannerConfig:
    """Create security audit configuration."""
    return (ConfigurationBuilder()
            .enable_all_features()
            .set_performance_mode('thorough')
            .set_severity_filter('low')
            .build())


def create_quick_scan_config() -> ScannerConfig:
    """Create quick scan configuration."""
    return (ConfigurationBuilder()
            .disable_all_features()
            .set_performance_mode('fast')
            .build())


# Preset configurations
PRESET_CONFIGS = {
    'default': create_default_config,
    'ci': create_ci_config,
    'audit': create_security_audit_config,
    'quick': create_quick_scan_config,
}


def get_preset_config(preset: str) -> ScannerConfig:
    """
    Get a preset configuration.
    
    Args:
        preset: One of 'default', 'ci', 'audit', 'quick'
        
    Returns:
        ScannerConfig instance
    """
    if preset not in PRESET_CONFIGS:
        raise ValueError(f"Unknown preset: {preset}. Available: {list(PRESET_CONFIGS.keys())}")
    
    return PRESET_CONFIGS[preset]()


# Example usage
if __name__ == '__main__':
    # Example 1: Default config
    config = create_default_config()
    print("Default Config:")
    print(config.to_json())
    
    # Example 2: Builder pattern
    config = (ConfigurationBuilder()
              .enable_all_features()
              .set_workers(8)
              .set_output_dir('./my_results')
              .build())
    print("\nCustom Config:")
    print(config.to_json())
    
    # Example 3: Load from environment
    config = ScannerConfig.from_env()
    print("\nConfig from ENV:")
    print(config.to_json())
    
    # Example 4: Presets
    for preset_name in PRESET_CONFIGS.keys():
        config = get_preset_config(preset_name)
        print(f"\n{preset_name.upper()} Preset:")
        print(f"  Workers: {config.max_workers}")
        print(f"  CVE Integration: {config.enable_cve_integration}")
        print(f"  ML: {config.enable_advanced_ml}")
