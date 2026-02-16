"""
Network Configuration

Centralized configuration for network operations, retry logic, and timeouts.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import os
import yaml
from pathlib import Path


@dataclass
class NetworkConfig:
    """
    Configuration for network retry behavior and timeouts.
    
    This configuration controls how the scanner handles network errors,
    retries, and timeouts when connecting to external services.
    
    Attributes:
        max_retries: Maximum number of retry attempts (default: 3)
        base_delay: Base delay in seconds for exponential backoff (default: 1.0)
        max_delay: Maximum delay in seconds between retries (default: 30.0)
        jitter_max: Maximum jitter to add to backoff (default: 1.0)
        default_timeout: Default request timeout in seconds (default: 30)
        retryable_status_codes: HTTP status codes that should trigger retry
        enable_degraded_mode: Continue scanning even if some services fail
    """
    
    # Retry configuration
    max_retries: int = field(default=3)
    base_delay: float = field(default=1.0)
    max_delay: float = field(default=30.0)
    jitter_max: float = field(default=1.0)
    
    # Timeout configuration
    default_timeout: int = field(default=30)
    connect_timeout: int = field(default=10)
    read_timeout: int = field(default=30)
    
    # HTTP status codes that should trigger retry
    retryable_status_codes: List[int] = field(
        default_factory=lambda: [408, 429, 500, 502, 503, 504]
    )
    
    # Degraded mode - continue scanning even if external services fail
    enable_degraded_mode: bool = field(default=True)
    
    # Service-specific timeouts (in seconds)
    service_timeouts: dict = field(default_factory=lambda: {
        'fireblocks_api': 30,
        'callback_server': 60,
        'ngrok_api': 15,
        'collaborator': 45,
        'interactsh': 45,
    })
    
    @classmethod
    def from_env(cls) -> 'NetworkConfig':
        """
        Create configuration from environment variables.
        
        Environment variables:
        - MEGIDO_MAX_RETRIES: Maximum retry attempts
        - MEGIDO_BASE_DELAY: Base delay for backoff (seconds)
        - MEGIDO_MAX_DELAY: Maximum delay between retries (seconds)
        - MEGIDO_DEFAULT_TIMEOUT: Default request timeout (seconds)
        - MEGIDO_DEGRADED_MODE: Enable degraded mode (true/false)
        
        Returns:
            NetworkConfig instance
        """
        return cls(
            max_retries=int(os.getenv('MEGIDO_MAX_RETRIES', '3')),
            base_delay=float(os.getenv('MEGIDO_BASE_DELAY', '1.0')),
            max_delay=float(os.getenv('MEGIDO_MAX_DELAY', '30.0')),
            jitter_max=float(os.getenv('MEGIDO_JITTER_MAX', '1.0')),
            default_timeout=int(os.getenv('MEGIDO_DEFAULT_TIMEOUT', '30')),
            enable_degraded_mode=os.getenv('MEGIDO_DEGRADED_MODE', 'true').lower() == 'true',
        )
    
    @classmethod
    def from_dict(cls, config_dict: dict) -> 'NetworkConfig':
        """
        Create configuration from dictionary.
        
        Args:
            config_dict: Configuration dictionary
            
        Returns:
            NetworkConfig instance
        """
        return cls(**{k: v for k, v in config_dict.items() if k in cls.__dataclass_fields__})
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'NetworkConfig':
        """
        Load configuration from YAML file.
        
        Args:
            yaml_path: Path to YAML configuration file
            
        Returns:
            NetworkConfig instance
        """
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Extract network config from YAML structure
        config_dict = {}
        if 'network' in data:
            config_dict['max_retries'] = data['network'].get('max_retries')
            config_dict['base_delay'] = data['network'].get('base_delay')
            config_dict['max_delay'] = data['network'].get('max_delay')
            config_dict['jitter_max'] = data['network'].get('jitter_max')
        
        if 'timeouts' in data:
            config_dict['default_timeout'] = data['timeouts'].get('default')
            config_dict['connect_timeout'] = data['timeouts'].get('connect')
            config_dict['read_timeout'] = data['timeouts'].get('read')
            if 'services' in data['timeouts']:
                config_dict['service_timeouts'] = data['timeouts']['services']
        
        if 'error_handling' in data:
            config_dict['retryable_status_codes'] = data['error_handling'].get('retryable_status_codes')
            config_dict['enable_degraded_mode'] = data['error_handling'].get('degraded_mode_enabled')
        
        # Remove None values
        config_dict = {k: v for k, v in config_dict.items() if v is not None}
        
        return cls.from_dict(config_dict)
    
    @classmethod
    def from_django_settings(cls) -> 'NetworkConfig':
        """
        Load configuration from Django settings.
        
        Returns:
            NetworkConfig instance
        """
        try:
            from django.conf import settings
            
            return cls(
                max_retries=getattr(settings, 'NETWORK_MAX_RETRIES', 3),
                base_delay=getattr(settings, 'NETWORK_BASE_DELAY', 1.0),
                max_delay=getattr(settings, 'NETWORK_MAX_DELAY', 30.0),
                jitter_max=getattr(settings, 'NETWORK_JITTER_MAX', 1.0),
                default_timeout=getattr(settings, 'NETWORK_DEFAULT_TIMEOUT', 30),
                connect_timeout=getattr(settings, 'NETWORK_CONNECT_TIMEOUT', 10),
                read_timeout=getattr(settings, 'NETWORK_READ_TIMEOUT', 30),
                retryable_status_codes=getattr(settings, 'NETWORK_RETRYABLE_STATUS_CODES', [408, 429, 500, 502, 503, 504]),
                enable_degraded_mode=getattr(settings, 'NETWORK_DEGRADED_MODE_ENABLED', True),
                service_timeouts=getattr(settings, 'NETWORK_SERVICE_TIMEOUTS', {}),
            )
        except ImportError:
            # Django not available, use defaults
            return cls()
    
    def to_dict(self) -> dict:
        """
        Convert configuration to dictionary.
        
        Returns:
            Configuration as dictionary
        """
        return {
            'max_retries': self.max_retries,
            'base_delay': self.base_delay,
            'max_delay': self.max_delay,
            'jitter_max': self.jitter_max,
            'default_timeout': self.default_timeout,
            'connect_timeout': self.connect_timeout,
            'read_timeout': self.read_timeout,
            'retryable_status_codes': self.retryable_status_codes,
            'enable_degraded_mode': self.enable_degraded_mode,
            'service_timeouts': self.service_timeouts,
        }
    
    def get_service_timeout(self, service_name: str) -> int:
        """
        Get timeout for a specific service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Timeout in seconds
        """
        return self.service_timeouts.get(service_name, self.default_timeout)


# Default configuration instance
DEFAULT_CONFIG = NetworkConfig()
