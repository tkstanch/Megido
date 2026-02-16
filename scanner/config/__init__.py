"""
Scanner Configuration Package

Centralized configuration management for the Megido scanner.
"""

from .network_config import NetworkConfig, DEFAULT_CONFIG

__all__ = ['NetworkConfig', 'DEFAULT_CONFIG']
