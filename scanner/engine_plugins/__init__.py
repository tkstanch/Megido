"""
Multi-Engine Plugin Architecture for Megido Vulnerability Scanner

This module provides a unified plugin architecture for running multiple
analysis engines side by side:
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)
- SCA (Software Composition Analysis)
- Secrets Detection
- Custom Scanners

The architecture provides:
- Pluggable engine interface
- Dynamic registry and discovery
- Config-based engine management
- Result aggregation
- Comprehensive logging
"""

from .base_engine import BaseEngine, EngineResult, EngineSeverity
from .engine_registry import EngineRegistry, get_engine_registry
from .engine_orchestrator import EngineOrchestrator

__all__ = [
    'BaseEngine',
    'EngineResult',
    'EngineSeverity',
    'EngineRegistry',
    'get_engine_registry',
    'EngineOrchestrator',
]
