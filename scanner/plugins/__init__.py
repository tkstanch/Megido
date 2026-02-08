"""
Megido Plugin System

This package contains the plugin infrastructure for Megido's exploit registry
and payload generation system.
"""

from .exploit_plugin import ExploitPlugin
from .plugin_registry import PluginRegistry, get_registry, reset_registry
from .payload_generator import PayloadGenerator, get_payload_generator

__all__ = [
    'ExploitPlugin', 
    'PluginRegistry', 
    'PayloadGenerator',
    'get_registry',
    'reset_registry',
    'get_payload_generator',
]
