"""
Default configuration values for proof reporting and visual proof capture.

This module provides centralized default configuration values used across
the scanner to ensure consistency.
"""

import copy

# Default proof reporting and visual proof configuration
DEFAULT_PROOF_CONFIG = {
    'enable_proof_reporting': True,
    'enable_visual_proof': True,
    'capture_visual_proof': True,
    'visual_proof': {
        'enabled': True,
        'type': 'auto',
        'duration': 3.0,
        'wait_time': 2.0,
        'viewport': (1280, 720)
    }
}


def get_default_proof_config():
    """
    Get a copy of the default proof configuration.
    
    Returns a copy to prevent accidental modification of the global defaults.
    
    Returns:
        dict: Default proof configuration
    """
    return copy.deepcopy(DEFAULT_PROOF_CONFIG)


def merge_with_defaults(config):
    """
    Merge provided config with defaults, giving priority to provided values.
    
    Args:
        config: Configuration dictionary (can be None or empty)
        
    Returns:
        dict: Merged configuration with defaults
    """
    merged = copy.deepcopy(DEFAULT_PROOF_CONFIG)
    if config:
        for key, value in config.items():
            if key == 'visual_proof' and isinstance(value, dict):
                # Deep merge visual_proof dict
                merged['visual_proof'].update(value)
            else:
                # Replace other values entirely
                merged[key] = value
    return merged
