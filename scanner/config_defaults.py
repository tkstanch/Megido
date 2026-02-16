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
    
    Note: This function performs a shallow merge for most keys, but does a
    one-level deep merge for the 'visual_proof' dictionary to allow partial
    overrides of visual proof settings while keeping other defaults.
    
    Args:
        config: Configuration dictionary (can be None or empty)
        
    Returns:
        dict: Merged configuration with defaults
        
    Examples:
        # Partial visual_proof override
        merge_with_defaults({'visual_proof': {'type': 'gif'}})
        # Returns all defaults but with type='gif'
        
        # Complete override
        merge_with_defaults({'enable_visual_proof': False})
        # Returns all defaults but with enable_visual_proof=False
    """
    merged = copy.deepcopy(DEFAULT_PROOF_CONFIG)
    if config:
        for key, value in config.items():
            if key == 'visual_proof' and isinstance(value, dict) and isinstance(merged.get('visual_proof'), dict):
                # Deep merge visual_proof dict (one level only)
                merged['visual_proof'].update(value)
            else:
                # Replace other values entirely
                merged[key] = value
    return merged
