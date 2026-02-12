"""
Configuration Manager

Manages loading and parsing of engine configuration files (YAML/JSON).
Handles enabling/disabling engines and engine-specific settings.
"""

import os
import json
import yaml
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Manages engine configuration.
    
    Loads configuration from YAML or JSON files and provides
    access to engine settings and enabled/disabled status.
    
    Configuration file format (YAML):
    ```yaml
    engines:
      bandit:
        enabled: true
        config:
          severity_threshold: medium
          exclude_patterns:
            - "*/tests/*"
      
      gitleaks:
        enabled: true
        config:
          timeout: 300
      
      trivy:
        enabled: false
    ```
    
    Or JSON:
    ```json
    {
      "engines": {
        "bandit": {
          "enabled": true,
          "config": {
            "severity_threshold": "medium"
          }
        }
      }
    }
    ```
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the config manager.
        
        Args:
            config_path: Optional path to configuration file.
                        If not provided, looks for default config files.
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """
        Load configuration from file.
        
        Tries to load from:
        1. Specified config_path
        2. scanner/engine_plugins/engines_config.yaml
        3. scanner/engine_plugins/engines_config.json
        4. Falls back to empty config if none found
        """
        if self.config_path:
            # Try user-specified path
            if self._load_file(self.config_path):
                logger.info(f"Loaded config from: {self.config_path}")
                return
        
        # Try default locations
        current_dir = Path(__file__).parent
        
        default_yaml = current_dir / 'engines_config.yaml'
        if default_yaml.exists():
            if self._load_file(str(default_yaml)):
                logger.info(f"Loaded config from default location: {default_yaml}")
                return
        
        default_json = current_dir / 'engines_config.json'
        if default_json.exists():
            if self._load_file(str(default_json)):
                logger.info(f"Loaded config from default location: {default_json}")
                return
        
        # No config file found, use defaults
        logger.info("No config file found, using default configuration (all engines enabled)")
        self.config = {'engines': {}}
    
    def _load_file(self, filepath: str) -> bool:
        """
        Load configuration from a specific file.
        
        Args:
            filepath: Path to config file
        
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            with open(filepath, 'r') as f:
                if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                    self.config = yaml.safe_load(f) or {}
                elif filepath.endswith('.json'):
                    self.config = json.load(f)
                else:
                    logger.error(f"Unsupported config file format: {filepath}")
                    return False
            
            # Validate basic structure
            if not isinstance(self.config, dict):
                logger.error(f"Invalid config format in {filepath}: root must be a dictionary")
                self.config = {}
                return False
            
            return True
        
        except FileNotFoundError:
            logger.debug(f"Config file not found: {filepath}")
            return False
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML config {filepath}: {e}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON config {filepath}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading config from {filepath}: {e}")
            return False
    
    def get_enabled_engines(self) -> List[str]:
        """
        Get list of enabled engine IDs.
        
        Returns:
            List[str]: List of enabled engine IDs.
                      Empty list means all engines are enabled.
        """
        engines_config = self.config.get('engines', {})
        
        # If no engines config, all are enabled
        if not engines_config:
            return []
        
        enabled = []
        for engine_id, engine_config in engines_config.items():
            if isinstance(engine_config, dict):
                # Check if explicitly enabled (default: True if not specified)
                if engine_config.get('enabled', True):
                    enabled.append(engine_id)
            elif engine_config is True:
                # Simple boolean format
                enabled.append(engine_id)
        
        return enabled
    
    def is_engine_enabled(self, engine_id: str) -> bool:
        """
        Check if a specific engine is enabled.
        
        Args:
            engine_id: Engine identifier
        
        Returns:
            bool: True if enabled, False otherwise
        """
        engines_config = self.config.get('engines', {})
        
        # If no engines config, all are enabled by default
        if not engines_config:
            return True
        
        engine_config = engines_config.get(engine_id)
        
        # If engine not in config, it's enabled by default
        if engine_config is None:
            return True
        
        # Check enabled flag
        if isinstance(engine_config, dict):
            return engine_config.get('enabled', True)
        elif isinstance(engine_config, bool):
            return engine_config
        
        return True
    
    def get_engine_config(self, engine_id: str) -> Dict[str, Any]:
        """
        Get configuration for a specific engine.
        
        Args:
            engine_id: Engine identifier
        
        Returns:
            Dict[str, Any]: Engine-specific configuration
        """
        engines_config = self.config.get('engines', {})
        engine_config = engines_config.get(engine_id, {})
        
        if isinstance(engine_config, dict):
            # Return the 'config' section if it exists
            return engine_config.get('config', {})
        
        return {}
    
    def get_global_config(self) -> Dict[str, Any]:
        """
        Get global configuration that applies to all engines.
        
        Returns:
            Dict[str, Any]: Global configuration
        """
        return self.config.get('global', {})
    
    def reload_config(self) -> bool:
        """
        Reload configuration from file.
        
        Returns:
            bool: True if reloaded successfully, False otherwise
        """
        try:
            self._load_config()
            logger.info("Configuration reloaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def save_config(self, filepath: Optional[str] = None) -> bool:
        """
        Save current configuration to file.
        
        Args:
            filepath: Optional path to save to. If not provided,
                     uses the original config_path or default location.
        
        Returns:
            bool: True if saved successfully, False otherwise
        """
        save_path = filepath or self.config_path
        
        if not save_path:
            # Use default location
            current_dir = Path(__file__).parent
            save_path = str(current_dir / 'engines_config.yaml')
        
        try:
            with open(save_path, 'w') as f:
                if save_path.endswith('.json'):
                    json.dump(self.config, f, indent=2)
                else:
                    # Default to YAML
                    yaml.dump(self.config, f, default_flow_style=False)
            
            logger.info(f"Configuration saved to: {save_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to save configuration to {save_path}: {e}")
            return False
    
    def update_engine_config(self, engine_id: str, enabled: Optional[bool] = None,
                           config: Optional[Dict[str, Any]] = None) -> None:
        """
        Update configuration for a specific engine.
        
        Args:
            engine_id: Engine identifier
            enabled: Optional new enabled status
            config: Optional new configuration dict
        """
        if 'engines' not in self.config:
            self.config['engines'] = {}
        
        if engine_id not in self.config['engines']:
            self.config['engines'][engine_id] = {}
        
        engine_config = self.config['engines'][engine_id]
        
        if enabled is not None:
            engine_config['enabled'] = enabled
        
        if config is not None:
            if 'config' not in engine_config:
                engine_config['config'] = {}
            engine_config['config'].update(config)
        
        logger.info(f"Updated configuration for engine: {engine_id}")
