"""
Plugin Registry

This module implements the plugin discovery and registry system.
It automatically finds and loads exploit plugins from the plugins/exploits/ directory.

Note: Logging is configured at the module level. Configure Django logging settings
to control the verbosity of plugin discovery and registration messages.
"""

import os
import importlib
import inspect
from typing import Dict, List, Optional, Type
from pathlib import Path
import logging

from .exploit_plugin import ExploitPlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Registry for managing exploit plugins.
    
    This class handles:
    - Automatic discovery of plugin classes in the plugins/exploits/ directory
    - Registration and storage of plugin instances
    - Retrieval of plugins by vulnerability type
    - Plugin lifecycle management
    
    Usage:
        registry = PluginRegistry()
        registry.discover_plugins()
        plugin = registry.get_plugin('sqli')
        payloads = plugin.generate_payloads()
    """
    
    def __init__(self):
        """Initialize the plugin registry."""
        self._plugins: Dict[str, ExploitPlugin] = {}
        self._plugin_classes: Dict[str, Type[ExploitPlugin]] = {}
    
    def discover_plugins(self, plugins_dir: Optional[str] = None) -> int:
        """
        Discover and load all exploit plugins from the specified directory.
        
        This method:
        1. Scans the plugins/exploits/ directory for Python files
        2. Imports each module and looks for ExploitPlugin subclasses
        3. Instantiates and registers each plugin found
        
        Args:
            plugins_dir: Optional path to plugins directory. If not provided,
                        uses the default plugins/exploits/ directory relative
                        to this file.
        
        Returns:
            int: Number of plugins discovered and loaded
        """
        if plugins_dir is None:
            # Default to plugins/exploits/ directory
            current_dir = Path(__file__).parent
            plugins_dir = current_dir / 'exploits'
        else:
            plugins_dir = Path(plugins_dir)
        
        if not plugins_dir.exists():
            logger.warning(f"Plugins directory not found: {plugins_dir}")
            return 0
        
        plugins_found = 0
        
        # Scan for Python files in the plugins directory
        for filepath in plugins_dir.glob('*.py'):
            if filepath.name.startswith('_'):
                # Skip __init__.py and private modules
                continue
            
            module_name = filepath.stem
            
            try:
                # Import the module
                # Construct the full module path
                module_path = f'scanner.plugins.exploits.{module_name}'
                
                try:
                    module = importlib.import_module(module_path)
                except ImportError:
                    # Try alternative import path
                    module_path = f'plugins.exploits.{module_name}'
                    module = importlib.import_module(module_path)
                
                # Find all classes in the module that inherit from ExploitPlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a subclass of ExploitPlugin and not ExploitPlugin itself
                    if (issubclass(obj, ExploitPlugin) and 
                        obj is not ExploitPlugin and
                        obj.__module__ == module.__name__):
                        
                        # Instantiate the plugin
                        try:
                            plugin_instance = obj()
                            vuln_type = plugin_instance.vulnerability_type
                            
                            # Register the plugin
                            self._plugins[vuln_type] = plugin_instance
                            self._plugin_classes[vuln_type] = obj
                            
                            plugins_found += 1
                            logger.info(
                                f"Loaded plugin: {plugin_instance.name} "
                                f"(type: {vuln_type}, version: {plugin_instance.version})"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to instantiate plugin {name} from {module_name}: {e}"
                            )
            
            except Exception as e:
                logger.error(f"Failed to load plugin module {module_name}: {e}")
        
        logger.info(f"Plugin discovery complete. Loaded {plugins_found} plugin(s).")
        return plugins_found
    
    def register_plugin(self, plugin: ExploitPlugin) -> None:
        """
        Manually register a plugin instance.
        
        Args:
            plugin: ExploitPlugin instance to register
        """
        vuln_type = plugin.vulnerability_type
        self._plugins[vuln_type] = plugin
        self._plugin_classes[vuln_type] = type(plugin)
        logger.info(f"Manually registered plugin: {plugin.name} (type: {vuln_type})")
    
    def get_plugin(self, vulnerability_type: str) -> Optional[ExploitPlugin]:
        """
        Retrieve a plugin by vulnerability type.
        
        Args:
            vulnerability_type: The vulnerability type identifier (e.g., 'sqli', 'xss')
        
        Returns:
            ExploitPlugin instance if found, None otherwise
        """
        return self._plugins.get(vulnerability_type)
    
    def list_plugins(self) -> List[Dict[str, str]]:
        """
        List all registered plugins with their information.
        
        Returns:
            List of dictionaries containing plugin information:
            - vulnerability_type: Vulnerability type identifier
            - name: Plugin name
            - description: Plugin description
            - version: Plugin version
        """
        return [
            {
                'vulnerability_type': plugin.vulnerability_type,
                'name': plugin.name,
                'description': plugin.description,
                'version': plugin.version,
            }
            for plugin in self._plugins.values()
        ]
    
    def has_plugin(self, vulnerability_type: str) -> bool:
        """
        Check if a plugin exists for the given vulnerability type.
        
        Args:
            vulnerability_type: Vulnerability type identifier
        
        Returns:
            bool: True if plugin exists, False otherwise
        """
        return vulnerability_type in self._plugins
    
    def get_plugin_count(self) -> int:
        """
        Get the total number of registered plugins.
        
        Returns:
            int: Number of registered plugins
        """
        return len(self._plugins)
    
    def clear_plugins(self) -> None:
        """
        Clear all registered plugins from the registry.
        """
        self._plugins.clear()
        self._plugin_classes.clear()
        logger.info("All plugins cleared from registry.")


# Global singleton instance
_global_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """
    Get the global plugin registry instance.
    
    This function returns a singleton instance of the PluginRegistry.
    On first call, it creates the registry and discovers all plugins.
    
    Returns:
        PluginRegistry: The global plugin registry instance
    """
    global _global_registry
    
    if _global_registry is None:
        _global_registry = PluginRegistry()
        _global_registry.discover_plugins()
    
    return _global_registry


def reset_registry() -> None:
    """
    Reset the global plugin registry.
    
    This is mainly useful for testing purposes.
    """
    global _global_registry
    _global_registry = None
