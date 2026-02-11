"""
Scan Plugin Registry

This module implements plugin discovery and registry for scan plugins.
It automatically finds and loads scan plugins from the scan_plugins/detectors/ directory.

The registry provides:
- Automatic plugin discovery
- Plugin lifecycle management
- Plugin retrieval by ID
- Plugin listing and metadata

Note: Configure Django logging to control plugin discovery verbosity.
"""

import os
import importlib
import inspect
import logging
from typing import Dict, List, Optional, Type
from pathlib import Path

from .base_scan_plugin import BaseScanPlugin

logger = logging.getLogger(__name__)


class ScanPluginRegistry:
    """
    Registry for managing scan plugins.
    
    This class handles:
    - Automatic discovery of plugin classes in scan_plugins/detectors/
    - Registration and storage of plugin instances
    - Retrieval of plugins by ID
    - Plugin lifecycle management
    
    Usage:
        registry = ScanPluginRegistry()
        registry.discover_plugins()
        plugin = registry.get_plugin('xss_scanner')
        findings = plugin.scan('https://example.com')
    """
    
    def __init__(self):
        """Initialize the scan plugin registry."""
        self._plugins: Dict[str, BaseScanPlugin] = {}
        self._plugin_classes: Dict[str, Type[BaseScanPlugin]] = {}
    
    def discover_plugins(self, plugins_dir: Optional[str] = None) -> int:
        """
        Discover and load all scan plugins from the specified directory.
        
        This method:
        1. Scans the scan_plugins/detectors/ directory for Python files
        2. Imports each module and looks for BaseScanPlugin subclasses
        3. Instantiates and registers each plugin found
        
        Args:
            plugins_dir: Optional path to plugins directory. If not provided,
                        uses the default scan_plugins/detectors/ directory.
        
        Returns:
            int: Number of plugins discovered and loaded
        """
        if plugins_dir is None:
            # Default to scan_plugins/detectors/ directory
            current_dir = Path(__file__).parent
            plugins_dir = current_dir / 'detectors'
        else:
            plugins_dir = Path(plugins_dir)
        
        if not plugins_dir.exists():
            logger.warning(f"Scan plugins directory not found: {plugins_dir}")
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
                module_path = f'scanner.scan_plugins.detectors.{module_name}'
                
                try:
                    module = importlib.import_module(module_path)
                except ImportError:
                    # Try alternative import path
                    module_path = f'scan_plugins.detectors.{module_name}'
                    module = importlib.import_module(module_path)
                
                # Find all classes in the module that inherit from BaseScanPlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a subclass of BaseScanPlugin and not BaseScanPlugin itself
                    if (issubclass(obj, BaseScanPlugin) and 
                        obj is not BaseScanPlugin and
                        obj.__module__ == module.__name__):
                        
                        # Instantiate the plugin
                        try:
                            plugin_instance = obj()
                            plugin_id = plugin_instance.plugin_id
                            
                            # Register the plugin
                            self._plugins[plugin_id] = plugin_instance
                            self._plugin_classes[plugin_id] = obj
                            
                            plugins_found += 1
                            logger.info(
                                f"Loaded scan plugin: {plugin_instance.name} "
                                f"(id: {plugin_id}, version: {plugin_instance.version})"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to instantiate scan plugin {name} from {module_name}: {e}"
                            )
            
            except Exception as e:
                logger.error(f"Failed to load scan plugin module {module_name}: {e}")
        
        logger.info(f"Scan plugin discovery complete. Loaded {plugins_found} plugin(s).")
        return plugins_found
    
    def register_plugin(self, plugin: BaseScanPlugin) -> None:
        """
        Manually register a plugin instance.
        
        Args:
            plugin: BaseScanPlugin instance to register
        """
        plugin_id = plugin.plugin_id
        self._plugins[plugin_id] = plugin
        self._plugin_classes[plugin_id] = type(plugin)
        logger.info(f"Manually registered scan plugin: {plugin.name} (id: {plugin_id})")
    
    def get_plugin(self, plugin_id: str) -> Optional[BaseScanPlugin]:
        """
        Retrieve a plugin by its ID.
        
        Args:
            plugin_id: The plugin identifier
        
        Returns:
            BaseScanPlugin instance if found, None otherwise
        """
        return self._plugins.get(plugin_id)
    
    def get_all_plugins(self) -> List[BaseScanPlugin]:
        """
        Get all registered plugins.
        
        Returns:
            List[BaseScanPlugin]: List of all plugin instances
        """
        return list(self._plugins.values())
    
    def list_plugins(self) -> List[Dict[str, str]]:
        """
        List all registered plugins with their information.
        
        Returns:
            List of dictionaries containing plugin information:
            - plugin_id: Plugin identifier
            - name: Plugin name
            - description: Plugin description
            - version: Plugin version
            - vulnerability_types: List of vulnerability types
        """
        return [
            {
                'plugin_id': plugin.plugin_id,
                'name': plugin.name,
                'description': plugin.description,
                'version': plugin.version,
                'vulnerability_types': plugin.vulnerability_types,
                'supports_async': plugin.supports_async,
            }
            for plugin in self._plugins.values()
        ]
    
    def has_plugin(self, plugin_id: str) -> bool:
        """
        Check if a plugin exists with the given ID.
        
        Args:
            plugin_id: Plugin identifier
        
        Returns:
            bool: True if plugin exists, False otherwise
        """
        return plugin_id in self._plugins
    
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
        logger.info("All scan plugins cleared from registry.")


# Global singleton instance
_global_scan_registry: Optional[ScanPluginRegistry] = None


def get_scan_registry() -> ScanPluginRegistry:
    """
    Get the global scan plugin registry instance.
    
    This function returns a singleton instance of the ScanPluginRegistry.
    On first call, it creates the registry and discovers all plugins.
    
    Returns:
        ScanPluginRegistry: The global scan plugin registry instance
    """
    global _global_scan_registry
    
    if _global_scan_registry is None:
        _global_scan_registry = ScanPluginRegistry()
        _global_scan_registry.discover_plugins()
    
    return _global_scan_registry


def reset_scan_registry() -> None:
    """
    Reset the global scan plugin registry.
    
    This is mainly useful for testing purposes.
    """
    global _global_scan_registry
    _global_scan_registry = None
