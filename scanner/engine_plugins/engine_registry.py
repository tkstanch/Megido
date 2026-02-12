"""
Engine Registry

Manages dynamic discovery, registration, and retrieval of scanner engines.
Automatically discovers engines from the engines/ directory.
"""

import os
import importlib
import inspect
import logging
from typing import Dict, List, Optional, Type, Any
from pathlib import Path

from .base_engine import BaseEngine

logger = logging.getLogger(__name__)


class EngineRegistry:
    """
    Registry for managing scanner engines.
    
    This class handles:
    - Automatic discovery of engine classes in engine_plugins/engines/
    - Registration and storage of engine instances
    - Retrieval of engines by ID or category
    - Engine lifecycle management
    
    Usage:
        registry = EngineRegistry()
        registry.discover_engines()
        engine = registry.get_engine('bandit')
        results = engine.scan('/path/to/code')
    """
    
    def __init__(self):
        """Initialize the engine registry."""
        self._engines: Dict[str, BaseEngine] = {}
        self._engine_classes: Dict[str, Type[BaseEngine]] = {}
        self._engines_by_category: Dict[str, List[str]] = {}
    
    def discover_engines(self, engines_dir: Optional[str] = None) -> int:
        """
        Discover and load all engines from the specified directory.
        
        This method:
        1. Scans the engine_plugins/engines/ directory for Python files
        2. Imports each module and looks for BaseEngine subclasses
        3. Instantiates and registers each engine found
        
        Args:
            engines_dir: Optional path to engines directory. If not provided,
                        uses the default engine_plugins/engines/ directory.
        
        Returns:
            int: Number of engines discovered and loaded
        """
        if engines_dir is None:
            # Default to engine_plugins/engines/ directory
            current_dir = Path(__file__).parent
            engines_dir = current_dir / 'engines'
        else:
            engines_dir = Path(engines_dir)
        
        if not engines_dir.exists():
            logger.warning(f"Engines directory not found: {engines_dir}")
            return 0
        
        engines_found = 0
        
        # Scan for Python files in the engines directory
        for filepath in engines_dir.glob('*.py'):
            if filepath.name.startswith('_'):
                # Skip __init__.py and private modules
                continue
            
            module_name = filepath.stem
            
            try:
                # Import the module
                module_path = f'scanner.engine_plugins.engines.{module_name}'
                
                try:
                    module = importlib.import_module(module_path)
                except ImportError as e:
                    # Try alternative import path
                    logger.debug(f"Import failed with {module_path}, trying alternative: {e}")
                    module_path = f'engine_plugins.engines.{module_name}'
                    module = importlib.import_module(module_path)
                
                # Find all classes in the module that inherit from BaseEngine
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a subclass of BaseEngine and not BaseEngine itself
                    if (issubclass(obj, BaseEngine) and 
                        obj is not BaseEngine and
                        obj.__module__ == module.__name__):
                        
                        # Instantiate the engine
                        try:
                            engine_instance = obj()
                            engine_id = engine_instance.engine_id
                            
                            # Register the engine
                            self._engines[engine_id] = engine_instance
                            self._engine_classes[engine_id] = obj
                            
                            # Add to category index
                            category = engine_instance.category
                            if category not in self._engines_by_category:
                                self._engines_by_category[category] = []
                            self._engines_by_category[category].append(engine_id)
                            
                            engines_found += 1
                            logger.info(
                                f"Loaded engine: {engine_instance.name} "
                                f"(id: {engine_id}, category: {category}, version: {engine_instance.version})"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to instantiate engine {name} from {module_name}: {e}",
                                exc_info=True
                            )
            
            except Exception as e:
                logger.error(f"Failed to load engine module {module_name}: {e}", exc_info=True)
        
        logger.info(f"Engine discovery complete. Loaded {engines_found} engine(s).")
        return engines_found
    
    def register_engine(self, engine: BaseEngine) -> None:
        """
        Manually register an engine instance.
        
        Args:
            engine: BaseEngine instance to register
        """
        engine_id = engine.engine_id
        self._engines[engine_id] = engine
        self._engine_classes[engine_id] = type(engine)
        
        # Add to category index
        category = engine.category
        if category not in self._engines_by_category:
            self._engines_by_category[category] = []
        if engine_id not in self._engines_by_category[category]:
            self._engines_by_category[category].append(engine_id)
        
        logger.info(f"Manually registered engine: {engine.name} (id: {engine_id})")
    
    def get_engine(self, engine_id: str) -> Optional[BaseEngine]:
        """
        Retrieve an engine by its ID.
        
        Args:
            engine_id: The engine identifier
        
        Returns:
            BaseEngine instance if found, None otherwise
        """
        return self._engines.get(engine_id)
    
    def get_engines_by_category(self, category: str) -> List[BaseEngine]:
        """
        Get all engines for a specific category.
        
        Args:
            category: Engine category (sast, dast, sca, secrets, etc.)
        
        Returns:
            List[BaseEngine]: List of engines in that category
        """
        engine_ids = self._engines_by_category.get(category, [])
        return [self._engines[eid] for eid in engine_ids if eid in self._engines]
    
    def get_all_engines(self) -> List[BaseEngine]:
        """
        Get all registered engines.
        
        Returns:
            List[BaseEngine]: List of all engine instances
        """
        return list(self._engines.values())
    
    def list_engines(self) -> List[Dict[str, Any]]:
        """
        List all registered engines with their information.
        
        Returns:
            List of dictionaries containing engine information:
            - engine_id: Engine identifier
            - name: Engine name
            - description: Engine description
            - version: Engine version
            - category: Engine category
            - available: Whether engine is available
        """
        return [
            {
                'engine_id': engine.engine_id,
                'name': engine.name,
                'description': engine.description,
                'version': engine.version,
                'category': engine.category,
                'available': engine.is_available(),
                'requires_target_path': engine.requires_target_path,
            }
            for engine in self._engines.values()
        ]
    
    def has_engine(self, engine_id: str) -> bool:
        """
        Check if an engine exists with the given ID.
        
        Args:
            engine_id: Engine identifier
        
        Returns:
            bool: True if engine exists, False otherwise
        """
        return engine_id in self._engines
    
    def get_engine_count(self) -> int:
        """
        Get the total number of registered engines.
        
        Returns:
            int: Number of registered engines
        """
        return len(self._engines)
    
    def get_available_engines(self) -> List[BaseEngine]:
        """
        Get all engines that are available and ready to use.
        
        Returns:
            List[BaseEngine]: List of available engines
        """
        return [engine for engine in self._engines.values() if engine.is_available()]
    
    def clear_engines(self) -> None:
        """
        Clear all registered engines from the registry.
        """
        self._engines.clear()
        self._engine_classes.clear()
        self._engines_by_category.clear()
        logger.info("All engines cleared from registry.")


# Global singleton instance
_global_engine_registry: Optional[EngineRegistry] = None


def get_engine_registry() -> EngineRegistry:
    """
    Get the global engine registry instance.
    
    This function returns a singleton instance of the EngineRegistry.
    On first call, it creates the registry and discovers all engines.
    
    Returns:
        EngineRegistry: The global engine registry instance
    """
    global _global_engine_registry
    
    if _global_engine_registry is None:
        _global_engine_registry = EngineRegistry()
        _global_engine_registry.discover_engines()
    
    return _global_engine_registry


def reset_engine_registry() -> None:
    """
    Reset the global engine registry.
    
    This is mainly useful for testing purposes.
    """
    global _global_engine_registry
    _global_engine_registry = None
