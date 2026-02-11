"""
Tests for Multi-Engine Plugin Architecture

Tests for the engine plugin system including:
- Base engine interface
- Engine registry and discovery
- Configuration management
- Engine orchestrator
"""

import os
import json
import tempfile
import unittest
from pathlib import Path
from typing import List, Dict, Any, Optional

from scanner.engine_plugins.base_engine import BaseEngine, EngineResult, EngineSeverity
from scanner.engine_plugins.engine_registry import EngineRegistry, reset_engine_registry
from scanner.engine_plugins.config_manager import ConfigManager
from scanner.engine_plugins.engine_orchestrator import EngineOrchestrator


class TestEngine(BaseEngine):
    """Test engine for unit tests"""
    
    def __init__(self, engine_id='test_engine', should_fail=False):
        super().__init__()
        self._id = engine_id
        self._should_fail = should_fail
    
    @property
    def engine_id(self) -> str:
        return self._id
    
    @property
    def name(self) -> str:
        return f'Test Engine ({self._id})'
    
    @property
    def description(self) -> str:
        return 'Test engine for unit tests'
    
    @property
    def category(self) -> str:
        return 'custom'
    
    def scan(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[EngineResult]:
        if self._should_fail:
            raise RuntimeError("Test engine intentionally failed")
        
        return [
            EngineResult(
                engine_id=self.engine_id,
                engine_name=self.name,
                title='Test Finding',
                description='This is a test finding',
                severity='medium',
                confidence=0.8
            )
        ]


class TestBaseEngine(unittest.TestCase):
    """Tests for BaseEngine interface"""
    
    def test_engine_creation(self):
        """Test creating an engine instance"""
        engine = TestEngine()
        self.assertEqual(engine.engine_id, 'test_engine')
        self.assertEqual(engine.name, 'Test Engine (test_engine)')
        self.assertEqual(engine.category, 'custom')
        self.assertTrue(engine.is_available())
    
    def test_engine_scan(self):
        """Test engine scan method"""
        engine = TestEngine()
        results = engine.scan('/tmp')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, 'Test Finding')
        self.assertEqual(results[0].severity, 'medium')
    
    def test_engine_health_status(self):
        """Test engine health status"""
        engine = TestEngine()
        status = engine.get_health_status()
        
        self.assertIn('available', status)
        self.assertTrue(status['available'])
        self.assertIn('message', status)


class TestEngineRegistry(unittest.TestCase):
    """Tests for EngineRegistry"""
    
    def setUp(self):
        """Set up test registry"""
        reset_engine_registry()
        self.registry = EngineRegistry()
    
    def test_manual_registration(self):
        """Test manually registering an engine"""
        engine = TestEngine()
        self.registry.register_engine(engine)
        
        self.assertEqual(self.registry.get_engine_count(), 1)
        self.assertTrue(self.registry.has_engine('test_engine'))
        
        retrieved = self.registry.get_engine('test_engine')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.engine_id, 'test_engine')
    
    def test_list_engines(self):
        """Test listing all engines"""
        engine1 = TestEngine('engine1')
        engine2 = TestEngine('engine2')
        
        self.registry.register_engine(engine1)
        self.registry.register_engine(engine2)
        
        engines = self.registry.list_engines()
        self.assertEqual(len(engines), 2)
        
        engine_ids = [e['engine_id'] for e in engines]
        self.assertIn('engine1', engine_ids)
        self.assertIn('engine2', engine_ids)
    
    def test_get_engines_by_category(self):
        """Test filtering engines by category"""
        engine1 = TestEngine('engine1')
        self.registry.register_engine(engine1)
        
        sast_engines = self.registry.get_engines_by_category('sast')
        custom_engines = self.registry.get_engines_by_category('custom')
        
        self.assertEqual(len(sast_engines), 0)
        self.assertEqual(len(custom_engines), 1)
    
    def test_clear_engines(self):
        """Test clearing all engines"""
        engine = TestEngine()
        self.registry.register_engine(engine)
        
        self.assertEqual(self.registry.get_engine_count(), 1)
        
        self.registry.clear_engines()
        self.assertEqual(self.registry.get_engine_count(), 0)


class TestConfigManager(unittest.TestCase):
    """Tests for ConfigManager"""
    
    def setUp(self):
        """Set up test config manager"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temp files"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_yaml_config_loading(self):
        """Test loading YAML configuration"""
        config_path = os.path.join(self.temp_dir, 'test_config.yaml')
        
        config_content = """
engines:
  engine1:
    enabled: true
    config:
      timeout: 100
  engine2:
    enabled: false
"""
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        manager = ConfigManager(config_path)
        
        self.assertTrue(manager.is_engine_enabled('engine1'))
        self.assertFalse(manager.is_engine_enabled('engine2'))
        
        engine1_config = manager.get_engine_config('engine1')
        self.assertEqual(engine1_config['timeout'], 100)
    
    def test_json_config_loading(self):
        """Test loading JSON configuration"""
        config_path = os.path.join(self.temp_dir, 'test_config.json')
        
        config_content = {
            'engines': {
                'engine1': {
                    'enabled': True,
                    'config': {'timeout': 200}
                }
            }
        }
        
        with open(config_path, 'w') as f:
            json.dump(config_content, f)
        
        manager = ConfigManager(config_path)
        
        self.assertTrue(manager.is_engine_enabled('engine1'))
        
        engine1_config = manager.get_engine_config('engine1')
        self.assertEqual(engine1_config['timeout'], 200)
    
    def test_default_config(self):
        """Test default config when no file exists"""
        manager = ConfigManager('/nonexistent/config.yaml')
        
        # All engines enabled by default when no config file is found
        self.assertTrue(manager.is_engine_enabled('any_engine'))
        
        # get_enabled_engines returns a list of explicitly enabled engines
        # An empty list means all engines are enabled by default
        enabled = manager.get_enabled_engines()
        self.assertIsInstance(enabled, list)
    
    def test_update_engine_config(self):
        """Test updating engine configuration"""
        manager = ConfigManager()
        
        manager.update_engine_config('test_engine', enabled=True, config={'key': 'value'})
        
        self.assertTrue(manager.is_engine_enabled('test_engine'))
        
        config = manager.get_engine_config('test_engine')
        self.assertEqual(config['key'], 'value')


class TestEngineOrchestrator(unittest.TestCase):
    """Tests for EngineOrchestrator"""
    
    def setUp(self):
        """Set up test orchestrator"""
        reset_engine_registry()
        self.registry = EngineRegistry()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_orchestrator_with_single_engine(self):
        """Test running orchestrator with one engine"""
        engine = TestEngine('test1')
        self.registry.register_engine(engine)
        
        # Create empty config to ensure all engines are enabled
        config_path = os.path.join(self.temp_dir, 'config.yaml')
        with open(config_path, 'w') as f:
            f.write('engines: {}\n')
        
        orchestrator = EngineOrchestrator(config_path=config_path, registry=self.registry)
        
        results = orchestrator.run_scan(self.temp_dir, parallel=False)
        
        self.assertEqual(results['summary'].total_engines, 1)
        self.assertEqual(results['summary'].successful_engines, 1)
        self.assertEqual(results['summary'].total_findings, 1)
    
    def test_orchestrator_with_multiple_engines(self):
        """Test running orchestrator with multiple engines"""
        engine1 = TestEngine('test1')
        engine2 = TestEngine('test2')
        
        self.registry.register_engine(engine1)
        self.registry.register_engine(engine2)
        
        # Create empty config to ensure all engines are enabled
        config_path = os.path.join(self.temp_dir, 'config.yaml')
        with open(config_path, 'w') as f:
            f.write('engines: {}\n')
        
        orchestrator = EngineOrchestrator(config_path=config_path, registry=self.registry)
        
        results = orchestrator.run_scan(self.temp_dir, parallel=False)
        
        self.assertEqual(results['summary'].total_engines, 2)
        self.assertEqual(results['summary'].successful_engines, 2)
        self.assertEqual(results['summary'].total_findings, 2)
    
    def test_orchestrator_with_failing_engine(self):
        """Test orchestrator handles engine failures gracefully"""
        engine1 = TestEngine('test1', should_fail=False)
        engine2 = TestEngine('test2', should_fail=True)
        
        self.registry.register_engine(engine1)
        self.registry.register_engine(engine2)
        
        # Create empty config to ensure all engines are enabled
        config_path = os.path.join(self.temp_dir, 'config.yaml')
        with open(config_path, 'w') as f:
            f.write('engines: {}\n')
        
        orchestrator = EngineOrchestrator(config_path=config_path, registry=self.registry)
        
        results = orchestrator.run_scan(self.temp_dir, parallel=False)
        
        self.assertEqual(results['summary'].total_engines, 2)
        self.assertEqual(results['summary'].successful_engines, 1)
        self.assertEqual(results['summary'].failed_engines, 1)
        self.assertEqual(results['summary'].total_findings, 1)
    
    def test_orchestrator_parallel_execution(self):
        """Test parallel execution of engines"""
        engine1 = TestEngine('test1')
        engine2 = TestEngine('test2')
        
        self.registry.register_engine(engine1)
        self.registry.register_engine(engine2)
        
        # Create empty config to ensure all engines are enabled
        config_path = os.path.join(self.temp_dir, 'config.yaml')
        with open(config_path, 'w') as f:
            f.write('engines: {}\n')
        
        orchestrator = EngineOrchestrator(config_path=config_path, registry=self.registry)
        
        results = orchestrator.run_scan(self.temp_dir, parallel=True, max_workers=2)
        
        self.assertEqual(results['summary'].total_engines, 2)
        self.assertEqual(results['summary'].successful_engines, 2)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestBaseEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestEngineRegistry))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigManager))
    suite.addTests(loader.loadTestsFromTestCase(TestEngineOrchestrator))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
