"""
Tests for Scanner Configuration Module
"""
import unittest
import tempfile
import os
import json
from discover.scanner_config import (
    ScannerConfig,
    ConfigurationBuilder,
    create_default_config,
    create_ci_config,
    create_security_audit_config,
    create_quick_scan_config,
    get_preset_config
)


class TestScannerConfig(unittest.TestCase):
    """Tests for ScannerConfig dataclass."""
    
    def test_default_initialization(self):
        """Test default config initialization."""
        config = ScannerConfig()
        
        self.assertTrue(config.enable_cve_integration)
        self.assertTrue(config.enable_advanced_ml)
        self.assertTrue(config.enable_auto_remediation)
        self.assertFalse(config.enable_container_scanning)
        self.assertEqual(config.max_workers, 5)
    
    def test_custom_initialization(self):
        """Test custom config initialization."""
        config = ScannerConfig(
            enable_cve_integration=False,
            max_workers=10,
            output_dir='./custom_results'
        )
        
        self.assertFalse(config.enable_cve_integration)
        self.assertEqual(config.max_workers, 10)
        self.assertEqual(config.output_dir, './custom_results')
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = ScannerConfig()
        config_dict = config.to_dict()
        
        self.assertIsInstance(config_dict, dict)
        self.assertIn('enable_cve_integration', config_dict)
        self.assertIn('max_workers', config_dict)
    
    def test_to_json(self):
        """Test conversion to JSON."""
        config = ScannerConfig()
        json_str = config.to_json()
        
        self.assertIsInstance(json_str, str)
        
        # Verify it's valid JSON
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)
    
    def test_save_and_load(self):
        """Test save and load from file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, 'test_config.json')
            
            # Create and save
            config = ScannerConfig(max_workers=15, output_dir='./test_output')
            config.save(config_path)
            
            # Verify file exists
            self.assertTrue(os.path.exists(config_path))
            
            # Load
            loaded_config = ScannerConfig.load(config_path)
            
            # Verify values
            self.assertEqual(loaded_config.max_workers, 15)
            self.assertEqual(loaded_config.output_dir, './test_output')
    
    def test_from_env(self):
        """Test loading from environment variables."""
        # Set env vars
        os.environ['SCANNER_MAX_WORKERS'] = '20'
        os.environ['SCANNER_OUTPUT_DIR'] = './env_test'
        os.environ['SCANNER_CVE_INTEGRATION'] = 'false'
        
        config = ScannerConfig.from_env()
        
        self.assertEqual(config.max_workers, 20)
        self.assertEqual(config.output_dir, './env_test')
        self.assertFalse(config.enable_cve_integration)
        
        # Cleanup
        del os.environ['SCANNER_MAX_WORKERS']
        del os.environ['SCANNER_OUTPUT_DIR']
        del os.environ['SCANNER_CVE_INTEGRATION']


class TestConfigurationBuilder(unittest.TestCase):
    """Tests for ConfigurationBuilder."""
    
    def test_initialization(self):
        """Test builder initialization."""
        builder = ConfigurationBuilder()
        config = builder.build()
        
        self.assertIsInstance(config, ScannerConfig)
    
    def test_enable_all_features(self):
        """Test enabling all features."""
        config = (ConfigurationBuilder()
                  .enable_all_features()
                  .build())
        
        self.assertTrue(config.enable_cve_integration)
        self.assertTrue(config.enable_advanced_ml)
        self.assertTrue(config.enable_auto_remediation)
        self.assertTrue(config.enable_container_scanning)
        self.assertTrue(config.enable_distributed_scanning)
    
    def test_disable_all_features(self):
        """Test disabling all features."""
        config = (ConfigurationBuilder()
                  .disable_all_features()
                  .build())
        
        self.assertFalse(config.enable_cve_integration)
        self.assertFalse(config.enable_advanced_ml)
        self.assertFalse(config.enable_auto_remediation)
        self.assertFalse(config.enable_container_scanning)
    
    def test_set_performance_mode_fast(self):
        """Test fast performance mode."""
        config = (ConfigurationBuilder()
                  .set_performance_mode('fast')
                  .build())
        
        self.assertEqual(config.max_workers, 10)
        self.assertTrue(config.enable_distributed_scanning)
        self.assertFalse(config.enable_advanced_ml)
    
    def test_set_performance_mode_balanced(self):
        """Test balanced performance mode."""
        config = (ConfigurationBuilder()
                  .set_performance_mode('balanced')
                  .build())
        
        self.assertEqual(config.max_workers, 5)
        self.assertFalse(config.enable_distributed_scanning)
        self.assertTrue(config.enable_advanced_ml)
    
    def test_set_performance_mode_thorough(self):
        """Test thorough performance mode."""
        config = (ConfigurationBuilder()
                  .set_performance_mode('thorough')
                  .build())
        
        self.assertEqual(config.max_workers, 3)
        self.assertTrue(config.enable_graph_analysis)
        self.assertTrue(config.enable_cloud_scanning)
    
    def test_set_workers(self):
        """Test setting workers."""
        config = (ConfigurationBuilder()
                  .set_workers(12)
                  .build())
        
        self.assertEqual(config.max_workers, 12)
        self.assertEqual(config.num_distributed_workers, 12)
    
    def test_set_output_dir(self):
        """Test setting output directory."""
        config = (ConfigurationBuilder()
                  .set_output_dir('./my_results')
                  .build())
        
        self.assertEqual(config.output_dir, './my_results')
    
    def test_set_severity_filter(self):
        """Test setting severity filter."""
        config = (ConfigurationBuilder()
                  .set_severity_filter('high')
                  .build())
        
        self.assertEqual(config.min_severity, 'high')
    
    def test_add_file_extensions(self):
        """Test adding file extensions."""
        config = (ConfigurationBuilder()
                  .add_file_extensions(['.rs', '.cpp'])
                  .build())
        
        self.assertIn('.rs', config.file_extensions)
        self.assertIn('.cpp', config.file_extensions)
    
    def test_add_exclude_patterns(self):
        """Test adding exclude patterns."""
        config = (ConfigurationBuilder()
                  .add_exclude_patterns(['*/temp/*', '*/cache/*'])
                  .build())
        
        self.assertIn('*/temp/*', config.exclude_patterns)
        self.assertIn('*/cache/*', config.exclude_patterns)
    
    def test_enable_cve_integration(self):
        """Test enabling CVE integration."""
        config = (ConfigurationBuilder()
                  .enable_cve_integration(days=60)
                  .build())
        
        self.assertTrue(config.enable_cve_integration)
        self.assertEqual(config.cve_fetch_days, 60)
    
    def test_enable_auto_pr(self):
        """Test enabling auto PR."""
        config = (ConfigurationBuilder()
                  .enable_auto_pr(branch_prefix='fix-security')
                  .build())
        
        self.assertTrue(config.auto_generate_pr)
        self.assertEqual(config.pr_branch_prefix, 'fix-security')
    
    def test_set_log_level(self):
        """Test setting log level."""
        config = (ConfigurationBuilder()
                  .set_log_level('DEBUG')
                  .build())
        
        self.assertEqual(config.log_level, 'DEBUG')
    
    def test_fluent_interface(self):
        """Test chaining multiple builder methods."""
        config = (ConfigurationBuilder()
                  .enable_all_features()
                  .set_workers(8)
                  .set_output_dir('./results')
                  .set_severity_filter('medium')
                  .set_log_level('INFO')
                  .build())
        
        self.assertEqual(config.max_workers, 8)
        self.assertEqual(config.output_dir, './results')
        self.assertEqual(config.min_severity, 'medium')
        self.assertEqual(config.log_level, 'INFO')
        self.assertTrue(config.enable_cve_integration)


class TestPresetConfigs(unittest.TestCase):
    """Tests for preset configurations."""
    
    def test_create_default_config(self):
        """Test default config creation."""
        config = create_default_config()
        
        self.assertIsInstance(config, ScannerConfig)
        self.assertTrue(config.enable_cve_integration)
        self.assertEqual(config.max_workers, 5)
    
    def test_create_ci_config(self):
        """Test CI config creation."""
        config = create_ci_config()
        
        self.assertTrue(config.enable_distributed_scanning)
        self.assertTrue(config.auto_generate_pr)
        self.assertEqual(config.log_level, 'WARNING')
    
    def test_create_security_audit_config(self):
        """Test security audit config creation."""
        config = create_security_audit_config()
        
        self.assertEqual(config.min_severity, 'low')
        self.assertTrue(config.enable_graph_analysis)
    
    def test_create_quick_scan_config(self):
        """Test quick scan config creation."""
        config = create_quick_scan_config()
        
        self.assertEqual(config.max_workers, 10)
        self.assertFalse(config.enable_cve_integration)
    
    def test_get_preset_config(self):
        """Test getting preset configs."""
        # Test all presets
        presets = ['default', 'ci', 'audit', 'quick']
        
        for preset in presets:
            config = get_preset_config(preset)
            self.assertIsInstance(config, ScannerConfig)
    
    def test_get_preset_config_invalid(self):
        """Test getting invalid preset."""
        with self.assertRaises(ValueError):
            get_preset_config('invalid_preset')


class TestIntegration(unittest.TestCase):
    """Integration tests for configuration module."""
    
    def test_full_workflow(self):
        """Test complete configuration workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, 'workflow_config.json')
            
            # 1. Create config with builder
            config = (ConfigurationBuilder()
                      .enable_all_features()
                      .set_workers(6)
                      .set_output_dir(temp_dir)
                      .build())
            
            # 2. Save to file
            config.save(config_path)
            
            # 3. Load from file
            loaded_config = ScannerConfig.load(config_path)
            
            # 4. Verify
            self.assertEqual(loaded_config.max_workers, 6)
            self.assertEqual(loaded_config.output_dir, temp_dir)
            self.assertTrue(loaded_config.enable_cve_integration)
    
    def test_preset_customization(self):
        """Test customizing a preset config."""
        # Start with CI preset
        config = create_ci_config()
        
        # Customize
        config.max_workers = 16
        config.output_dir = './custom_ci_results'
        
        # Verify
        self.assertEqual(config.max_workers, 16)
        self.assertEqual(config.output_dir, './custom_ci_results')
        # Original CI settings preserved
        self.assertTrue(config.auto_generate_pr)


if __name__ == '__main__':
    unittest.main()
