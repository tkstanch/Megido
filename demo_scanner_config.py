#!/usr/bin/env python3
"""
Scanner Configuration Demo

Demonstrates various ways to configure the Enterprise Scanner:
1. Default configuration
2. Builder pattern
3. Environment variables
4. Preset configurations
5. File-based configuration
"""

import os
import sys
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from discover.scanner_config import (
    ScannerConfig,
    ConfigurationBuilder,
    create_default_config,
    create_ci_config,
    create_security_audit_config,
    create_quick_scan_config,
    get_preset_config
)


def print_section(title):
    """Print section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print('=' * 80)


def demo_1_default_config():
    """Demo 1: Default configuration."""
    print_section("Demo 1: Default Configuration")
    
    config = create_default_config()
    
    print("\n📋 Default Configuration:")
    print(f"   CVE Integration: {config.enable_cve_integration}")
    print(f"   Advanced ML: {config.enable_advanced_ml}")
    print(f"   Auto Remediation: {config.enable_auto_remediation}")
    print(f"   Container Scanning: {config.enable_container_scanning}")
    print(f"   Distributed Scanning: {config.enable_distributed_scanning}")
    print(f"   Max Workers: {config.max_workers}")
    print(f"   Output Dir: {config.output_dir}")


def demo_2_builder_pattern():
    """Demo 2: Builder pattern for custom configuration."""
    print_section("Demo 2: Builder Pattern (Fluent API)")
    
    # Example 1: Enable all features
    print("\n🔧 Configuration 1: All Features Enabled")
    config1 = (ConfigurationBuilder()
               .enable_all_features()
               .set_workers(8)
               .set_output_dir('./comprehensive_scan')
               .build())
    
    print(f"   CVE Integration: {config1.enable_cve_integration}")
    print(f"   Advanced ML: {config1.enable_advanced_ml}")
    print(f"   Container Scanning: {config1.enable_container_scanning}")
    print(f"   Workers: {config1.max_workers}")
    
    # Example 2: Performance-focused
    print("\n⚡ Configuration 2: Fast Performance Mode")
    config2 = (ConfigurationBuilder()
               .set_performance_mode('fast')
               .set_workers(12)
               .build())
    
    print(f"   Workers: {config2.max_workers}")
    print(f"   Distributed: {config2.enable_distributed_scanning}")
    print(f"   Advanced ML: {config2.enable_advanced_ml}")
    
    # Example 3: Security audit
    print("\n🔍 Configuration 3: Thorough Security Audit")
    config3 = (ConfigurationBuilder()
               .set_performance_mode('thorough')
               .set_severity_filter('low')
               .enable_cve_integration(days=60)
               .build())
    
    print(f"   Min Severity: {config3.min_severity}")
    print(f"   CVE Days: {config3.cve_fetch_days}")
    print(f"   Graph Analysis: {config3.enable_graph_analysis}")


def demo_3_preset_configs():
    """Demo 3: Preset configurations."""
    print_section("Demo 3: Preset Configurations")
    
    presets = ['default', 'ci', 'audit', 'quick']
    
    for preset_name in presets:
        config = get_preset_config(preset_name)
        
        print(f"\n📦 {preset_name.upper()} Preset:")
        print(f"   Workers: {config.max_workers}")
        print(f"   CVE Integration: {config.enable_cve_integration}")
        print(f"   Advanced ML: {config.enable_advanced_ml}")
        print(f"   Distributed: {config.enable_distributed_scanning}")


def demo_4_file_based_config():
    """Demo 4: File-based configuration."""
    print_section("Demo 4: File-Based Configuration")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = os.path.join(temp_dir, 'scanner_config.json')
        
        # Create and save config
        print("\n💾 Creating configuration file...")
        config = (ConfigurationBuilder()
                  .enable_all_features()
                  .set_workers(6)
                  .set_output_dir('./file_based_results')
                  .build())
        
        config.save(config_path)
        print(f"   Saved to: {config_path}")
        
        # Load config
        print("\n📂 Loading configuration from file...")
        loaded_config = ScannerConfig.load(config_path)
        
        print(f"   Workers: {loaded_config.max_workers}")
        print(f"   Output Dir: {loaded_config.output_dir}")
        print(f"   CVE Integration: {loaded_config.enable_cve_integration}")


def demo_5_environment_variables():
    """Demo 5: Environment variable configuration."""
    print_section("Demo 5: Environment Variable Configuration")
    
    # Set some env vars
    print("\n🌍 Setting environment variables...")
    os.environ['SCANNER_MAX_WORKERS'] = '10'
    os.environ['SCANNER_OUTPUT_DIR'] = './env_results'
    os.environ['SCANNER_CVE_INTEGRATION'] = 'false'
    os.environ['SCANNER_LOG_LEVEL'] = 'DEBUG'
    
    # Load from env
    config = ScannerConfig.from_env()
    
    print(f"   Max Workers: {config.max_workers} (from SCANNER_MAX_WORKERS)")
    print(f"   Output Dir: {config.output_dir} (from SCANNER_OUTPUT_DIR)")
    print(f"   CVE Integration: {config.enable_cve_integration} (from SCANNER_CVE_INTEGRATION)")
    print(f"   Log Level: {config.log_level} (from SCANNER_LOG_LEVEL)")


def demo_6_practical_examples():
    """Demo 6: Practical configuration examples."""
    print_section("Demo 6: Practical Configuration Examples")
    
    # Example 1: CI/CD Pipeline
    print("\n🔄 Example 1: CI/CD Pipeline Configuration")
    ci_config = (ConfigurationBuilder()
                 .enable_all_features()
                 .set_performance_mode('fast')
                 .set_workers(8)
                 .enable_auto_pr(branch_prefix='security-auto-fix')
                 .set_log_level('WARNING')
                 .build())
    
    print(f"   Performance: Fast")
    print(f"   Workers: {ci_config.max_workers}")
    print(f"   Auto PR: {ci_config.auto_generate_pr}")
    print(f"   PR Prefix: {ci_config.pr_branch_prefix}")
    
    # Example 2: Pre-commit Hook
    print("\n🎣 Example 2: Pre-commit Hook Configuration")
    precommit_config = (ConfigurationBuilder()
                        .set_performance_mode('fast')
                        .set_severity_filter('high')
                        .set_log_level('ERROR')
                        .build())
    
    print(f"   Performance: Fast")
    print(f"   Min Severity: {precommit_config.min_severity}")
    print(f"   Log Level: {precommit_config.log_level}")
    
    # Example 3: Nightly Security Scan
    print("\n🌙 Example 3: Nightly Security Scan Configuration")
    nightly_config = (ConfigurationBuilder()
                      .enable_all_features()
                      .set_performance_mode('thorough')
                      .enable_cve_integration(days=1)
                      .set_severity_filter('low')
                      .build())
    
    print(f"   Performance: Thorough")
    print(f"   CVE Days: {nightly_config.cve_fetch_days}")
    print(f"   Min Severity: {nightly_config.min_severity}")
    print(f"   All Features: Enabled")


def main():
    """Run all demos."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║            Enterprise Scanner Configuration Demo                            ║
║                                                                              ║
║  Learn how to customize the scanner for your needs:                         ║
║  • Default configurations                                                   ║
║  • Builder pattern (fluent API)                                             ║
║  • Preset configurations                                                    ║
║  • File-based configuration                                                 ║
║  • Environment variables                                                    ║
║  • Practical examples                                                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    demos = [
        ("Default Configuration", demo_1_default_config),
        ("Builder Pattern", demo_2_builder_pattern),
        ("Preset Configurations", demo_3_preset_configs),
        ("File-Based Configuration", demo_4_file_based_config),
        ("Environment Variables", demo_5_environment_variables),
        ("Practical Examples", demo_6_practical_examples),
    ]
    
    print("\nAvailable demos:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  {len(demos) + 1}. Run all demos")
    print("  0. Exit")
    
    try:
        choice = input("\nSelect demo (0-7): ").strip()
        
        if choice == '0':
            print("\n👋 Goodbye!")
            return
        elif choice == str(len(demos) + 1):
            # Run all demos
            for name, demo_func in demos:
                try:
                    demo_func()
                except Exception as e:
                    print(f"\n❌ Error in {name}: {e}")
        elif choice.isdigit() and 1 <= int(choice) <= len(demos):
            # Run selected demo
            name, demo_func = demos[int(choice) - 1]
            try:
                demo_func()
            except Exception as e:
                print(f"\n❌ Error in {name}: {e}")
        else:
            print("\n❌ Invalid choice")
    
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    
    print("\n" + "=" * 80)
    print("Configuration demo completed!")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    main()
