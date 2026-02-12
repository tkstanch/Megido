#!/usr/bin/env python3
"""
Multi-Engine Scanner Demo

Demonstrates the multi-engine plugin architecture for Megido.
Shows how multiple analysis engines (SAST, DAST, SCA, secrets) can run
in parallel and aggregate their results.

Usage:
    python demo_multi_engine_scanner.py [target_path]
    
    If no target path is provided, scans the current directory.
"""

import os
import sys
import json
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from scanner.engine_plugins import (
    get_engine_registry,
    EngineOrchestrator
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print demo banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        Megido Multi-Engine Vulnerability Scanner             ║
║               Plugin Architecture Demo                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_section(title):
    """Print a section header"""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print('=' * 70)


def list_available_engines():
    """List all available engines"""
    print_section("Available Scanner Engines")
    
    registry = get_engine_registry()
    engines = registry.list_engines()
    
    if not engines:
        print("⚠️  No engines found. Make sure engines are in scanner/engine_plugins/engines/")
        return
    
    print(f"\nFound {len(engines)} engine(s):\n")
    
    for engine in engines:
        status_icon = "✅" if engine['available'] else "❌"
        print(f"{status_icon} {engine['name']}")
        print(f"   ID:          {engine['engine_id']}")
        print(f"   Category:    {engine['category']}")
        print(f"   Version:     {engine['version']}")
        print(f"   Description: {engine['description']}")
        print(f"   Available:   {'Yes' if engine['available'] else 'No - Install required tools'}")
        print()


def run_scan(target_path):
    """Run a multi-engine scan"""
    print_section(f"Running Multi-Engine Scan on: {target_path}")
    
    # Create orchestrator with default config
    orchestrator = EngineOrchestrator()
    
    # Display configuration
    enabled_engines = orchestrator.get_enabled_engines()
    if enabled_engines:
        print(f"\n✓ Enabled engines from config: {', '.join(enabled_engines)}")
    else:
        print("\n✓ All available engines are enabled (no config file found)")
    
    print(f"\n⏳ Starting scan... (this may take a few moments)\n")
    
    # Run the scan
    try:
        results = orchestrator.run_scan(
            target=target_path,
            parallel=True,  # Run engines in parallel
            max_workers=4   # Use up to 4 parallel workers
        )
        
        # Display results
        display_results(results)
        
        return results
    
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        print(f"\n❌ Scan failed: {e}")
        return None


def display_results(results):
    """Display scan results in a readable format"""
    summary = results['summary']
    findings = results['findings']
    engine_results = results['engine_results']
    
    # Summary section
    print_section("Scan Summary")
    
    print(f"\n⏱️  Execution Time: {summary.execution_time:.2f}s")
    print(f"🔧 Engines Run: {summary.total_engines}")
    print(f"✅ Successful: {summary.successful_engines}")
    print(f"❌ Failed: {summary.failed_engines}")
    print(f"\n🔍 Total Findings: {summary.total_findings}")
    
    # Findings by severity
    if summary.findings_by_severity:
        print("\n📊 Findings by Severity:")
        for severity, count in sorted(summary.findings_by_severity.items()):
            icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': '⚪'
            }.get(severity, '⚫')
            print(f"   {icon} {severity.upper()}: {count}")
    
    # Findings by engine
    if summary.findings_by_engine:
        print("\n🎯 Findings by Engine:")
        for engine_id, count in sorted(summary.findings_by_engine.items()):
            print(f"   • {engine_id}: {count}")
    
    # Engine execution details
    print_section("Engine Execution Details")
    
    for result in engine_results:
        status_icon = "✅" if result.success else "❌"
        print(f"\n{status_icon} {result.engine_name} ({result.engine_id})")
        print(f"   Execution Time: {result.execution_time:.2f}s")
        if result.success:
            print(f"   Findings: {len(result.findings)}")
        else:
            print(f"   Error: {result.error}")
    
    # Detailed findings
    if findings:
        print_section("Detailed Findings")
        
        for i, finding in enumerate(findings[:10], 1):  # Show first 10
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': '⚪'
            }.get(finding.severity, '⚫')
            
            print(f"\n{i}. {severity_icon} [{finding.severity.upper()}] {finding.title}")
            print(f"   Engine: {finding.engine_name}")
            
            if finding.file_path:
                location = f"{finding.file_path}"
                if finding.line_number:
                    location += f":{finding.line_number}"
                print(f"   Location: {location}")
            
            if finding.url:
                print(f"   URL: {finding.url}")
            
            if finding.description:
                print(f"   Description: {finding.description[:100]}...")
            
            if finding.cwe_id:
                print(f"   CWE: {finding.cwe_id}")
            
            if finding.confidence:
                print(f"   Confidence: {finding.confidence * 100:.0f}%")
        
        if len(findings) > 10:
            print(f"\n   ... and {len(findings) - 10} more findings")
    
    print()


def save_results_to_file(results, output_file='scan_results.json'):
    """Save results to a JSON file"""
    try:
        # Convert to serializable format
        output = {
            'summary': results['summary'].to_dict(),
            'findings': [f.to_dict() for f in results['findings']],
            'engine_results': [
                {
                    'engine_id': r.engine_id,
                    'engine_name': r.engine_name,
                    'success': r.success,
                    'findings_count': len(r.findings),
                    'error': r.error,
                    'execution_time': r.execution_time
                }
                for r in results['engine_results']
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"✅ Results saved to: {output_file}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        print(f"❌ Failed to save results: {e}")
        return False


def main():
    """Main demo function"""
    print_banner()
    
    # Determine target path
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    else:
        # Use current directory by default
        target_path = os.getcwd()
    
    # Validate target path
    if not os.path.exists(target_path):
        print(f"❌ Error: Target path does not exist: {target_path}")
        sys.exit(1)
    
    print(f"🎯 Target: {target_path}\n")
    
    # List available engines
    list_available_engines()
    
    # Run the scan
    results = run_scan(target_path)
    
    # Save results if scan was successful
    if results and results['findings']:
        print_section("Save Results")
        save_results_to_file(results)
    
    print_section("Demo Complete")
    print("\n✨ Multi-engine scan demonstration finished!")
    print("\n📚 For more information:")
    print("   - Config file: scanner/engine_plugins/engines_config.yaml")
    print("   - Add engines: scanner/engine_plugins/engines/")
    print("   - Base interface: scanner/engine_plugins/base_engine.py")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        print(f"\n❌ Demo failed: {e}")
        sys.exit(1)
