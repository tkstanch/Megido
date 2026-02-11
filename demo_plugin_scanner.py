#!/usr/bin/env python3
"""
Demo Script: Plugin-Based Vulnerability Scanner

This script demonstrates the new plugin-based scanning architecture.

Usage:
    python demo_plugin_scanner.py [url]

Example:
    python demo_plugin_scanner.py https://example.com
"""

import sys
import os
import django

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
django.setup()

def main():
    """Main demo function"""
    
    # Check if URL provided
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = 'https://example.com'
    
    print("=" * 70)
    print("  Megido Plugin-Based Vulnerability Scanner - Demo")
    print("=" * 70)
    print()
    
    try:
        from scanner.scan_plugins import get_scan_registry
        from scanner.scan_engine import get_scan_engine
        
        # ===== Part 1: Show Available Plugins =====
        print("📦 Part 1: Available Scan Plugins")
        print("-" * 70)
        
        registry = get_scan_registry()
        plugins = registry.list_plugins()
        
        print(f"\nDiscovered {len(plugins)} plugin(s):\n")
        
        for i, plugin in enumerate(plugins, 1):
            print(f"{i}. {plugin['name']} (v{plugin['version']})")
            print(f"   ID: {plugin['plugin_id']}")
            print(f"   Description: {plugin['description']}")
            print(f"   Detects: {', '.join(plugin['vulnerability_types'])}")
            print(f"   Async Support: {'Yes' if plugin['supports_async'] else 'No (TODO)'}")
            print()
        
        # ===== Part 2: Run Individual Plugin =====
        print("\n📡 Part 2: Testing Individual Plugin (XSS Scanner)")
        print("-" * 70)
        
        xss_plugin = registry.get_plugin('xss_scanner')
        if xss_plugin:
            print(f"\nRunning {xss_plugin.name} on {target_url}...")
            print()
            
            config = {
                'verify_ssl': False,
                'timeout': 10,
            }
            
            findings = xss_plugin.scan(target_url, config)
            
            if findings:
                print(f"✓ Found {len(findings)} potential issue(s):\n")
                for finding in findings:
                    print(f"  [{finding.severity.upper()}] {finding.description}")
                    print(f"  Evidence: {finding.evidence[:100]}...")
                    print()
            else:
                print("✓ No issues found by this plugin")
        else:
            print("⚠ XSS plugin not found")
        
        # ===== Part 3: Run Full Scan with All Plugins =====
        print("\n🔍 Part 3: Full Scan with Scan Engine (All Plugins)")
        print("-" * 70)
        
        engine = get_scan_engine()
        
        print(f"\nScanning {target_url} with all available plugins...")
        print()
        
        config = {
            'verify_ssl': False,
            'timeout': 10,
        }
        
        all_findings = engine.scan(target_url, config)
        
        print(f"✓ Scan completed. Total findings: {len(all_findings)}\n")
        
        if all_findings:
            # Group by severity
            by_severity = {}
            for finding in all_findings:
                severity = finding.severity
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(finding)
            
            # Display results
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in by_severity:
                    findings_list = by_severity[severity]
                    print(f"\n{severity.upper()} Severity ({len(findings_list)}):")
                    print("-" * 70)
                    
                    for finding in findings_list:
                        print(f"\n  • {finding.description}")
                        print(f"    Type: {finding.vulnerability_type}")
                        print(f"    URL: {finding.url}")
                        if finding.parameter:
                            print(f"    Parameter: {finding.parameter}")
                        print(f"    Confidence: {finding.confidence:.0%}")
                        if finding.cwe_id:
                            print(f"    CWE: {finding.cwe_id}")
                        print(f"    Evidence: {finding.evidence[:150]}...")
                        print(f"    Remediation: {finding.remediation[:150]}...")
        else:
            print("✓ No vulnerabilities detected!")
        
        # ===== Part 4: Architecture Overview =====
        print("\n\n🏗️  Part 4: Architecture Overview")
        print("-" * 70)
        print("""
The new plugin-based architecture provides:

✨ Features:
  • Modular, extensible design
  • Automatic plugin discovery
  • Consistent vulnerability reporting
  • Easy to add new vulnerability checks
  • Separation of detection vs exploitation
  
🔌 Plugin Types:
  • Scan Plugins (Detection) - in scanner/scan_plugins/
  • Exploit Plugins (Exploitation) - in scanner/plugins/
  
🚀 Future Enhancements (Roadmap):
  • Async scanning with asyncio/Celery
  • Real-time progress via WebSocket
  • Plugin configuration UI
  • Scan scheduling and templates
  • More detection plugins (SQLi, CSRF, etc.)
  
📖 Documentation:
  • SCANNER_PLUGIN_GUIDE.md - Complete plugin development guide
  • scanner/scan_plugins/README.md - Quick reference
  • USAGE_GUIDE.md - Updated user guide
        """)
        
        print("\n" + "=" * 70)
        print("  Demo Complete!")
        print("=" * 70)
        print("\nTo create your own plugin:")
        print("  1. See SCANNER_PLUGIN_GUIDE.md")
        print("  2. Create a file in scanner/scan_plugins/detectors/")
        print("  3. Inherit from BaseScanPlugin")
        print("  4. Implement required methods")
        print("  5. Plugin is auto-discovered on next run!")
        print()
        
    except ImportError as e:
        print(f"\n❌ Error: Missing dependencies")
        print(f"   {e}")
        print("\nPlease install required packages:")
        print("   pip install django djangorestframework requests beautifulsoup4")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
