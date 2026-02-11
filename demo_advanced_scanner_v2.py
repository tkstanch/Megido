#!/usr/bin/env python3
"""
Advanced Scanner Demo

Demonstrates the extremely advanced scanner with:
- 6 detection plugins (XSS, SQLi, CSRF, Headers, SSL, Sensitive Data)
- ML-based anomaly detection
- Risk scoring and prioritization
- Interactive HTML dashboard
- Compliance mapping
"""

import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Main demo function"""
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = 'http://testsite.local'
    
    print("=" * 80)
    print("  🛡️  MEGIDO EXTREMELY ADVANCED SECURITY SCANNER - DEMO")
    print("=" * 80)
    print()
    
    try:
        from scanner.scan_plugins import get_scan_registry
        from scanner.advanced_scan_engine import get_advanced_scan_engine
        
        # ===== Part 1: Show Available Plugins =====
        print("📦 Part 1: Detection Plugins")
        print("-" * 80)
        
        registry = get_scan_registry()
        plugins = registry.list_plugins()
        
        print(f"\n✨ Discovered {len(plugins)} advanced plugin(s):\n")
        
        for i, plugin in enumerate(plugins, 1):
            print(f"{i}. {plugin['name']} (v{plugin['version']})")
            print(f"   ID: {plugin['plugin_id']}")
            print(f"   Detects: {', '.join(plugin['vulnerability_types'])}")
            print()
        
        # ===== Part 2: Run Advanced Scan =====
        print("\n🔍 Part 2: Advanced Scan with ML & Risk Scoring")
        print("-" * 80)
        
        engine = get_advanced_scan_engine()
        
        print(f"\nScanning {target_url} with advanced features...")
        print("- ML-based confidence boosting")
        print("- Comprehensive risk scoring (0-100)")
        print("- Compliance framework mapping")
        print("- False positive detection")
        print()
        
        config = {
            'verify_ssl': False,
            'timeout': 10,
        }
        
        result = engine.scan_with_advanced_features(target_url, config)
        
        # Display results
        print(f"✓ Scan completed!\n")
        
        risk_summary = result['risk_summary']
        print(f"📊 Risk Summary:")
        print(f"   Total Findings: {risk_summary['total_findings']}")
        print(f"   Average Risk Score: {risk_summary['average_risk_score']:.1f}/100")
        print(f"   ML-Enhanced: {'✓ Yes' if result['ml_enabled'] else '✗ No (install scikit-learn)'}")
        print()
        
        by_severity = risk_summary.get('by_severity', {})
        if by_severity:
            print(f"   By Severity:")
            for severity, count in sorted(by_severity.items(), 
                                         key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x[0], 0),
                                         reverse=True):
                print(f"     • {severity.upper()}: {count}")
        print()
        
        # Show findings
        findings = result['findings']
        if findings:
            print(f"🔍 Findings Details:\n")
            for i, finding in enumerate(findings[:5], 1):  # Show first 5
                print(f"{i}. [{finding['severity'].upper()}] {finding['description']}")
                print(f"   Type: {finding['vulnerability_type']}")
                print(f"   Risk Score: {finding.get('risk_score', 0):.1f}/100")
                print(f"   Confidence: {finding.get('confidence', 0):.0%}")
                if 'ml_confidence' in finding:
                    print(f"   ML Confidence: {finding['ml_confidence']:.2f}")
                if 'compliance_violations' in finding and finding['compliance_violations']:
                    print(f"   Compliance: {', '.join(finding['compliance_violations'])}")
                print()
            
            if len(findings) > 5:
                print(f"   ... and {len(findings) - 5} more findings\n")
        else:
            print("✓ No vulnerabilities detected!\n")
        
        # ===== Part 3: Generate Dashboard =====
        print("\n📊 Part 3: Interactive HTML Dashboard")
        print("-" * 80)
        
        try:
            dashboard_path = engine.generate_html_dashboard(result)
            print(f"\n✓ Dashboard generated: {dashboard_path}")
            print(f"  Open in browser: file://{os.path.abspath(dashboard_path)}")
            print()
        except Exception as e:
            print(f"⚠ Dashboard generation skipped: {e}\n")
        
        # ===== Part 4: Feature Comparison =====
        print("\n✨ Part 4: Advanced Features Overview")
        print("-" * 80)
        print("""
🚀 Extremely Advanced Scanner Features:

✅ Detection Capabilities (6 Plugins)
   • XSS - Cross-Site Scripting detection
   • SQLi - Advanced SQL Injection with multiple techniques
   • CSRF - Cross-Site Request Forgery protection checking
   • Sensitive Data - API keys, secrets, credentials
   • Security Headers - X-Frame-Options, CSP, HSTS
   • SSL/TLS - HTTPS configuration analysis

✅ ML/AI Integration
   • Anomaly detection using Isolation Forest
   • TF-IDF feature extraction
   • Confidence score boosting
   • False positive prediction

✅ Risk Scoring System
   • Comprehensive 0-100 scoring
   • Multi-factor risk calculation
   • Severity + Confidence + CWE + Context
   • Automatic risk level assignment

✅ Compliance Mapping
   • OWASP Top 10 2021
   • PCI-DSS requirements
   • GDPR Article 32
   • Automatic violation detection

✅ Enhanced Reporting
   • Interactive HTML dashboards
   • Risk statistics visualization
   • Color-coded severity indicators
   • Dark-themed professional design

🔮 Coming Soon (Phase 3)
   • SARIF format export for IDE integration
   • CVE correlation and threat intelligence
   • Automated remediation suggestions
   • Container and runtime scanning
        """)
        
        print("\n" + "=" * 80)
        print("  Demo Complete!")
        print("=" * 80)
        print("\nTo use in your code:")
        print("""
from scanner.advanced_scan_engine import get_advanced_scan_engine

engine = get_advanced_scan_engine()
result = engine.scan_with_advanced_features('https://example.com')
dashboard = engine.generate_html_dashboard(result)
        """)
        print()
        
    except ImportError as e:
        print(f"\n❌ Error: Missing dependencies")
        print(f"   {e}")
        print("\nPlease install required packages:")
        print("   pip install requests beautifulsoup4")
        print("\nFor ML features (optional):")
        print("   pip install scikit-learn numpy")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
