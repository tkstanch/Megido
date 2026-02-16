#!/usr/bin/env python3
"""
Demo script for visual proof diagnostics and warnings system.

This script demonstrates:
1. Running diagnostic checks
2. Interpreting warning messages
3. Understanding visual proof status codes
4. Troubleshooting common issues
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70 + "\n")


def demo_diagnostics():
    """Demo 1: Run comprehensive diagnostic checks."""
    print_section("DEMO 1: Visual Proof Diagnostics")
    
    from scanner.visual_proof_diagnostics import check_visual_proof_dependencies
    
    print("Running comprehensive diagnostic check...\n")
    result = check_visual_proof_dependencies()
    
    print(f"Overall Status: {result['overall_status'].upper()}")
    print(f"  {'✓' if result['overall_status'] == 'ok' else '✗'} System ready for visual proof capture\n")
    
    print("Dependency Status:")
    deps = result['dependencies']
    print(f"  Playwright: {'✓ Installed' if deps['playwright'] else '✗ Not installed'}")
    print(f"  Selenium:   {'✓ Installed' if deps['selenium'] else '✗ Not installed'}")
    print(f"  Pillow:     {'✓ Installed' if deps['pillow'] else '✗ Not installed'}\n")
    
    print("Browser Status:")
    browsers = result['browsers']
    print(f"  Status: {browsers['status']}")
    for detail in browsers['details']:
        print(f"  - {detail}")
    print()
    
    print("Filesystem Status:")
    fs = result['filesystem']
    print(f"  Directory: {fs['path']}")
    print(f"  Exists:    {'✓' if fs['directory_exists'] else '✗'}")
    print(f"  Writable:  {'✓' if fs['writable'] else '✗'}")
    if fs['error']:
        print(f"  Error:     {fs['error']}")
    print()
    
    if result['errors']:
        print("Critical Errors Found:")
        for error in result['errors']:
            if isinstance(error, dict):
                print(f"  ✗ [{error.get('severity', 'ERROR').upper()}] {error.get('component', 'Unknown')}")
                print(f"    {error.get('message', str(error))}")
            else:
                print(f"  ✗ {error}")
        print()
    
    if result['warnings']:
        print("Warnings Found:")
        for warning in result['warnings']:
            if isinstance(warning, dict):
                print(f"  ⚠ [{warning.get('severity', 'WARNING').upper()}] {warning.get('component', 'Unknown')}")
                print(f"    {warning.get('message', str(warning))}")
            else:
                print(f"  ⚠ {warning}")
        print()
    
    if result['recommendations']:
        print("Recommendations:")
        for i, rec in enumerate(result['recommendations'], 1):
            print(f"  {i}. {rec}")
        print()


def demo_warnings():
    """Demo 2: Show how warnings appear in scan results."""
    print_section("DEMO 2: Scan-Level Warnings")
    
    from scanner.visual_proof_diagnostics import get_visual_proof_warnings
    
    print("Collecting warnings for scan results...\n")
    warnings = get_visual_proof_warnings()
    
    if not warnings:
        print("✓ No warnings! Visual proof system is properly configured.\n")
    else:
        print(f"Found {len(warnings)} warning(s):\n")
        for i, warning in enumerate(warnings, 1):
            print(f"{i}. [{warning['severity'].upper()}] {warning['component']}")
            print(f"   Message:        {warning['message']}")
            print(f"   Recommendation: {warning['recommendation']}")
            print()
    
    print("These warnings would appear in the scan results API response:")
    print("""
    {
      "scan_id": 123,
      "warnings": [""")
    for warning in warnings:
        print(f"""        {{
          "category": "{warning['category']}",
          "severity": "{warning['severity']}",
          "component": "{warning['component']}",
          "message": "{warning['message']}",
          "recommendation": "{warning['recommendation']}"
        }},""")
    print("""      ],
      "vulnerabilities": [...]
    }
    """)


def demo_proof_data_status():
    """Demo 3: Show visual proof status tracking in ProofData."""
    print_section("DEMO 3: Visual Proof Status Tracking")
    
    from scanner.proof_reporter import ProofData
    
    print("Creating ProofData instance...\n")
    proof_data = ProofData('xss', vulnerability_id=1)
    
    print(f"Initial status: {proof_data.visual_proof_status}")
    print(f"Initial warnings: {len(proof_data.visual_proof_warnings)}\n")
    
    print("Simulating visual proof capture failure...\n")
    proof_data.set_visual_proof_status('failed')
    proof_data.add_visual_proof_warning(
        message='Browser automation failed',
        severity='high',
        component='Selenium',
        recommendation='Check ChromeDriver installation'
    )
    
    print(f"Updated status: {proof_data.visual_proof_status}")
    print(f"Warnings collected: {len(proof_data.visual_proof_warnings)}\n")
    
    print("Proof data dictionary:")
    data_dict = proof_data.to_dict()
    print(f"  visual_proof_status: {data_dict['visual_proof_status']}")
    print(f"  visual_proof_warnings: {len(data_dict['visual_proof_warnings'])} warning(s)")
    for warning in data_dict['visual_proof_warnings']:
        print(f"    - [{warning['severity']}] {warning['message']}")
    print()


def demo_status_codes():
    """Demo 4: Explain all visual proof status codes."""
    print_section("DEMO 4: Visual Proof Status Codes")
    
    status_codes = {
        'captured': {
            'meaning': 'Visual proof successfully captured',
            'color': '🟢',
            'action': 'None required - visual proof is available'
        },
        'disabled': {
            'meaning': 'Visual proof disabled by configuration',
            'color': '⚪',
            'action': 'Enable in config if needed'
        },
        'failed': {
            'meaning': 'Capture attempted but failed',
            'color': '🔴',
            'action': 'Check warnings and logs for details'
        },
        'not_supported': {
            'meaning': 'Not supported for this vulnerability type',
            'color': '🔵',
            'action': 'None - feature not applicable'
        },
        'missing_dependencies': {
            'meaning': 'Required dependencies not installed',
            'color': '🟡',
            'action': 'Install Playwright, Selenium, or Pillow'
        },
        'not_attempted': {
            'meaning': 'Visual proof not attempted',
            'color': '⚪',
            'action': 'None - may be disabled or not configured'
        }
    }
    
    print("Visual Proof Status Codes:\n")
    for code, info in status_codes.items():
        print(f"{info['color']} {code.upper()}")
        print(f"   Meaning: {info['meaning']}")
        print(f"   Action:  {info['action']}")
        print()


def demo_frontend_usage():
    """Demo 5: Show how frontend should use the new status field."""
    print_section("DEMO 5: Frontend Integration Example")
    
    print("""
JavaScript/TypeScript Frontend Example:

```javascript
async function checkVisualProofStatus(vulnerabilityId) {
  const response = await fetch(`/api/scans/${scanId}/results/`);
  const data = await response.json();
  
  // Check scan-level warnings
  if (data.warnings && data.warnings.length > 0) {
    const vpWarnings = data.warnings.filter(w => w.category === 'visual_proof');
    if (vpWarnings.length > 0) {
      showSystemWarning('Visual Proof System Issues Detected', vpWarnings);
    }
  }
  
  // Check vulnerability-specific status
  const vuln = data.vulnerabilities.find(v => v.id === vulnerabilityId);
  
  switch (vuln.visual_proof_status) {
    case 'captured':
      // Show visual proof viewer
      displayVisualProof(vuln.visual_proof_path, vuln.visual_proof_type);
      break;
      
    case 'missing_dependencies':
      // Show installation instructions
      showError(
        'Visual proof unavailable - dependencies missing',
        'Install required packages: pip install playwright selenium Pillow'
      );
      break;
      
    case 'failed':
      // Show failure message with troubleshooting link
      showWarning(
        'Visual proof capture failed',
        'Check browser automation setup. See troubleshooting guide.'
      );
      break;
      
    case 'disabled':
      // Show info message
      showInfo('Visual proof is disabled in configuration');
      break;
      
    case 'not_supported':
      // Show info message
      showInfo('Visual proof not supported for this vulnerability type');
      break;
      
    default:
      // Not attempted
      showInfo('Visual proof was not captured for this vulnerability');
  }
}
```

Python Backend Example:

```python
from scanner.models import Scan, Vulnerability

# Check scan warnings
scan = Scan.objects.get(id=123)
if scan.warnings:
    visual_proof_warnings = [
        w for w in scan.warnings 
        if w.get('category') == 'visual_proof'
    ]
    for warning in visual_proof_warnings:
        print(f"[{warning['severity']}] {warning['message']}")
        print(f"Fix: {warning['recommendation']}")

# Check vulnerability status
vuln = Vulnerability.objects.get(id=456)
if vuln.visual_proof_status == 'captured':
    print(f"Visual proof: {vuln.visual_proof_path}")
elif vuln.visual_proof_status == 'missing_dependencies':
    print("Install dependencies to enable visual proof")
```
    """)


def main():
    """Run all demos."""
    print("\n" + "🔍" * 35)
    print(" Visual Proof Diagnostics & Warnings System Demo")
    print("🔍" * 35)
    
    try:
        demo_diagnostics()
        demo_warnings()
        demo_proof_data_status()
        demo_status_codes()
        demo_frontend_usage()
        
        print_section("Summary")
        print("""
The visual proof system now provides:

✓ Automated dependency checking
✓ Clear status codes for each vulnerability
✓ Actionable recommendations for fixing issues
✓ Comprehensive warnings in scan results
✓ Frontend-friendly API responses
✓ Detailed troubleshooting documentation

Users will no longer see "No visual proof available" without understanding why!
        """)
        
    except Exception as e:
        print(f"\n❌ Error running demo: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
