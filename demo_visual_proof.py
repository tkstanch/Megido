"""
Visual Proof of Impact - Demo and Testing Script

This script demonstrates the visual proof capture functionality
for vulnerability exploitations.

Usage:
    python3 demo_visual_proof.py
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def demo_visual_proof_capture():
    """Demonstrate visual proof capture functionality."""
    print("=" * 80)
    print("VISUAL PROOF OF IMPACT - DEMO")
    print("=" * 80)
    print()
    
    # Check dependencies
    print("1. Checking Dependencies...")
    print("-" * 80)
    
    dependencies = {
        'Pillow': False,
        'playwright': False,
        'selenium': False
    }
    
    try:
        from PIL import Image
        dependencies['Pillow'] = True
        print("✓ Pillow (PIL) - INSTALLED")
    except ImportError:
        print("✗ Pillow (PIL) - NOT INSTALLED")
        print("  Install with: pip install Pillow")
    
    try:
        from playwright.sync_api import sync_playwright
        dependencies['playwright'] = True
        print("✓ Playwright - INSTALLED")
    except ImportError:
        print("✗ Playwright - NOT INSTALLED")
        print("  Install with: pip install playwright && playwright install chromium")
    
    try:
        from selenium import webdriver
        dependencies['selenium'] = True
        print("✓ Selenium - INSTALLED")
    except ImportError:
        print("✗ Selenium - NOT INSTALLED")
        print("  Install with: pip install selenium")
    
    print()
    
    if not dependencies['Pillow']:
        print("ERROR: Pillow is required for visual proof capture")
        return False
    
    if not dependencies['playwright'] and not dependencies['selenium']:
        print("ERROR: Either Playwright or Selenium is required")
        return False
    
    # Import visual proof module
    print("2. Loading Visual Proof Module...")
    print("-" * 80)
    
    try:
        from scanner.visual_proof_capture import VisualProofCapture, get_visual_proof_capture
        print("✓ Visual Proof module loaded successfully")
        print()
    except Exception as e:
        print(f"✗ Failed to load module: {e}")
        return False
    
    # Create capture instance
    print("3. Initializing Visual Proof Capture...")
    print("-" * 80)
    
    try:
        output_dir = 'media/exploit_proofs_demo'
        capture = VisualProofCapture(output_dir)
        print(f"✓ Visual Proof Capture initialized")
        print(f"  Output directory: {output_dir}")
        print(f"  Max file size: {capture.MAX_FILE_SIZE_MB}MB")
        print(f"  Max duration: {capture.MAX_DURATION_SECONDS}s")
        print(f"  Compression quality: {capture.COMPRESSION_QUALITY}%")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        return False
    
    # Demo 1: URL Validation
    print("4. Demo: URL Validation")
    print("-" * 80)
    
    test_urls = [
        ('https://example.com', True),
        ('http://localhost:8000', True),
        ('https://192.168.1.1', True),
        ('ftp://example.com', False),
        ('javascript:alert(1)', False),
        ('', False),
    ]
    
    for url, should_pass in test_urls:
        is_valid = capture.sanitize_url(url)
        status = "✓" if is_valid == should_pass else "✗"
        print(f"  {status} {url[:50]:50} → {'VALID' if is_valid else 'INVALID'}")
    
    print()
    
    # Demo 2: Filename Generation
    print("5. Demo: Secure Filename Generation")
    print("-" * 80)
    
    vuln_types = ['xss', 'sqli', 'rce', 'lfi', 'ssrf']
    for vuln_type in vuln_types:
        filename = capture.generate_filename(vuln_type, 123, 'png')
        print(f"  {vuln_type:10} → {filename}")
    
    print()
    
    # Demo 3: Capture Types
    print("6. Demo: Capture Type Selection")
    print("-" * 80)
    
    vuln_types_with_capture = [
        ('xss', 'Dynamic → GIF'),
        ('csrf', 'Dynamic → GIF'),
        ('clickjacking', 'Dynamic → GIF'),
        ('sqli', 'Static → Screenshot'),
        ('rce', 'Static → Screenshot'),
        ('lfi', 'Static → Screenshot'),
        ('ssrf', 'Static → Screenshot'),
        ('info_disclosure', 'Static → Screenshot'),
    ]
    
    for vuln_type, capture_desc in vuln_types_with_capture:
        print(f"  {vuln_type:20} → {capture_desc}")
    
    print()
    
    # Demo 4: Real Capture (if user wants)
    print("7. Live Capture Demo (Optional)")
    print("-" * 80)
    print("Would you like to test a real capture? This will:")
    print("  - Navigate to https://example.com")
    print("  - Capture a screenshot")
    print("  - Save to media/exploit_proofs_demo/")
    print()
    
    response = input("Run live capture? (y/n): ").strip().lower()
    
    if response == 'y':
        try:
            print("\nCapturing screenshot of example.com...")
            screenshot_bytes = capture.capture_screenshot('https://example.com', wait_time=1.0)
            
            if screenshot_bytes:
                # Save to file
                filename = capture.generate_filename('demo', 1, 'png')
                file_path = Path(output_dir) / filename
                file_path.write_bytes(screenshot_bytes)
                
                print(f"✓ Screenshot captured successfully!")
                print(f"  File: {file_path}")
                print(f"  Size: {len(screenshot_bytes)} bytes ({len(screenshot_bytes)/1024:.1f} KB)")
                print()
            else:
                print("✗ Screenshot capture failed")
                print()
        except Exception as e:
            print(f"✗ Capture error: {e}")
            print()
    else:
        print("Skipped live capture demo")
        print()
    
    # Demo 5: Feature Summary
    print("8. Feature Summary")
    print("-" * 80)
    print("✓ Automatic visual proof capture for all vulnerability types")
    print("✓ Smart type selection (GIF for dynamic, screenshot for static)")
    print("✓ File size optimization (<10MB guaranteed)")
    print("✓ Multiple browser support (Playwright, Selenium)")
    print("✓ Secure filename generation")
    print("✓ URL validation and sanitization")
    print("✓ Graceful error handling (non-blocking)")
    print("✓ Dashboard integration with fullscreen viewer")
    print("✓ Download capability")
    print()
    
    # Demo 6: Integration Example
    print("9. Integration Example")
    print("-" * 80)
    print("In your exploitation code:")
    print()
    print("```python")
    print("from scanner.visual_proof_capture import get_visual_proof_capture")
    print()
    print("# After successful exploitation")
    print("if result['success']:")
    print("    capture = get_visual_proof_capture()")
    print("    proof = capture.capture_exploit_proof(")
    print("        vuln_type='xss',")
    print("        vuln_id=vulnerability.id,")
    print("        url=vulnerability.url,")
    print("        capture_type='gif',  # or 'screenshot'")
    print("        duration=3.0")
    print("    )")
    print("    ")
    print("    if proof:")
    print("        vulnerability.visual_proof_path = proof['path']")
    print("        vulnerability.visual_proof_type = proof['type']")
    print("        vulnerability.visual_proof_size = proof['size']")
    print("        vulnerability.save()")
    print("```")
    print()
    
    # Demo 7: Dashboard Display
    print("10. Dashboard Display")
    print("-" * 80)
    print("Visual proofs are automatically displayed in the dashboard:")
    print()
    print("  • Purple-themed section (distinct from other proof types)")
    print("  • Inline thumbnail preview (max 400px height)")
    print("  • File type and size indicators")
    print("  • Click to view fullscreen modal")
    print("  • Download button for evidence export")
    print("  • Keyboard shortcuts (ESC to close)")
    print("  • Responsive design (mobile-friendly)")
    print()
    
    # Demo 8: Configuration
    print("11. Configuration Options")
    print("-" * 80)
    print("```python")
    print("config = {")
    print("    'visual_proof': {")
    print("        'enabled': True,          # Toggle feature on/off")
    print("        'type': 'auto',           # 'auto', 'screenshot', or 'gif'")
    print("        'duration': 3.0,          # GIF duration in seconds")
    print("        'max_file_size_mb': 10,  # Maximum file size")
    print("        'compression_quality': 85 # Image quality (1-100)")
    print("    }")
    print("}")
    print()
    print("exploit_vulnerabilities(vulnerabilities, config)")
    print("```")
    print()
    
    print("=" * 80)
    print("DEMO COMPLETE!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run a vulnerability scan")
    print("  2. Exploit discovered vulnerabilities")
    print("  3. View visual proofs in the dashboard")
    print("  4. Download proofs for reports")
    print()
    
    return True


if __name__ == '__main__':
    success = demo_visual_proof_capture()
    sys.exit(0 if success else 1)
