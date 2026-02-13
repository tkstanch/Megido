#!/usr/bin/env python3
"""
Demo: XSS GIF Proof Generation

This script demonstrates the automatic GIF proof generation feature
for verified XSS vulnerabilities.

Requirements:
    - pip install playwright
    - playwright install chromium
    OR
    - pip install selenium

Usage:
    python3 demo_xss_gif_proof.py
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.xss_gif_capture import get_xss_gif_capture


def main():
    print("=" * 80)
    print("XSS Visual Proof (GIF) Generation Demo")
    print("=" * 80)
    print()
    
    # Initialize GIF capture
    print("Initializing XSS GIF capture module...")
    gif_capture = get_xss_gif_capture()
    
    if not gif_capture:
        print("❌ ERROR: GIF capture not available.")
        print()
        print("Please install required dependencies:")
        print("  pip install playwright")
        print("  playwright install chromium")
        print()
        print("OR:")
        print("  pip install selenium")
        return 1
    
    print(f"✓ GIF capture initialized using {'Playwright' if gif_capture.use_playwright else 'Selenium'}")
    print()
    
    # Test URL sanitization
    print("=" * 80)
    print("Testing URL Sanitization")
    print("=" * 80)
    print()
    
    test_urls = [
        ('http://example.com', True),
        ('https://example.com', True),
        ('file:///etc/passwd', False),
        ('javascript:alert(1)', False),
        ('http://localhost:8080/test', True),
    ]
    
    for url, expected in test_urls:
        result = gif_capture.sanitize_url(url)
        status = "✓" if result == expected else "✗"
        print(f"{status} {url}: {result}")
    
    print()
    
    # Test filename generation
    print("=" * 80)
    print("Testing Filename Generation")
    print("=" * 80)
    print()
    
    url = "http://example.com/test"
    payload = "<script>alert(1)</script>"
    filename = gif_capture.generate_filename(url, payload)
    print(f"Generated filename: {filename}")
    print()
    
    # Demonstrate directory structure
    print("=" * 80)
    print("Directory Structure")
    print("=" * 80)
    print()
    print(f"Output directory: {gif_capture.output_dir}")
    print(f"Exists: {gif_capture.output_dir.exists()}")
    print()
    
    # Show integration example
    print("=" * 80)
    print("Integration Example")
    print("=" * 80)
    print()
    print("When XSS plugin finds a VERIFIED vulnerability:")
    print()
    print("1. Finding is created with verified=True")
    print("2. _capture_gif_proof(finding) is called automatically")
    print("3. GIF is captured using headless browser")
    print("4. finding['proof_gif'] is set to '/media/xss_gif_proofs/xss_proof_*.gif'")
    print("5. GIF is embedded in HTML reports and linked in Markdown/JSON reports")
    print()
    
    # Show report integration
    print("=" * 80)
    print("Report Integration")
    print("=" * 80)
    print()
    print("HTML Report:")
    print("  - GIF displayed as <img> tag with preview")
    print("  - Download link provided")
    print()
    print("Markdown Report:")
    print("  - GIF linked with ![XSS Exploitation GIF](path/to/gif)")
    print("  - Download link provided")
    print()
    print("JSON Report:")
    print("  - GIF path in finding['proof_gif']")
    print()
    
    # Show example finding
    print("=" * 80)
    print("Example Finding with GIF Proof")
    print("=" * 80)
    print()
    print("finding = {")
    print("    'type': 'dom',")
    print("    'url': 'http://target.com/search?q=<payload>',")
    print("    'parameter': 'q',")
    print("    'payload': '<script>alert(document.domain)</script>',")
    print("    'verified': True,")
    print("    'verification_method': 'callback',")
    print("    'severity': 'high',")
    print("    'proof_gif': '/media/xss_gif_proofs/xss_proof_abc123_20260213_112345.gif',")
    print("    # ... other fields ...")
    print("}")
    print()
    
    # Show security features
    print("=" * 80)
    print("Security Features")
    print("=" * 80)
    print()
    print("✓ URL validation and sanitization")
    print("✓ Resource limits:")
    print("  - Max duration: 5 seconds")
    print("  - Max file size: 10 MB")
    print("  - Max screenshots: 10")
    print("✓ Error handling - doesn't interrupt scanning")
    print("✓ Automatic cleanup of old files (7 days)")
    print("✓ No execution of untrusted JavaScript")
    print()
    
    # Cleanup info
    print("=" * 80)
    print("Maintenance")
    print("=" * 80)
    print()
    print("To manually cleanup old GIF files:")
    print()
    print("from scanner.xss_gif_capture import get_xss_gif_capture")
    print("capture = get_xss_gif_capture()")
    print("capture.cleanup_old_files(max_age_days=7)")
    print()
    
    print("=" * 80)
    print("Demo Complete")
    print("=" * 80)
    print()
    print("The XSS GIF proof generation feature is now ready to use!")
    print("Run an XSS scan with callback verification enabled to see it in action.")
    print()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
