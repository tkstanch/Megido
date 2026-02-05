#!/usr/bin/env python3
"""
Megido Security - Demo Script
Demonstrates the API functionality with sample data
"""

import requests
import json
import time
from datetime import datetime
import os

BASE_URL = "http://localhost:8000"

# API Token for authentication - set this via environment variable or hardcode for testing
# To get a token, run: python manage.py create_scanner_token --username <your-username>
API_TOKEN = os.environ.get('MEGIDO_API_TOKEN', '')

# Headers to include in all API requests
HEADERS = {
    'Authorization': f'Token {API_TOKEN}',
    'Content-Type': 'application/json',
} if API_TOKEN else {
    'Content-Type': 'application/json',
}

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def print_result(label, data):
    """Print formatted results"""
    print(f"\n{label}:")
    print(json.dumps(data, indent=2))

def demo_repeater():
    """Demonstrate the Repeater functionality"""
    print_header("HTTP Repeater Demo")
    
    # Create a request
    print("\n1. Creating a repeater request...")
    request_data = {
        "url": "http://example.com",
        "method": "GET",
        "headers": json.dumps({"User-Agent": "Megido Security Scanner"}),
        "body": "",
        "name": "Example.com Test"
    }
    
    response = requests.post(f"{BASE_URL}/repeater/api/requests/", json=request_data)
    result = response.json()
    print_result("Created request", result)
    request_id = result.get('id')
    
    # Send the request
    print("\n2. Sending the request...")
    response = requests.post(f"{BASE_URL}/repeater/api/requests/{request_id}/send/")
    result = response.json()
    
    if 'error' not in result:
        print_result("Response received", {
            "status_code": result.get('status_code'),
            "response_time": f"{result.get('response_time', 0):.2f}ms",
            "body_length": len(result.get('body', ''))
        })
    else:
        print(f"   Error: {result['error']}")
    
    # List all requests
    print("\n3. Listing all repeater requests...")
    response = requests.get(f"{BASE_URL}/repeater/api/requests/")
    requests_list = response.json()
    print(f"   Total requests: {len(requests_list)}")
    for req in requests_list[:3]:
        print(f"   - {req['name']}: {req['method']} {req['url']}")

def demo_scanner():
    """Demonstrate the Scanner functionality"""
    print_header("Vulnerability Scanner Demo")
    
    if not API_TOKEN:
        print("\n⚠️  WARNING: No API token configured!")
        print("   The scanner API requires authentication.")
        print("   Set MEGIDO_API_TOKEN environment variable or configure it in demo.py")
        print("\n   To create a token, run:")
        print("   python manage.py create_scanner_token --username <your-username>")
        print("\n   Skipping scanner demo...")
        return
    
    # Create a scan target
    print("\n1. Creating scan target...")
    target_data = {
        "url": "http://example.com",
        "name": "Example.com Security Scan"
    }
    
    response = requests.post(f"{BASE_URL}/scanner/api/targets/", json=target_data, headers=HEADERS)
    result = response.json()
    print_result("Created target", result)
    target_id = result.get('id')
    
    # Start a scan
    print("\n2. Starting vulnerability scan...")
    response = requests.post(f"{BASE_URL}/scanner/api/targets/{target_id}/scan/", headers=HEADERS)
    result = response.json()
    print_result("Scan initiated", result)
    scan_id = result.get('id')
    
    # Wait a moment for scan to complete
    time.sleep(2)
    
    # Get scan results
    print("\n3. Retrieving scan results...")
    response = requests.get(f"{BASE_URL}/scanner/api/scans/{scan_id}/results/")
    result = response.json()
    
    print(f"\n   Scan Status: {result['status']}")
    print(f"   Started: {result['started_at']}")
    print(f"   Completed: {result['completed_at']}")
    print(f"   Vulnerabilities Found: {len(result['vulnerabilities'])}")
    
    if result['vulnerabilities']:
        print("\n   Vulnerabilities:")
        for vuln in result['vulnerabilities']:
            print(f"   - [{vuln['severity'].upper()}] {vuln['type']}")
            print(f"     URL: {vuln['url']}")
            print(f"     Description: {vuln['description']}")
    else:
        print("   ✓ No vulnerabilities detected")

def demo_proxy():
    """Demonstrate the Proxy functionality"""
    print_header("HTTP Proxy Demo")
    
    print("\n1. Listing captured proxy requests...")
    response = requests.get(f"{BASE_URL}/proxy/api/requests/")
    requests_list = response.json()
    
    print(f"   Total captured requests: {len(requests_list)}")
    
    if requests_list:
        print("\n   Recent requests:")
        for req in requests_list[:5]:
            status = req.get('status_code', 'N/A')
            print(f"   - {req['method']} {req['url']} - Status: {status}")
    else:
        print("   No requests captured yet")
        print("   Note: Configure your browser to use the proxy to capture traffic")

def demo_interceptor():
    """Demonstrate the Interceptor functionality"""
    print_header("Request Interceptor Demo")
    
    print("\n1. Checking for intercepted requests...")
    response = requests.get(f"{BASE_URL}/interceptor/api/intercepted/")
    intercepted_list = response.json()
    
    print(f"   Pending intercepted requests: {len(intercepted_list)}")
    
    if intercepted_list:
        print("\n   Intercepted requests:")
        for req in intercepted_list:
            print(f"   - {req['original_method']} {req['original_url']}")
            print(f"     Status: {req['status']}")
    else:
        print("   No pending intercepted requests")
        print("   Note: Enable interception mode to capture requests")

def main():
    """Main demo function"""
    print("\n" + "=" * 70)
    print("  Megido Security Testing Platform - API Demo")
    print("=" * 70)
    print("\n  This script demonstrates the API functionality")
    print("  Make sure the Django server is running on http://localhost:8000")
    print("\n  Press Ctrl+C to exit at any time")
    
    input("\n  Press Enter to continue...")
    
    try:
        # Test connection
        print_header("Testing Connection")
        print("\nConnecting to Megido API...")
        response = requests.get(f"{BASE_URL}/")
        if response.status_code == 200:
            print("✓ Connected successfully!")
        else:
            print("✗ Connection failed!")
            return
        
        # Run demos
        input("\nPress Enter to start Repeater demo...")
        demo_repeater()
        
        input("\n\nPress Enter to start Scanner demo...")
        demo_scanner()
        
        input("\n\nPress Enter to check Proxy status...")
        demo_proxy()
        
        input("\n\nPress Enter to check Interceptor status...")
        demo_interceptor()
        
        print_header("Demo Complete")
        print("\n  ✓ All demos completed successfully!")
        print("\n  For more information, see:")
        print("  - README.md for project overview")
        print("  - USAGE_GUIDE.md for detailed usage instructions")
        print("\n  Access the web interface at: http://localhost:8000")
        print()
        
    except requests.exceptions.ConnectionError:
        print("\n✗ Error: Could not connect to the server")
        print("  Make sure the Django server is running:")
        print("  python manage.py runserver")
    except KeyboardInterrupt:
        print("\n\n✋ Demo interrupted by user")
    except Exception as e:
        print(f"\n✗ Error: {e}")

if __name__ == '__main__':
    main()
