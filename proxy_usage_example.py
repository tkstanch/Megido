#!/usr/bin/env python3
"""
Example script demonstrating proxy usage and features.

This script shows:
1. How to start the proxy
2. How to use the API endpoints
3. How to replay requests
4. How to query logs
5. How to work with WebSocket messages

Usage:
    python proxy_usage_example.py
"""

import requests
import json
import time
from pathlib import Path


# Configuration
API_BASE_URL = 'http://localhost:8000'
PROXY_API = f'{API_BASE_URL}/proxy/api'


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def example_list_requests():
    """Example: List captured requests"""
    print_section("Example 1: List Captured Requests")
    
    # Basic list
    response = requests.get(f'{PROXY_API}/requests/')
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"Total requests: {data['total']}")
    print(f"Showing {len(data['requests'])} requests\n")
    
    # Show first few requests
    for req in data['requests'][:3]:
        print(f"  [{req['id']}] {req['method']} {req['url'][:60]}")
        print(f"      Protocol: {req['protocol']}, Source: {req['source_ip']}")
        if req['status_code']:
            print(f"      Response: {req['status_code']} ({req['response_time']:.2f}ms)")
        print()


def example_filter_requests():
    """Example: Filter requests"""
    print_section("Example 2: Filter Requests")
    
    # Filter by method
    response = requests.get(f'{PROXY_API}/requests/', params={
        'method': 'POST',
        'limit': 5
    })
    data = response.json()
    print(f"POST requests found: {data['total']}")
    
    # Filter by protocol
    response = requests.get(f'{PROXY_API}/requests/', params={
        'protocol': 'HTTPS',
        'limit': 5
    })
    data = response.json()
    print(f"HTTPS requests found: {data['total']}")
    
    # Search in URLs
    response = requests.get(f'{PROXY_API}/requests/', params={
        'search': 'api',
        'limit': 5
    })
    data = response.json()
    print(f"Requests with 'api' in URL: {data['total']}")


def example_request_details():
    """Example: Get request details"""
    print_section("Example 3: Get Request Details")
    
    # Get first request ID
    response = requests.get(f'{PROXY_API}/requests/', params={'limit': 1})
    data = response.json()
    
    if data['requests']:
        request_id = data['requests'][0]['id']
        
        # Get full details
        response = requests.get(f'{PROXY_API}/requests/{request_id}/')
        details = response.json()
        
        print(f"Request ID: {details['id']}")
        print(f"Method: {details['method']}")
        print(f"URL: {details['url']}")
        print(f"Protocol: {details['protocol']}")
        print(f"Source IP: {details['source_ip']}")
        print(f"User Agent: {details['user_agent']}")
        print(f"Request Size: {details['request_size']} bytes")
        
        # Show headers
        headers = json.loads(details['headers'])
        print(f"\nHeaders ({len(headers)}):")
        for key, value in list(headers.items())[:5]:
            print(f"  {key}: {value}")
        
        # Show response if available
        if 'response' in details:
            resp = details['response']
            print(f"\nResponse:")
            print(f"  Status: {resp['status_code']}")
            print(f"  Time: {resp['response_time']:.2f}ms")
            print(f"  Size: {resp['response_size']} bytes")
            print(f"  Cached: {resp['cached']}")
    else:
        print("No requests found in database")


def example_replay_request():
    """Example: Replay a request"""
    print_section("Example 4: Replay Request")
    
    # Get a request to replay
    response = requests.get(f'{PROXY_API}/requests/', params={
        'method': 'GET',
        'limit': 1
    })
    data = response.json()
    
    if data['requests']:
        request_id = data['requests'][0]['id']
        original_url = data['requests'][0]['url']
        
        print(f"Replaying request {request_id}")
        print(f"Original URL: {original_url}")
        
        # Replay to original URL
        print("\n1. Replay to original URL:")
        response = requests.post(f'{PROXY_API}/requests/{request_id}/replay/')
        result = response.json()
        
        if result.get('success'):
            print(f"   ✓ Success! Status: {result['response']['status_code']}")
            print(f"   Response time: {result['response']['response_time']:.2f}ms")
        else:
            print(f"   ✗ Failed: {result.get('error')}")
        
        # Replay to test URL (example)
        print("\n2. Replay to test URL:")
        test_url = 'http://httpbin.org/get'
        response = requests.post(
            f'{PROXY_API}/requests/{request_id}/replay/',
            json={'target_url': test_url}
        )
        result = response.json()
        
        if result.get('success'):
            print(f"   ✓ Success! Status: {result['response']['status_code']}")
        else:
            print(f"   ✗ Failed: {result.get('error')}")
    else:
        print("No GET requests found for replay example")


def example_websocket_messages():
    """Example: Query WebSocket messages"""
    print_section("Example 5: WebSocket Messages")
    
    response = requests.get(f'{PROXY_API}/websocket-messages/list/', params={
        'limit': 10
    })
    data = response.json()
    
    print(f"Total WebSocket messages: {data['total']}")
    
    if data['messages']:
        print(f"\nShowing {len(data['messages'])} messages:\n")
        
        for msg in data['messages'][:5]:
            print(f"  Connection: {msg['connection_id']}")
            print(f"  Direction: {msg['direction']}, Type: {msg['message_type']}")
            print(f"  Size: {msg['payload_size']} bytes")
            print(f"  Payload preview: {msg['payload'][:50]}...")
            print()
    else:
        print("No WebSocket messages found")


def example_errors():
    """Example: Query error logs"""
    print_section("Example 6: Error Logs")
    
    response = requests.get(f'{PROXY_API}/errors/list/', params={
        'limit': 10
    })
    data = response.json()
    
    print(f"Total errors: {data['total']}")
    
    if data['errors']:
        print(f"\nRecent errors:\n")
        
        for err in data['errors'][:5]:
            print(f"  [{err['error_type']}] {err['error_message']}")
            if err['url']:
                print(f"    URL: {err['url']}")
            if err['source_ip']:
                print(f"    Source: {err['source_ip']}")
            print()
    else:
        print("No errors logged (proxy is running smoothly!)")


def example_statistics():
    """Example: Get proxy statistics"""
    print_section("Example 7: Proxy Statistics")
    
    response = requests.get(f'{PROXY_API}/stats/')
    stats = response.json()
    
    print(f"Total Requests: {stats['total_requests']}")
    print(f"WebSocket Messages: {stats['total_websocket_messages']}")
    print(f"Errors: {stats['total_errors']}")
    print(f"Average Response Time: {stats['avg_response_time']:.2f}ms" 
          if stats['avg_response_time'] else "N/A")
    print(f"Recent Auth Failures: {stats['recent_auth_failures']}")
    
    print("\nRequests by Method:")
    for item in stats['requests_by_method']:
        print(f"  {item['method']}: {item['count']}")
    
    print("\nRequests by Protocol:")
    for item in stats['requests_by_protocol']:
        print(f"  {item['protocol']}: {item['count']}")


def example_file_logs():
    """Example: Access file-based logs"""
    print_section("Example 8: File-Based Logs")
    
    log_dir = Path('logs/proxy')
    
    if log_dir.exists():
        print(f"Log directory: {log_dir}")
        print(f"\nLog structure:")
        
        for subdir in ['requests', 'responses', 'websockets', 'errors', 'auth']:
            path = log_dir / subdir
            if path.exists():
                # Count log files
                count = len(list(path.rglob('*.json')))
                print(f"  {subdir}/: {count} log files")
        
        # Show recent request log
        requests_dir = log_dir / 'requests'
        if requests_dir.exists():
            log_files = sorted(requests_dir.rglob('*.json'), 
                             key=lambda x: x.stat().st_mtime, reverse=True)
            
            if log_files:
                print(f"\nMost recent request log:")
                with open(log_files[0], 'r') as f:
                    log_data = json.load(f)
                    print(f"  File: {log_files[0].name}")
                    print(f"  Time: {log_data['timestamp']}")
                    print(f"  Method: {log_data.get('method')}")
                    print(f"  URL: {log_data.get('url', 'N/A')[:60]}")
    else:
        print(f"Log directory not found: {log_dir}")
        print("Logs will be created when the proxy starts logging")


def example_cli_tool():
    """Example: Using the CLI tool"""
    print_section("Example 9: CLI Tool Usage")
    
    print("The proxy_replay_cli.py tool provides command-line access:\n")
    
    print("1. List captured requests:")
    print("   $ python proxy_replay_cli.py list --limit 20\n")
    
    print("2. Show request details:")
    print("   $ python proxy_replay_cli.py show 123\n")
    
    print("3. Replay a request:")
    print("   $ python proxy_replay_cli.py replay 123\n")
    
    print("4. Replay to test server:")
    print("   $ python proxy_replay_cli.py replay 123 --target-url http://localhost:3000\n")
    
    print("5. Replay multiple requests:")
    print("   $ python proxy_replay_cli.py replay-range 100 110 --delay 1.0\n")
    
    print("6. Search requests:")
    print("   $ python proxy_replay_cli.py list --url api.example.com --method POST\n")


def example_python_api():
    """Example: Using Python API"""
    print_section("Example 10: Python API Usage")
    
    print("Direct database access via Django ORM:\n")
    
    print("""
from proxy.models import ProxyRequest, ProxyResponse
from proxy.replay_utils import replay_from_database
from proxy.logging_utils import ProxyLogger

# Query requests
https_posts = ProxyRequest.objects.filter(
    protocol='HTTPS',
    method='POST'
).order_by('-timestamp')[:10]

# Replay a request
result = replay_from_database(123, target_url='http://localhost:3000')

# Access logs
logger = ProxyLogger()
recent_logs = logger.get_recent_logs('requests', limit=50)
recent_errors = logger.get_recent_logs('errors', limit=20)

# Cleanup old logs
removed_count = logger.cleanup_old_logs(days_to_keep=30)
print(f"Removed {removed_count} old log files")

# Statistics
from django.db.models import Count, Avg
method_stats = ProxyRequest.objects.values('method').annotate(
    count=Count('id')
)
    """)


def main():
    """Run all examples"""
    print("\n" + "=" * 70)
    print("  MEGIDO PROXY - USAGE EXAMPLES")
    print("=" * 70)
    print(f"\n  API Base URL: {API_BASE_URL}")
    print(f"  Proxy API: {PROXY_API}\n")
    print("  Note: Django server must be running at {API_BASE_URL}")
    print("=" * 70)
    
    try:
        # Check if API is accessible
        response = requests.get(f'{PROXY_API}/stats/', timeout=2)
        if response.status_code != 200:
            print(f"\n⚠️  Warning: API returned status {response.status_code}")
            print("Some examples may not work correctly.\n")
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error: Cannot connect to API at {API_BASE_URL}")
        print(f"   {str(e)}")
        print("\n   Please ensure:")
        print("   1. Django server is running: python manage.py runserver")
        print("   2. API URL is correct in this script")
        print("\n   Showing documentation examples only...\n")
        
        # Show examples that don't require API
        example_cli_tool()
        example_python_api()
        return
    
    # Run examples that require API
    try:
        example_list_requests()
        time.sleep(0.5)
        
        example_filter_requests()
        time.sleep(0.5)
        
        example_request_details()
        time.sleep(0.5)
        
        # Skip replay example in demo mode to avoid external requests
        # example_replay_request()
        
        example_websocket_messages()
        time.sleep(0.5)
        
        example_errors()
        time.sleep(0.5)
        
        example_statistics()
        time.sleep(0.5)
        
        example_file_logs()
        time.sleep(0.5)
        
        example_cli_tool()
        example_python_api()
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("  Examples completed!")
    print("=" * 70 + "\n")


if __name__ == '__main__':
    main()
