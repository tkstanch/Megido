#!/usr/bin/env python3
"""
Command-line tool for replaying HTTP requests captured by the proxy.

Usage:
    python proxy_replay_cli.py list [--limit N]
    python proxy_replay_cli.py replay <request_id> [--target-url URL] [--no-verify-ssl]
    python proxy_replay_cli.py replay-range <start_id> <end_id> [--target-url URL] [--delay SECONDS]
    python proxy_replay_cli.py show <request_id>
    python proxy_replay_cli.py search --url PATTERN [--method METHOD] [--limit N]
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# Add parent directory to path for Django imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
import django
django.setup()

from proxy.models import ProxyRequest, ProxyResponse
from proxy.replay_utils import RequestReplayer, replay_from_database


def list_requests(limit: int = 20, method: str = None, url_pattern: str = None):
    """List recent captured requests"""
    queryset = ProxyRequest.objects.all()
    
    # Apply filters
    if method:
        queryset = queryset.filter(method=method.upper())
    if url_pattern:
        queryset = queryset.filter(url__icontains=url_pattern)
    
    requests = queryset[:limit]
    
    if not requests:
        print("No requests found.")
        return
    
    print(f"\n{'ID':<8} {'Method':<8} {'Protocol':<10} {'URL':<60} {'Timestamp':<20}")
    print("-" * 110)
    
    for req in requests:
        url_display = req.url[:57] + '...' if len(req.url) > 60 else req.url
        timestamp = req.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{req.id:<8} {req.method:<8} {req.protocol:<10} {url_display:<60} {timestamp:<20}")
    
    print(f"\nShowing {len(requests)} of {queryset.count()} total requests")


def show_request(request_id: int):
    """Show detailed information about a request"""
    try:
        request = ProxyRequest.objects.get(id=request_id)
    except ProxyRequest.DoesNotExist:
        print(f"Error: Request with ID {request_id} not found")
        return 1
    
    print("\n" + "=" * 80)
    print(f"Request ID: {request.id}")
    print("=" * 80)
    print(f"Method:      {request.method}")
    print(f"URL:         {request.url}")
    print(f"Protocol:    {request.protocol}")
    print(f"Host:        {request.host}:{request.port}")
    print(f"Source IP:   {request.source_ip or 'N/A'}")
    print(f"User Agent:  {request.user_agent or 'N/A'}")
    print(f"Timestamp:   {request.timestamp}")
    print(f"Size:        {request.request_size} bytes")
    print(f"Is Replay:   {request.is_replay}")
    
    # Show headers
    print("\nHeaders:")
    print("-" * 80)
    headers = request.get_headers_dict()
    for key, value in headers.items():
        print(f"  {key}: {value}")
    
    # Show body if present
    if request.body:
        print("\nBody:")
        print("-" * 80)
        body_display = request.body[:500]
        if len(request.body) > 500:
            body_display += f"\n... (truncated, {len(request.body)} total bytes)"
        print(body_display)
    
    # Show response if available
    if hasattr(request, 'response'):
        resp = request.response
        print("\n" + "=" * 80)
        print("Response")
        print("=" * 80)
        print(f"Status Code:    {resp.status_code}")
        print(f"Response Time:  {resp.response_time:.2f} ms")
        print(f"Size:           {resp.response_size} bytes")
        print(f"Cached:         {resp.cached}")
        
        print("\nHeaders:")
        print("-" * 80)
        resp_headers = resp.get_headers_dict()
        for key, value in resp_headers.items():
            print(f"  {key}: {value}")
        
        if resp.body:
            print("\nBody:")
            print("-" * 80)
            body_display = resp.body[:500]
            if len(resp.body) > 500:
                body_display += f"\n... (truncated, {len(resp.body)} total bytes)"
            print(body_display)
    
    return 0


def replay_request(
    request_id: int,
    target_url: str = None,
    verify_ssl: bool = True,
    verbose: bool = False
):
    """Replay a single request"""
    print(f"\nReplaying request ID {request_id}...")
    
    if target_url:
        print(f"Target URL: {target_url}")
    
    try:
        result = replay_from_database(request_id, target_url)
        
        if result.get('success', False):
            print("\n✓ Replay successful!")
            response = result.get('response', {})
            print(f"  Status Code:   {response.get('status_code')}")
            print(f"  Response Time: {response.get('response_time', 0):.2f} ms")
            print(f"  Replayed Request ID: {result.get('replayed_request_id')}")
            
            if verbose:
                print("\n  Response Headers:")
                for key, value in response.get('headers', {}).items():
                    print(f"    {key}: {value}")
                
                body = response.get('body', '')
                if body:
                    print(f"\n  Response Body ({len(body)} bytes):")
                    print(f"    {body[:500]}")
        else:
            print(f"\n✗ Replay failed: {result.get('error')}")
            return 1
            
    except Exception as e:
        print(f"\n✗ Error during replay: {e}")
        return 1
    
    return 0


def replay_range(
    start_id: int,
    end_id: int,
    target_url: str = None,
    delay: float = 0.5,
    verify_ssl: bool = True
):
    """Replay a range of requests"""
    print(f"\nReplaying requests {start_id} to {end_id}...")
    
    requests = ProxyRequest.objects.filter(
        id__gte=start_id,
        id__lte=end_id
    ).order_by('id')
    
    if not requests:
        print("No requests found in the specified range")
        return 1
    
    print(f"Found {requests.count()} requests to replay")
    
    replayer = RequestReplayer(verify_ssl=verify_ssl)
    
    success_count = 0
    failure_count = 0
    
    for request in requests:
        print(f"\nReplaying {request.method} {request.url}...", end=" ")
        
        result = replayer.replay_from_dict(
            {
                'url': request.url,
                'method': request.method,
                'headers': request.headers,
                'body': request.body
            },
            target_url=target_url
        )
        
        if result.get('response', {}).get('success', False):
            status = result['response'].get('status_code')
            response_time = result['response'].get('response_time', 0)
            print(f"✓ {status} ({response_time:.0f}ms)")
            success_count += 1
        else:
            error = result.get('error_message', 'Unknown error')
            print(f"✗ {error}")
            failure_count += 1
        
        # Delay between requests
        if delay > 0:
            import time
            time.sleep(delay)
    
    print(f"\n{'='*60}")
    print(f"Replay Summary:")
    print(f"  Total:    {success_count + failure_count}")
    print(f"  Success:  {success_count}")
    print(f"  Failed:   {failure_count}")
    print(f"{'='*60}")
    
    return 0 if failure_count == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description='Replay HTTP requests captured by Megido proxy',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List captured requests')
    list_parser.add_argument('--limit', type=int, default=20, help='Number of requests to show')
    list_parser.add_argument('--method', help='Filter by HTTP method')
    list_parser.add_argument('--url', help='Filter by URL pattern')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show request details')
    show_parser.add_argument('request_id', type=int, help='Request ID to show')
    
    # Replay command
    replay_parser = subparsers.add_parser('replay', help='Replay a single request')
    replay_parser.add_argument('request_id', type=int, help='Request ID to replay')
    replay_parser.add_argument('--target-url', help='Alternative target URL')
    replay_parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    replay_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Replay range command
    range_parser = subparsers.add_parser('replay-range', help='Replay a range of requests')
    range_parser.add_argument('start_id', type=int, help='Start request ID')
    range_parser.add_argument('end_id', type=int, help='End request ID')
    range_parser.add_argument('--target-url', help='Alternative target URL for all requests')
    range_parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (seconds)')
    range_parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    if args.command == 'list':
        list_requests(args.limit, args.method, args.url)
        return 0
    
    elif args.command == 'show':
        return show_request(args.request_id)
    
    elif args.command == 'replay':
        verify_ssl = not args.no_verify_ssl
        return replay_request(
            args.request_id,
            args.target_url,
            verify_ssl,
            args.verbose
        )
    
    elif args.command == 'replay-range':
        verify_ssl = not args.no_verify_ssl
        return replay_range(
            args.start_id,
            args.end_id,
            args.target_url,
            args.delay,
            verify_ssl
        )
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {e}", file=sys.stderr)
        sys.exit(1)
