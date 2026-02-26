"""
Scan Plugin Detectors

This directory contains individual scan plugin implementations.
Each plugin detects a specific type of vulnerability or security issue.

Available Plugins:
- xss_scanner: Active XSS detection (reflected, stored, DOM-based) with 30+ payloads
- security_headers_scanner: Checks for missing security headers
- ssl_scanner: Checks for SSL/TLS configuration issues
- csrf_scanner: Detects missing or weak CSRF protection
- cors_scanner: CORS misconfiguration detection
- ssrf_detector: Server-Side Request Forgery detection
- lfi_detector: Local File Inclusion detection
- rfi_detector: Remote File Inclusion detection
- xxe_detector: XML External Entity injection detection
- rce_detector: Remote Code Execution detection
- clickjacking_detector: Clickjacking / UI redress detection
- javascript_hijacking_detector: JavaScript hijacking / JSONP data exposure
- cookie_security_scanner: Cookie security attribute checks
- info_disclosure_detector: Information disclosure detection
- sensitive_data_scanner: Sensitive data exposure detection
- session_fixation_detector: Session fixation detection
- open_redirect_detector: Active open redirect detection (CWE-601)
- crlf_detector: CRLF injection / HTTP header injection (CWE-113)
- crlf_injection_detector: Extended CRLF injection with response splitting
- sqli_scanner: SQL injection detection — error-based, boolean-blind,
                time-blind, UNION-based (CWE-89)
- idor_detector: Insecure Direct Object Reference detection (CWE-639)
- jwt_scanner: JWT security issues — alg:none, weak algorithms,
               missing expiry, key confusion (CWE-347)
- host_header_detector: Host header injection / cache poisoning (CWE-644)
- smuggling_detector: HTTP request smuggling — CL.TE / TE.CL (CWE-444)
- deserialization_detector: Insecure deserialization signature detection (CWE-502)
- graphql_scanner: GraphQL introspection and security checks (CWE-200)
- websocket_scanner: WebSocket security and CSWSH detection (CWE-1385)
- cache_poisoning_detector: Web cache poisoning via unkeyed headers (CWE-444)

Plugins are automatically discovered by the ScanPluginRegistry.
"""
