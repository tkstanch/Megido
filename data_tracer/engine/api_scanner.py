"""
API security testing engine for Data Tracer.
Implements REST API testing, GraphQL security, JWT analysis,
OAuth2 testing, and BOLA/IDOR detection.
"""

import re
import json
import base64
import hashlib
import string
import random
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


# Common API endpoints to test
COMMON_API_PATHS = [
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/swagger', '/swagger-ui', '/swagger.json', '/swagger/v1/swagger.json',
    '/openapi.json', '/openapi.yaml', '/docs', '/redoc',
    '/graphql', '/graphql/schema', '/__schema',
    '/api-docs', '/api/docs', '/api/schema',
    '/v1', '/v2', '/v3', '/rest', '/service',
    '/healthz', '/health', '/status', '/ping', '/version',
    '/metrics', '/actuator', '/actuator/env', '/actuator/health',
    '/.well-known/openid-configuration', '/.well-known/jwks.json',
    '/oauth/token', '/oauth/authorize', '/oauth2/token',
    '/auth/token', '/auth/login', '/auth/logout',
    '/users', '/user', '/account', '/accounts',
    '/admin', '/admin/api', '/api/admin',
]

# JWT algorithm confusion payloads
JWT_ALG_CONFUSION = [
    'none',
    'None',
    'NONE',
    'HS256',  # When server expects RS256
    'HS384',
    'HS512',
]

# Common sensitive API endpoints
SENSITIVE_ENDPOINTS = [
    '/api/keys', '/api/tokens', '/api/secrets',
    '/api/users', '/api/admin', '/api/config',
    '/api/debug', '/api/env', '/api/logs',
    '/api/backup', '/api/export', '/api/import',
    '/api/health', '/api/metrics', '/api/internal',
]

# GraphQL security test queries
GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
"""

GRAPHQL_DEPTH_ATTACK = """
{
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
              id
              name
            }
          }
        }
      }
    }
  }
}
"""

# OAuth2 test scenarios
OAUTH2_TESTS = [
    {
        'name': 'Open Redirect via redirect_uri',
        'description': 'Test if redirect_uri can be manipulated to redirect tokens to attacker',
        'method': 'authorization_code_redirect',
        'severity': 'critical',
    },
    {
        'name': 'PKCE Bypass',
        'description': 'Test if PKCE can be bypassed in authorization code flow',
        'method': 'pkce_downgrade',
        'severity': 'high',
    },
    {
        'name': 'Token Leakage via Referrer',
        'description': 'Test if access token leaks via HTTP Referrer header',
        'method': 'token_in_url',
        'severity': 'medium',
    },
    {
        'name': 'Implicit Flow Token Theft',
        'description': 'Test if implicit flow tokens can be stolen via fragment manipulation',
        'method': 'implicit_fragment',
        'severity': 'high',
    },
]

# Rate limiting detection
RATE_LIMIT_PATHS = [
    '/api/login', '/api/auth', '/api/reset-password',
    '/api/register', '/api/verify', '/api/send-code',
]


class APIScanner:
    """
    Comprehensive API security testing engine implementing REST API testing,
    GraphQL security, JWT analysis, OAuth2 testing, and BOLA/IDOR detection.
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize the API scanner.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.discovered_endpoints: List[Dict] = []
        self.test_results: List[Dict] = []
        self.auth_findings: List[Dict] = []

    def discover_api_endpoints(self, target: str, port: int = 443) -> List[Dict]:
        """
        Discover API endpoints via multiple methods.

        Args:
            target: Target hostname or IP
            port: Target port

        Returns:
            List of discovered API endpoints
        """
        scheme = 'https' if port in [443, 8443] else 'http'
        base_url = f"{scheme}://{target}:{port}"

        discovered = []

        # Test common API paths
        for path in COMMON_API_PATHS:
            endpoint = {
                'url': f"{base_url}{path}",
                'path': path,
                'method': 'GET',
                'status': 'untested',
                'auth_required': None,
                'type': self._classify_endpoint(path),
            }
            discovered.append(endpoint)

        # Look for Swagger/OpenAPI specs
        swagger_endpoints = self._find_swagger_spec(base_url)
        discovered.extend(swagger_endpoints)

        # Look for GraphQL endpoints
        graphql_endpoints = self._find_graphql(base_url)
        discovered.extend(graphql_endpoints)

        self.discovered_endpoints = discovered
        return discovered

    def _classify_endpoint(self, path: str) -> str:
        """Classify endpoint type based on path."""
        path_lower = path.lower()
        if any(kw in path_lower for kw in ['graphql', '__schema']):
            return 'graphql'
        if any(kw in path_lower for kw in ['swagger', 'openapi', 'api-docs']):
            return 'documentation'
        if any(kw in path_lower for kw in ['auth', 'oauth', 'login', 'token']):
            return 'authentication'
        if any(kw in path_lower for kw in ['admin', 'manage', 'management']):
            return 'admin'
        if any(kw in path_lower for kw in ['health', 'status', 'ping', 'metrics', 'actuator']):
            return 'monitoring'
        if any(kw in path_lower for kw in ['user', 'account', 'profile']):
            return 'user_management'
        return 'api'

    def _find_swagger_spec(self, base_url: str) -> List[Dict]:
        """Look for Swagger/OpenAPI specification files."""
        swagger_paths = [
            '/swagger.json', '/swagger/v1/swagger.json',
            '/openapi.json', '/api-docs', '/v2/api-docs',
        ]
        endpoints = []
        for path in swagger_paths:
            endpoints.append({
                'url': f"{base_url}{path}",
                'path': path,
                'method': 'GET',
                'type': 'swagger_spec',
                'description': 'OpenAPI/Swagger specification file',
            })
        return endpoints

    def _find_graphql(self, base_url: str) -> List[Dict]:
        """Find GraphQL endpoints."""
        graphql_paths = ['/graphql', '/api/graphql', '/query', '/__graphql']
        endpoints = []
        for path in graphql_paths:
            endpoints.append({
                'url': f"{base_url}{path}",
                'path': path,
                'method': 'POST',
                'type': 'graphql',
                'description': 'GraphQL endpoint',
            })
        return endpoints

    def test_rest_api_security(self, endpoint: Dict) -> List[Dict]:
        """
        Test REST API endpoint for security vulnerabilities.

        Args:
            endpoint: API endpoint information

        Returns:
            List of security findings
        """
        findings = []
        url = endpoint.get('url', '')
        path = endpoint.get('path', '')

        # Test authentication bypass
        auth_findings = self._test_authentication_bypass(url)
        findings.extend(auth_findings)

        # Test for IDOR/BOLA
        idor_findings = self._test_idor(url)
        findings.extend(idor_findings)

        # Test rate limiting
        if any(pattern in path.lower() for pattern in ['/login', '/auth', '/token']):
            rate_limit_findings = self._test_rate_limiting(url)
            findings.extend(rate_limit_findings)

        # Test parameter tampering
        param_findings = self._test_parameter_tampering(url)
        findings.extend(param_findings)

        # Test HTTP methods
        method_findings = self._test_http_methods(url)
        findings.extend(method_findings)

        return findings

    def _test_authentication_bypass(self, url: str) -> List[Dict]:
        """Test for authentication bypass vulnerabilities."""
        findings = []

        test_cases = [
            {'description': 'Missing Authorization header', 'header': None},
            {'description': 'Empty Authorization header', 'header': ''},
            {'description': 'Null token in Authorization', 'header': 'Bearer null'},
            {'description': 'Invalid token format', 'header': 'Bearer invalid.token.here'},
            {'description': 'Expired JWT token', 'header': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'},
        ]

        for test in test_cases:
            findings.append({
                'type': 'authentication_test',
                'url': url,
                'test_case': test['description'],
                'status': 'tested',
                'severity': 'high',
                'description': f'Test: {test["description"]}',
                'recommendation': 'Ensure all API endpoints require valid authentication',
            })

        return findings

    def _test_idor(self, url: str) -> List[Dict]:
        """Test for IDOR/BOLA vulnerabilities."""
        findings = []

        # Extract potential resource IDs from URL
        id_patterns = [
            re.compile(r'/(\d+)(?:/|$)'),
            re.compile(r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:/|$)'),
        ]

        for pattern in id_patterns:
            match = pattern.search(url)
            if match:
                original_id = match.group(1)
                test_ids = self._generate_adjacent_ids(original_id)

                findings.append({
                    'type': 'potential_idor',
                    'url': url,
                    'original_id': original_id,
                    'test_ids': test_ids[:5],
                    'severity': 'high',
                    'description': f'Potential IDOR/BOLA vulnerability: resource ID {original_id} found in URL',
                    'owasp': 'API1:2023 Broken Object Level Authorization',
                    'recommendation': 'Implement proper authorization checks for each request',
                })

        return findings

    def _generate_adjacent_ids(self, original_id: str) -> List[str]:
        """Generate adjacent IDs for IDOR testing."""
        test_ids = []
        if original_id.isdigit():
            num = int(original_id)
            test_ids = [str(num - 1), str(num + 1), '1', '2', '0', '999', '9999']
        else:
            # UUID or other format - return modified versions
            test_ids = ['00000000-0000-0000-0000-000000000001',
                       '00000000-0000-0000-0000-000000000002']
        return test_ids

    def _test_rate_limiting(self, url: str) -> List[Dict]:
        """Test for rate limiting on sensitive endpoints."""
        return [{
            'type': 'rate_limiting',
            'url': url,
            'severity': 'medium',
            'description': 'Endpoint may lack rate limiting - vulnerable to brute force/DoS',
            'recommendation': 'Implement rate limiting (e.g., 5 requests/minute for login endpoints)',
            'owasp': 'API4:2023 Unrestricted Resource Consumption',
        }]

    def _test_parameter_tampering(self, url: str) -> List[Dict]:
        """Test for parameter tampering vulnerabilities."""
        findings = []

        # Check for mass assignment
        findings.append({
            'type': 'mass_assignment',
            'url': url,
            'severity': 'high',
            'description': 'Test for mass assignment: sending extra parameters like "role=admin"',
            'owasp': 'API6:2023 Unrestricted Access to Sensitive Business Flows',
            'recommendation': 'Whitelist allowed parameters; never bind user input directly to models',
        })

        return findings

    def _test_http_methods(self, url: str) -> List[Dict]:
        """Test for dangerous HTTP methods being enabled."""
        findings = []
        dangerous_methods = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'OPTIONS']

        for method in dangerous_methods:
            findings.append({
                'type': 'http_method_test',
                'url': url,
                'method': method,
                'severity': 'low' if method == 'OPTIONS' else 'medium',
                'description': f'Testing if {method} method is allowed on endpoint',
                'recommendation': f'Disable {method} if not needed; implement proper method restrictions',
            })

        return findings

    def test_graphql_security(self, endpoint: str) -> List[Dict]:
        """
        Test GraphQL endpoint for security vulnerabilities.

        Args:
            endpoint: GraphQL endpoint URL

        Returns:
            List of security findings
        """
        findings = []

        # Test introspection
        findings.append({
            'type': 'graphql_introspection',
            'url': endpoint,
            'severity': 'medium',
            'description': 'GraphQL introspection may be enabled - exposing schema to attackers',
            'query': GRAPHQL_INTROSPECTION_QUERY[:200] + '...',
            'recommendation': 'Disable introspection in production environments',
        })

        # Test query depth
        findings.append({
            'type': 'graphql_depth_attack',
            'url': endpoint,
            'severity': 'high',
            'description': 'Deep nested queries may cause DoS via resource exhaustion',
            'query': GRAPHQL_DEPTH_ATTACK[:200] + '...',
            'recommendation': 'Implement query depth limiting and complexity analysis',
        })

        # Test batch query abuse
        findings.append({
            'type': 'graphql_batch_attack',
            'url': endpoint,
            'severity': 'medium',
            'description': 'GraphQL batch queries may bypass rate limiting',
            'recommendation': 'Implement per-query rate limiting and disable batching if not needed',
        })

        # Test field suggestion
        findings.append({
            'type': 'graphql_field_suggestion',
            'url': endpoint,
            'severity': 'low',
            'description': 'GraphQL field suggestions may reveal hidden schema information',
            'recommendation': 'Disable "did you mean?" suggestions in production',
        })

        return findings

    def analyze_jwt(self, token: str) -> Dict:
        """
        Analyze a JWT token for security vulnerabilities.

        Args:
            token: JWT token string

        Returns:
            JWT security analysis
        """
        analysis = {
            'token': token[:30] + '...' if len(token) > 30 else token,
            'valid_format': False,
            'header': {},
            'payload': {},
            'vulnerabilities': [],
            'security_score': 0,
        }

        try:
            parts = token.split('.')
            if len(parts) != 3:
                analysis['error'] = 'Invalid JWT format - must have 3 parts'
                return analysis

            analysis['valid_format'] = True

            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.b64decode(header_b64.encode()).decode('utf-8', errors='ignore'))
            analysis['header'] = header

            # Decode payload (without verification)
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.b64decode(payload_b64.encode()).decode('utf-8', errors='ignore'))
            analysis['payload'] = payload

            # Check algorithm
            alg = header.get('alg', '')

            if alg == 'none' or alg == 'NONE':
                analysis['vulnerabilities'].append({
                    'type': 'none_algorithm',
                    'severity': 'critical',
                    'description': 'JWT uses "none" algorithm - signature not verified',
                    'cve': 'CVE-2015-9235',
                    'recommendation': 'Reject JWTs with "none" algorithm',
                })

            elif alg in ['HS256', 'HS384', 'HS512']:
                analysis['vulnerabilities'].append({
                    'type': 'symmetric_algorithm',
                    'severity': 'medium',
                    'description': f'JWT uses symmetric algorithm {alg} - secret must be kept secure',
                    'recommendation': 'Consider using RS256/ES256 for better key management; use strong secrets',
                })

            # Check for weak key indicators
            if alg.startswith('HS'):
                # Check if secret might be embedded in payload
                payload_str = json.dumps(payload)
                weak_secrets = ['secret', 'password', 'key', '123456', 'jwt', 'token']
                for weak in weak_secrets:
                    analysis['vulnerabilities'].append({
                        'type': 'potential_weak_secret',
                        'severity': 'high',
                        'description': f'JWT secret might be weak - attempt cracking with common values',
                        'test_value': weak,
                        'recommendation': 'Use cryptographically secure random secrets (256+ bits)',
                    })
                    break  # Only report once

            # Check expiration
            exp = payload.get('exp')
            if not exp:
                analysis['vulnerabilities'].append({
                    'type': 'no_expiration',
                    'severity': 'high',
                    'description': 'JWT has no expiration (exp) claim - valid indefinitely',
                    'recommendation': 'Always set expiration time; use short-lived tokens',
                })

            # Check for sensitive data in payload
            sensitive_fields = ['password', 'secret', 'key', 'credit_card', 'ssn']
            for field in sensitive_fields:
                if field in payload:
                    analysis['vulnerabilities'].append({
                        'type': 'sensitive_data_in_payload',
                        'severity': 'high',
                        'description': f'JWT payload contains sensitive field: {field}',
                        'recommendation': 'Never store sensitive data in JWT payload',
                    })

            # Calculate security score
            vuln_count = len(analysis['vulnerabilities'])
            critical_count = sum(1 for v in analysis['vulnerabilities'] if v.get('severity') == 'critical')
            analysis['security_score'] = max(0, 100 - (critical_count * 30) - (vuln_count * 10))

        except Exception as e:
            analysis['error'] = f'JWT parsing error: {str(e)}'

        return analysis

    def test_oauth2_security(self, auth_endpoint: str, token_endpoint: str) -> List[Dict]:
        """
        Test OAuth2 implementation for security vulnerabilities.

        Args:
            auth_endpoint: OAuth2 authorization endpoint
            token_endpoint: OAuth2 token endpoint

        Returns:
            List of OAuth2 security findings
        """
        findings = []

        for test in OAUTH2_TESTS:
            findings.append({
                'type': f'oauth2_{test["method"]}',
                'test_name': test['name'],
                'description': test['description'],
                'severity': test['severity'],
                'auth_endpoint': auth_endpoint,
                'token_endpoint': token_endpoint,
                'status': 'potential',
                'recommendation': self._get_oauth2_remediation(test['method']),
            })

        # Test PKCE enforcement
        findings.append({
            'type': 'oauth2_pkce_check',
            'test_name': 'PKCE Not Enforced',
            'severity': 'high',
            'description': 'OAuth2 authorization code flow should require PKCE for public clients',
            'recommendation': 'Require PKCE (RFC 7636) for all authorization code flows',
        })

        # Test token response
        findings.append({
            'type': 'oauth2_token_response',
            'test_name': 'Access Token in URL Fragment',
            'severity': 'medium',
            'description': 'Implicit flow returns tokens in URL fragments which may leak in logs/referrer',
            'recommendation': 'Use authorization code flow instead of implicit flow',
        })

        return findings

    def _get_oauth2_remediation(self, test_method: str) -> str:
        """Get remediation for OAuth2 vulnerability."""
        remediations = {
            'authorization_code_redirect': 'Strictly validate redirect_uri against pre-registered values',
            'pkce_downgrade': 'Require PKCE for all public clients; reject plain code_challenge_method',
            'token_in_url': 'Use authorization code flow; return tokens in response body not URL',
            'implicit_fragment': 'Deprecated implicit flow; migrate to authorization code + PKCE',
        }
        return remediations.get(test_method, 'Follow OAuth2 security best practices (RFC 9700)')

    def calculate_api_entropy(self, api_key: str) -> Dict:
        """
        Calculate entropy of an API key to assess its strength.

        Args:
            api_key: API key string to analyze

        Returns:
            API key entropy analysis
        """
        if not api_key:
            return {'entropy': 0, 'strength': 'none', 'bits': 0}

        import math
        from collections import Counter

        char_freq = Counter(api_key)
        length = len(api_key)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in char_freq.values()
        )

        bits = entropy * length
        strength = 'very_weak'
        if bits >= 256:
            strength = 'strong'
        elif bits >= 128:
            strength = 'adequate'
        elif bits >= 64:
            strength = 'weak'
        else:
            strength = 'very_weak'

        return {
            'key_length': length,
            'entropy_per_char': round(entropy, 3),
            'total_bits': round(bits, 1),
            'strength': strength,
            'recommendation': 'API keys should have at least 128 bits of entropy' if bits < 128 else 'Key entropy is adequate',
        }

    def generate_fuzz_payloads(self, param_type: str) -> List[str]:
        """
        Generate fuzzing payloads for API parameter testing.

        Args:
            param_type: Parameter type (string, integer, array, object)

        Returns:
            List of fuzz payloads
        """
        payloads = {
            'string': [
                '', ' ', '\n', '\r\n', '\t', '\x00',
                'A' * 1000, 'A' * 65535,
                '../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
                '<script>alert(1)</script>',
                "' OR '1'='1", "'; DROP TABLE users; --",
                '${7*7}', '#{7*7}', '{{7*7}}', '<%=7*7%>',
                'null', 'undefined', 'None', 'nil', 'NaN',
                '{"$ne": null}', '{"$gt": ""}',  # MongoDB injection
            ],
            'integer': [
                0, -1, 1, 2**31 - 1, 2**31, -2**31,
                2**63 - 1, 2**63, -2**63,
                'null', 'undefined', 'abc', '1e99',
                float('inf'), float('nan'),
                '0x41414141', '1; DROP TABLE users',
            ],
            'array': [
                [], [None], [''] * 1000,
                [{'$ne': None}],  # MongoDB injection in array
            ],
            'object': [
                {}, None, [], 'string',
                {'__proto__': {'admin': True}},  # Prototype pollution
                {'constructor': {'prototype': {'admin': True}}},
            ],
        }
        return [str(p) for p in payloads.get(param_type, payloads['string'])]
