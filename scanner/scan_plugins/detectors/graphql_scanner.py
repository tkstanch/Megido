"""
GraphQL Introspection Scanner Plugin

Auto-detects GraphQL endpoints and runs introspection queries to map the
full schema. Flags enabled introspection as an information disclosure risk.

CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
"""

import json
import logging
from typing import Dict, List, Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

logger = logging.getLogger(__name__)

# Common GraphQL endpoint paths
_GRAPHQL_PATHS = [
    '/graphql',
    '/api/graphql',
    '/graphql/v1',
    '/v1/graphql',
    '/graph',
    '/gql',
    '/query',
]

_INTROSPECTION_QUERY = {
    "query": (
        "{"
        "__schema {"
        "  queryType { name } "
        "  mutationType { name } "
        "  types { name kind description } "
        "}"
        "}"
    )
}

_REMEDIATION = (
    "Disable GraphQL introspection in production environments. Most GraphQL "
    "libraries provide a configuration option to disable it "
    "(e.g., 'introspection: false' in Apollo Server). This prevents attackers "
    "from enumerating the full API schema. If introspection is required for "
    "development, restrict it to authenticated requests or internal IP ranges."
)


class GraphQLScannerPlugin(BaseScanPlugin):
    """
    GraphQL introspection scanner plugin.

    Auto-detects GraphQL endpoints at common paths under the target URL,
    sends an introspection query, and reports if the schema is exposed.
    """

    @property
    def plugin_id(self) -> str:
        return 'graphql_scanner'

    @property
    def name(self) -> str:
        return 'GraphQL Introspection Scanner'

    @property
    def description(self) -> str:
        return (
            'Detects exposed GraphQL endpoints with introspection enabled, '
            'which reveals the full API schema to unauthenticated attackers'
        )

    @property
    def version(self) -> str:
        return '1.0.0'

    @property
    def vulnerability_types(self) -> List[str]:
        return ['graphql']

    # ------------------------------------------------------------------
    # Public scan entry-point
    # ------------------------------------------------------------------

    def scan(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[VulnerabilityFinding]:
        """
        Scan for exposed GraphQL introspection.

        Args:
            url:    Target URL (base URL; GraphQL paths are appended automatically).
            config: Optional dict with keys:
                      verify_ssl      (bool, default False)
                      timeout         (int,  default 10)
                      extra_paths     (list) – additional GraphQL endpoint paths

        Returns:
            List of VulnerabilityFinding instances.
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available – skipping GraphQL scan")
            return []

        config = config or self.get_default_config()
        findings: List[VulnerabilityFinding] = []

        try:
            verify_ssl = config.get('verify_ssl', False)
            timeout = config.get('timeout', 10)
            extra_paths = config.get('extra_paths', [])

            from urllib.parse import urlparse
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            paths_to_test = list(_GRAPHQL_PATHS) + list(extra_paths)
            # Also test the target URL itself in case it IS the GraphQL endpoint
            paths_to_test.insert(0, parsed.path or '/')

            tested: set = set()
            for path in paths_to_test:
                endpoint_url = base + path
                if endpoint_url in tested:
                    continue
                tested.add(endpoint_url)

                finding = self._test_endpoint(endpoint_url, verify_ssl, timeout)
                if finding:
                    findings.append(finding)

        except Exception as exc:
            logger.error("Unexpected error during GraphQL scan of %s: %s", url, exc)

        logger.info("GraphQL scan of %s – %d finding(s)", url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _test_endpoint(
        self, endpoint_url: str, verify_ssl: bool, timeout: int
    ) -> Optional[VulnerabilityFinding]:
        """Send an introspection query to the endpoint and check the response."""
        try:
            response = requests.post(
                endpoint_url,
                json=_INTROSPECTION_QUERY,
                headers={'Content-Type': 'application/json'},
                timeout=timeout,
                verify=verify_ssl,
            )
        except Exception as exc:
            logger.debug("GraphQL probe failed for %s: %s", endpoint_url, exc)
            return None

        if response.status_code not in (200, 201):
            return None

        try:
            data = response.json()
        except Exception:
            return None

        # Introspection is enabled if the response contains __schema data
        if not isinstance(data, dict):
            return None

        schema_data = (
            data.get('data', {}) or {}
        ).get('__schema')

        if not schema_data:
            return None

        types_count = len(schema_data.get('types', []))
        query_type = (schema_data.get('queryType') or {}).get('name', 'unknown')
        mutation_type = (schema_data.get('mutationType') or {}).get('name')

        description = (
            f'GraphQL introspection is enabled at {endpoint_url}. '
            f'The full schema is exposed including {types_count} types. '
            f'Query root: "{query_type}"'
        )
        if mutation_type:
            description += f', Mutation root: "{mutation_type}"'
        description += '.'

        return VulnerabilityFinding(
            vulnerability_type='graphql',
            severity='medium',
            url=endpoint_url,
            description=description,
            evidence=(
                f'Endpoint: {endpoint_url} | '
                f'Introspection response status: {response.status_code} | '
                f'Types exposed: {types_count} | '
                f'Query type: {query_type} | '
                f'Mutation type: {mutation_type or "none"}'
            ),
            remediation=_REMEDIATION,
            confidence=0.95,
            cwe_id='CWE-200',
        )

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for GraphQL scanning."""
        return {
            'verify_ssl': False,
            'timeout': 10,
            'extra_paths': [],
        }
