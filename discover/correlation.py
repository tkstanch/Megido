"""
Intelligence Correlation Engine

Links all discovered entities across OSINT engine results:
  - Domain → IP → Subdomain → Port → Service
  - Email → Social profile
  - Certificate SAN → Subdomain
  - IP → Cloud resource
  - Any entity → Threat intel indicator

Builds a graph and provides:
  - Entity risk-score calculation
  - D3.js / Cytoscape.js compatible JSON export
  - Maltego MTGX stub export
  - STIX 2.1 bundle export
  - Attack surface summary
"""
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    CorrelationLink,
    Scan,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Node / Edge data classes
# ---------------------------------------------------------------------------

class Node:
    """A node in the correlation graph."""
    def __init__(self, node_id: str, entity_type: str, label: str, properties: Optional[Dict] = None):
        self.id = node_id
        self.entity_type = entity_type
        self.label = label
        self.properties = properties or {}
        self.risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.entity_type,
            'label': self.label,
            'risk_score': self.risk_score,
            'properties': self.properties,
        }


class Edge:
    """A directed edge between two nodes."""
    def __init__(self, source: str, target: str, edge_type: str, confidence: float = 1.0):
        self.source = source
        self.target = target
        self.edge_type = edge_type
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'target': self.target,
            'type': self.edge_type,
            'confidence': self.confidence,
        }


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Builds an entity relationship graph from aggregated OSINT engine results.
    """

    def __init__(self, scan: Scan):
        self.scan = scan
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._seen_edges: Set[Tuple[str, str, str]] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_graph(self, engine_results: Dict[str, Any]) -> 'CorrelationEngine':
        """
        Ingest aggregated engine results and build the correlation graph.

        Args:
            engine_results: Output of ``ScanOrchestrator.run()``, i.e.
                ``{engine_name: result_dict}`` mapping.

        Returns:
            self (fluent interface)
        """
        target = self.scan.target
        root_id = self._node_id('domain', target)
        self._add_node(root_id, 'domain', target)

        # DNS
        dns_data = engine_results.get('dns', {}).get('data', {})
        self._ingest_dns(root_id, dns_data)

        # Subdomains
        sub_data = engine_results.get('subdomains', {}).get('data', {})
        self._ingest_subdomains(root_id, sub_data)

        # Certificates
        cert_data = engine_results.get('certificates', {}).get('data', {})
        self._ingest_certificates(root_id, cert_data)

        # Email
        email_data = engine_results.get('email', {}).get('data', {})
        self._ingest_emails(root_id, email_data)

        # Social media
        social_data = engine_results.get('social_media', {}).get('data', {})
        self._ingest_social(root_id, social_data)

        # Cloud
        cloud_data = engine_results.get('cloud_enum', {}).get('data', {})
        self._ingest_cloud(root_id, cloud_data)

        # Threat intel
        threat_data = engine_results.get('threat_intel', {}).get('data', {})
        self._ingest_threat_intel(root_id, threat_data)

        # Compute risk scores
        self._compute_risk_scores(engine_results)

        # Persist to DB
        self._persist_links()

        return self

    def to_cytoscape(self) -> Dict[str, Any]:
        """Export graph as Cytoscape.js compatible JSON."""
        elements = []
        for node in self.nodes.values():
            elements.append({'data': node.to_dict()})
        for edge in self.edges:
            elements.append({'data': edge.to_dict()})
        return {'elements': elements}

    def to_d3(self) -> Dict[str, Any]:
        """Export graph as D3.js force-directed graph JSON."""
        return {
            'nodes': [n.to_dict() for n in self.nodes.values()],
            'links': [e.to_dict() for e in self.edges],
        }

    def to_stix(self) -> Dict[str, Any]:
        """Export a minimal STIX 2.1 bundle containing domain and IP indicators."""
        objects = []
        bundle_id = f'bundle--{self.scan.pk}'

        for node in self.nodes.values():
            if node.entity_type == 'domain':
                objects.append({
                    'type': 'domain-name',
                    'id': f'domain-name--{abs(hash(node.label)) % 10**18}',
                    'spec_version': '2.1',
                    'value': node.label,
                })
            elif node.entity_type == 'ip':
                objects.append({
                    'type': 'ipv4-addr',
                    'id': f'ipv4-addr--{abs(hash(node.label)) % 10**18}',
                    'spec_version': '2.1',
                    'value': node.label,
                })

        return {
            'type': 'bundle',
            'id': bundle_id,
            'spec_version': '2.1',
            'objects': objects,
        }

    def get_attack_surface_summary(self) -> Dict[str, Any]:
        """Return a summary of the discovered attack surface."""
        by_type: Dict[str, List[str]] = {}
        for node in self.nodes.values():
            by_type.setdefault(node.entity_type, []).append(node.label)

        high_risk_nodes = [n.to_dict() for n in self.nodes.values() if n.risk_score >= 70]
        high_risk_nodes.sort(key=lambda x: x['risk_score'], reverse=True)

        return {
            'total_entities': len(self.nodes),
            'total_relationships': len(self.edges),
            'entities_by_type': {k: len(v) for k, v in by_type.items()},
            'high_risk_entities': high_risk_nodes[:10],
        }

    # ------------------------------------------------------------------
    # Ingestion helpers
    # ------------------------------------------------------------------

    def _ingest_dns(self, root_id: str, data: Dict[str, Any]) -> None:
        for rtype, values in data.get('records', {}).items():
            for value in values:
                if rtype in ('A', 'AAAA'):
                    ip_id = self._node_id('ip', value)
                    self._add_node(ip_id, 'ip', value)
                    self._add_edge(root_id, ip_id, 'dns_resolves_to')
                elif rtype == 'MX':
                    mx_id = self._node_id('mail_server', value)
                    self._add_node(mx_id, 'mail_server', value)
                    self._add_edge(root_id, mx_id, 'mx_record')
                elif rtype == 'NS':
                    ns_id = self._node_id('nameserver', value)
                    self._add_node(ns_id, 'nameserver', value)
                    self._add_edge(root_id, ns_id, 'ns_record')

    def _ingest_subdomains(self, root_id: str, data: Dict[str, Any]) -> None:
        for subdomain in data.get('subdomains', []):
            sub_id = self._node_id('subdomain', subdomain)
            self._add_node(sub_id, 'subdomain', subdomain)
            self._add_edge(root_id, sub_id, 'has_subdomain')

    def _ingest_certificates(self, root_id: str, data: Dict[str, Any]) -> None:
        for cert in data.get('certificates', []):
            for san in cert.get('san', []):
                san_clean = san.lstrip('*.')
                san_id = self._node_id('san', san_clean)
                self._add_node(san_id, 'san', san_clean, {'source': 'certificate'})
                self._add_edge(root_id, san_id, 'cert_san')

    def _ingest_emails(self, root_id: str, data: Dict[str, Any]) -> None:
        for email_entry in data.get('emails', []):
            if isinstance(email_entry, dict):
                addr = email_entry.get('email', '')
                props = {k: v for k, v in email_entry.items() if k != 'email'}
            else:
                addr = str(email_entry)
                props = {}
            if addr:
                email_id = self._node_id('email', addr)
                self._add_node(email_id, 'email', addr, props)
                self._add_edge(root_id, email_id, 'has_email')

    def _ingest_social(self, root_id: str, data: Dict[str, Any]) -> None:
        for profile in data.get('username_profiles', []):
            url = profile.get('url', '')
            platform = profile.get('platform', 'unknown')
            profile_id = self._node_id('social_profile', url)
            self._add_node(profile_id, 'social_profile', url, {'platform': platform})
            self._add_edge(root_id, profile_id, 'has_social_profile')

        for secret in data.get('leaked_secrets', []):
            secret_id = self._node_id('leaked_secret', f"{secret.get('repo', '')}/{secret.get('file', '')}")
            self._add_node(secret_id, 'leaked_secret', secret_id, secret)
            self._add_edge(root_id, secret_id, 'has_leaked_secret')

    def _ingest_cloud(self, root_id: str, data: Dict[str, Any]) -> None:
        for resource_type in ('s3_buckets', 'azure_blobs', 'gcp_buckets', 'firebase_dbs'):
            for resource in data.get(resource_type, []):
                url = resource.get('url', resource.get('name', ''))
                res_id = self._node_id('cloud_resource', url)
                self._add_node(res_id, 'cloud_resource', url, {
                    'type': resource_type,
                    'status': resource.get('status'),
                })
                self._add_edge(root_id, res_id, 'has_cloud_resource')

    def _ingest_threat_intel(self, root_id: str, data: Dict[str, Any]) -> None:
        threat_score = data.get('threat_score', 0)
        if threat_score > 0:
            threat_id = self._node_id('threat_indicator', self.scan.target)
            self._add_node(threat_id, 'threat_indicator', self.scan.target, {
                'threat_score': threat_score,
            })
            self._add_edge(root_id, threat_id, 'has_threat_indicator')
            self.nodes[root_id].risk_score = max(self.nodes[root_id].risk_score, threat_score)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _compute_risk_scores(self, engine_results: Dict[str, Any]) -> None:
        threat_score = (
            engine_results
            .get('threat_intel', {})
            .get('data', {})
            .get('threat_score', 0)
        )
        for node in self.nodes.values():
            if node.entity_type == 'leaked_secret':
                node.risk_score = 90
            elif node.entity_type == 'cloud_resource':
                status = node.properties.get('status', '')
                node.risk_score = 80 if status == 'open' else 40
            elif node.entity_type == 'threat_indicator':
                node.risk_score = threat_score
            else:
                node.risk_score = max(node.risk_score, threat_score // 2)

    # ------------------------------------------------------------------
    # DB persistence
    # ------------------------------------------------------------------

    def _persist_links(self) -> None:
        links_to_create = []
        for edge in self.edges:
            source_node = self.nodes.get(edge.source)
            target_node = self.nodes.get(edge.target)
            if not source_node or not target_node:
                continue
            links_to_create.append(CorrelationLink(
                scan=self.scan,
                link_type='other',
                source_entity=source_node.label,
                source_type=source_node.entity_type,
                target_entity=target_node.label,
                target_type=target_node.entity_type,
                confidence=edge.confidence,
            ))
        try:
            CorrelationLink.objects.bulk_create(
                links_to_create, ignore_conflicts=True, batch_size=500
            )
        except Exception as exc:
            logger.warning("Could not persist correlation links: %s", exc)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _node_id(entity_type: str, value: str) -> str:
        return f'{entity_type}::{value}'

    def _add_node(
        self,
        node_id: str,
        entity_type: str,
        label: str,
        properties: Optional[Dict] = None,
    ) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = Node(node_id, entity_type, label, properties)

    def _add_edge(self, source: str, target: str, edge_type: str, confidence: float = 1.0) -> None:
        key = (source, target, edge_type)
        if key not in self._seen_edges:
            self._seen_edges.add(key)
            self.edges.append(Edge(source, target, edge_type, confidence))
