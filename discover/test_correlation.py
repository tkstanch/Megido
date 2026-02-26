"""
Tests for the Correlation Engine.
"""
from django.test import TestCase

from discover.models import Scan, CorrelationLink
from discover.correlation import CorrelationEngine, Node, Edge


class TestNode(TestCase):

    def test_node_to_dict(self):
        node = Node('domain::example.com', 'domain', 'example.com', {'extra': 1})
        d = node.to_dict()
        self.assertEqual(d['id'], 'domain::example.com')
        self.assertEqual(d['type'], 'domain')
        self.assertEqual(d['label'], 'example.com')
        self.assertEqual(d['properties']['extra'], 1)
        self.assertEqual(d['risk_score'], 0)


class TestEdge(TestCase):

    def test_edge_to_dict(self):
        edge = Edge('source_id', 'target_id', 'dns_resolves_to', confidence=0.9)
        d = edge.to_dict()
        self.assertEqual(d['source'], 'source_id')
        self.assertEqual(d['target'], 'target_id')
        self.assertEqual(d['type'], 'dns_resolves_to')
        self.assertAlmostEqual(d['confidence'], 0.9)


class TestCorrelationEngine(TestCase):

    def setUp(self):
        self.scan = Scan.objects.create(target='example.com')

    def _make_engine_results(self, **overrides):
        results = {
            'dns': {
                'success': True,
                'data': {
                    'domain': 'example.com',
                    'records': {
                        'A': ['1.2.3.4', '5.6.7.8'],
                        'MX': ['mail.example.com'],
                        'NS': ['ns1.example.com'],
                    },
                },
            },
            'subdomains': {
                'success': True,
                'data': {
                    'subdomains': ['api.example.com', 'www.example.com', 'mail.example.com'],
                },
            },
            'certificates': {
                'success': True,
                'data': {
                    'certificates': [
                        {'san': ['example.com', 'www.example.com', '*.example.com']},
                    ],
                },
            },
            'email': {
                'success': True,
                'data': {
                    'emails': [
                        {'email': 'john.doe@example.com', 'first_name': 'John', 'last_name': 'Doe'},
                    ],
                },
            },
            'social_media': {
                'success': True,
                'data': {
                    'username_profiles': [
                        {'platform': 'GitHub', 'url': 'https://github.com/example', 'exists': True},
                    ],
                    'leaked_secrets': [],
                },
            },
            'cloud_enum': {
                'success': True,
                'data': {
                    's3_buckets': [
                        {'name': 'example-backup', 'url': 'https://example-backup.s3.amazonaws.com/', 'status': 'open'},
                    ],
                    'azure_blobs': [],
                    'gcp_buckets': [],
                    'firebase_dbs': [],
                },
            },
            'threat_intel': {
                'success': True,
                'data': {
                    'threat_score': 40,
                    'shodan_internetdb': [],
                },
            },
        }
        results.update(overrides)
        return results

    def test_build_graph_creates_nodes(self):
        engine = CorrelationEngine(self.scan)
        results = self._make_engine_results()
        engine.build_graph(results)

        # Root domain node
        self.assertIn('domain::example.com', engine.nodes)
        # IP addresses
        self.assertIn('ip::1.2.3.4', engine.nodes)
        self.assertIn('ip::5.6.7.8', engine.nodes)
        # Subdomains
        self.assertIn('subdomain::api.example.com', engine.nodes)
        # Email
        self.assertIn('email::john.doe@example.com', engine.nodes)
        # Social profile
        self.assertTrue(any('social_profile' in k for k in engine.nodes))
        # Cloud resource
        self.assertTrue(any('cloud_resource' in k for k in engine.nodes))

    def test_build_graph_creates_edges(self):
        engine = CorrelationEngine(self.scan)
        results = self._make_engine_results()
        engine.build_graph(results)
        self.assertGreater(len(engine.edges), 0)

    def test_no_duplicate_edges(self):
        engine = CorrelationEngine(self.scan)
        results = self._make_engine_results()
        engine.build_graph(results)
        edge_keys = [(e.source, e.target, e.edge_type) for e in engine.edges]
        self.assertEqual(len(edge_keys), len(set(edge_keys)), "Duplicate edges found")

    def test_to_cytoscape(self):
        engine = CorrelationEngine(self.scan)
        engine.build_graph(self._make_engine_results())
        cy = engine.to_cytoscape()
        self.assertIn('elements', cy)
        self.assertIsInstance(cy['elements'], list)

    def test_to_d3(self):
        engine = CorrelationEngine(self.scan)
        engine.build_graph(self._make_engine_results())
        d3 = engine.to_d3()
        self.assertIn('nodes', d3)
        self.assertIn('links', d3)
        self.assertGreater(len(d3['nodes']), 0)

    def test_to_stix(self):
        engine = CorrelationEngine(self.scan)
        engine.build_graph(self._make_engine_results())
        stix = engine.to_stix()
        self.assertEqual(stix['type'], 'bundle')
        self.assertEqual(stix['spec_version'], '2.1')
        # Should contain at least the root domain
        domain_objects = [o for o in stix['objects'] if o['type'] == 'domain-name']
        self.assertGreater(len(domain_objects), 0)

    def test_attack_surface_summary(self):
        engine = CorrelationEngine(self.scan)
        engine.build_graph(self._make_engine_results())
        summary = engine.get_attack_surface_summary()
        self.assertIn('total_entities', summary)
        self.assertIn('total_relationships', summary)
        self.assertIn('entities_by_type', summary)
        self.assertIn('high_risk_entities', summary)
        self.assertGreater(summary['total_entities'], 0)

    def test_open_cloud_resource_gets_high_risk_score(self):
        engine = CorrelationEngine(self.scan)
        engine.build_graph(self._make_engine_results())
        cloud_nodes = [n for n in engine.nodes.values() if n.entity_type == 'cloud_resource']
        open_nodes = [n for n in cloud_nodes if n.properties.get('status') == 'open']
        for node in open_nodes:
            self.assertGreaterEqual(node.risk_score, 70)

    def test_correlation_links_persisted_to_db(self):
        initial_count = CorrelationLink.objects.filter(scan=self.scan).count()
        engine = CorrelationEngine(self.scan)
        engine.build_graph(self._make_engine_results())
        final_count = CorrelationLink.objects.filter(scan=self.scan).count()
        self.assertGreater(final_count, initial_count)

    def test_empty_results_does_not_crash(self):
        engine = CorrelationEngine(self.scan)
        engine.build_graph({})
        self.assertIn('domain::example.com', engine.nodes)
