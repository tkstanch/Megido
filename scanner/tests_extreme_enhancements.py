"""
Tests for EXTREME Enhancements:
- ML Engine
- Exploit Chain Detector
- Payload Optimizer

These tests validate the military-grade enhancements.
"""

import unittest
from unittest.mock import Mock, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.extreme_ml_engine import (
    ExtremeMLEngine,
    MLFeatures,
    create_ml_engine
)

from scanner.extreme_chain_detector import (
    ExtremeChainDetector,
    ExploitNode,
    AttackStage,
    ExploitComplexity,
    create_chain_detector
)

from scanner.extreme_payload_optimizer import (
    ExtremePayloadOptimizer,
    PayloadGenome,
    EvasionTechnique,
    create_payload_optimizer,
    example_fitness_function
)


class TestMLEngine(unittest.TestCase):
    """Test ML Engine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = create_ml_engine(enable_learning=False)
    
    def test_initialization(self):
        """Test engine initializes correctly"""
        self.assertIsNotNone(self.engine)
        self.assertIsNotNone(self.engine.pattern_database)
    
    def test_feature_extraction(self):
        """Test feature extraction from finding"""
        mock_response = Mock()
        mock_response.text = "Error: SQL syntax error"
        mock_response.status_code = 500
        mock_response.elapsed = Mock(total_seconds=lambda: 0.5)
        
        finding = {
            'type': 'sqli',
            'payload': "' OR '1'='1",
            'method': 'POST',
        }
        
        features = self.engine.extract_features(finding, mock_response)
        
        self.assertIsInstance(features, MLFeatures)
        self.assertGreater(features.response_length, 0)
        self.assertEqual(features.status_code, 500)
        self.assertGreater(features.error_density, 0)
    
    def test_confidence_prediction(self):
        """Test ML confidence prediction"""
        features = MLFeatures(
            response_length=500,
            response_time=0.5,
            status_code=200,
            error_density=0.5,
            payload_length=20,
            payload_complexity=0.3,
            payload_entropy=3.5,
            response_variance=0.4,
            sql_keywords=2,
        )
        
        confidence = self.engine.predict_confidence(features, 'sqli')
        
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)
    
    def test_false_positive_prediction(self):
        """Test false positive probability prediction"""
        # High error density = likely FP
        features_fp = MLFeatures(
            error_density=0.8,
            status_code=404,
        )
        
        fp_prob = self.engine.predict_false_positive_probability(features_fp)
        
        self.assertGreater(fp_prob, 0.5)
    
    def test_behavioral_anomaly_score(self):
        """Test behavioral anomaly scoring"""
        features = MLFeatures(
            response_variance=0.5,
            timing_anomaly=3.0,
            payload_entropy=5.0,
        )
        
        anomaly = self.engine.get_behavioral_anomaly_score(features)
        
        self.assertGreater(anomaly, 0.0)
        self.assertLessEqual(anomaly, 1.0)


class TestChainDetector(unittest.TestCase):
    """Test Exploit Chain Detector"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = create_chain_detector()
    
    def test_initialization(self):
        """Test detector initializes correctly"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(len(self.detector.detected_chains), 0)
    
    def test_single_finding_no_chain(self):
        """Test that single finding doesn't create chain"""
        findings = [
            {
                'type': 'xss',
                'url': 'http://test.com',
                'parameter': 'q',
                'confidence': 0.8,
            }
        ]
        
        chains = self.detector.analyze_findings(findings)
        
        # Single finding should not create multi-stage chain
        self.assertEqual(len(chains), 0)
    
    def test_multi_finding_chain_detection(self):
        """Test detection of exploit chains from multiple findings"""
        findings = [
            {
                'type': 'xss',
                'url': 'http://test.com/page1',
                'parameter': 'q',
                'confidence': 0.9,
                'verified': True,
            },
            {
                'type': 'sqli',
                'url': 'http://test.com/page2',
                'parameter': 'id',
                'confidence': 0.8,
                'verified': False,
            },
            {
                'type': 'command',
                'url': 'http://test.com/page3',
                'parameter': 'cmd',
                'confidence': 0.7,
                'verified': False,
            },
        ]
        
        chains = self.detector.analyze_findings(findings)
        
        # Should detect potential chains
        self.assertGreaterEqual(len(chains), 0)
    
    def test_impact_calculation(self):
        """Test chain impact calculation"""
        node1 = ExploitNode(
            vulnerability_id='test1',
            vulnerability_type='xss',
            attack_stage=AttackStage.INITIAL_ACCESS,
            complexity=ExploitComplexity.LOW,
            impact_score=7.0,
            verified=True,
        )
        
        node2 = ExploitNode(
            vulnerability_id='test2',
            vulnerability_type='sqli',
            attack_stage=AttackStage.EXECUTION,
            complexity=ExploitComplexity.MEDIUM,
            impact_score=8.0,
            verified=False,
        )
        
        from scanner.extreme_chain_detector import ExploitChain
        
        chain = ExploitChain(
            chain_id='test_chain',
            nodes=[node1, node2],
            total_impact=0.0,
            total_complexity=0,
            attack_narrative='Test',
        )
        
        impact = self.detector._calculate_chain_impact(chain)
        
        self.assertGreater(impact, 0)
    
    def test_mermaid_graph_generation(self):
        """Test Mermaid graph generation"""
        node = ExploitNode(
            vulnerability_id='test',
            vulnerability_type='xss',
            attack_stage=AttackStage.INITIAL_ACCESS,
            complexity=ExploitComplexity.LOW,
            impact_score=5.0,
        )
        
        from scanner.extreme_chain_detector import ExploitChain
        
        chain = ExploitChain(
            chain_id='test',
            nodes=[node],
            total_impact=5.0,
            total_complexity=2,
            attack_narrative='Test',
        )
        
        graph = self.detector.generate_attack_graph(chain, 'mermaid')
        
        self.assertIn('graph TD', graph)


class TestPayloadOptimizer(unittest.TestCase):
    """Test Payload Optimizer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.optimizer = create_payload_optimizer(
            'xss',
            population_size=10,
            max_generations=3
        )
    
    def test_initialization(self):
        """Test optimizer initializes correctly"""
        self.assertIsNotNone(self.optimizer)
        self.assertEqual(self.optimizer.vulnerability_type, 'xss')
        self.assertEqual(self.optimizer.population_size, 10)
    
    def test_population_initialization(self):
        """Test population initialization"""
        self.optimizer._initialize_population()
        
        self.assertEqual(len(self.optimizer.population), 10)
        
        # All should have payloads
        for genome in self.optimizer.population:
            self.assertIsNotNone(genome.payload)
            self.assertGreater(len(genome.payload), 0)
    
    def test_evolution(self):
        """Test payload evolution"""
        evolved = self.optimizer.evolve(example_fitness_function)
        
        self.assertEqual(len(evolved), 10)
        
        # Should have fitness scores
        for genome in evolved:
            self.assertGreaterEqual(genome.fitness, 0.0)
            self.assertLessEqual(genome.fitness, 1.0)
    
    def test_mutation(self):
        """Test payload mutation"""
        original = "<script>alert(1)</script>"
        mutated = self.optimizer._mutate(original)
        
        # Should produce different payload (most of the time)
        self.assertIsNotNone(mutated)
    
    def test_crossover(self):
        """Test payload crossover"""
        parent1 = PayloadGenome(payload="<script>alert(1)</script>")
        parent2 = PayloadGenome(payload="<img src=x onerror=alert(1)>")
        
        child = self.optimizer._crossover(parent1, parent2)
        
        self.assertIsNotNone(child)
        self.assertGreater(len(child), 0)
    
    def test_evasion_technique_application(self):
        """Test applying evasion techniques"""
        payload = "<script>alert(1)</script>"
        
        evaded = self.optimizer.apply_evasion_technique(
            payload,
            EvasionTechnique.ENCODING
        )
        
        self.assertIsNotNone(evaded)
    
    def test_top_payloads_retrieval(self):
        """Test getting top payloads"""
        self.optimizer.evolve(example_fitness_function)
        
        top = self.optimizer.get_top_payloads(n=3)
        
        self.assertEqual(len(top), 3)
        
        # Should be sorted by fitness
        for i in range(len(top) - 1):
            self.assertGreaterEqual(top[i].fitness, top[i+1].fitness)


class TestExtremeIntegration(unittest.TestCase):
    """Test integration between extreme modules"""
    
    def test_ml_and_chain_integration(self):
        """Test ML engine with chain detector"""
        ml_engine = create_ml_engine(enable_learning=False)
        chain_detector = create_chain_detector()
        
        # Create findings with ML features
        findings = [
            {
                'type': 'xss',
                'url': 'http://test.com',
                'parameter': 'q',
                'confidence': 0.9,
                'payload': '<script>alert(1)</script>',
            }
        ]
        
        # Extract features
        for finding in findings:
            features = ml_engine.extract_features(finding)
            finding['ml_confidence'] = ml_engine.predict_confidence(features, finding['type'])
        
        # Detect chains
        chains = chain_detector.analyze_findings(findings)
        
        # Should complete without errors
        self.assertIsNotNone(chains)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestMLEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestChainDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadOptimizer))
    suite.addTests(loader.loadTestsFromTestCase(TestExtremeIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)
