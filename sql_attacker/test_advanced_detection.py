"""
Advanced Testing Framework for SQL Injection Detection

Includes:
- Realistic test datasets
- Mutation fuzzing
- Benchmark testing
- Evasion technique testing
"""

import unittest
import random
import string
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

# Import our new modules
from sql_attacker.semantic_analyzer import SemanticAnalyzer, SQLContext
from sql_attacker.taint_tracker import TaintTracker, TaintLevel, SanitizationType
from sql_attacker.ensemble_detector import EnsembleDetector, DetectionResult, DetectionMethod
from sql_attacker.real_impact_analyzer import RealImpactAnalyzer, DataSensitivity

logger = logging.getLogger(__name__)


@dataclass
class TestCase:
    """Test case for SQL injection detection"""
    input_value: str
    is_malicious: bool
    category: str
    description: str
    expected_severity: str = "unknown"


class SQLInjectionTestDataset:
    """
    Comprehensive test dataset for SQL injection detection.
    Includes both malicious and benign inputs.
    """
    
    # Malicious inputs - should be detected
    MALICIOUS_INPUTS = [
        TestCase("' OR '1'='1", True, "classic", "Classic OR injection", "high"),
        TestCase("admin'--", True, "comment", "Comment injection", "high"),
        TestCase("' UNION SELECT * FROM users--", True, "union", "UNION-based injection", "critical"),
        TestCase("'; DROP TABLE users--", True, "stacked", "Stacked query injection", "critical"),
        TestCase("1' AND SLEEP(5)--", True, "time-based", "Time-based blind injection", "high"),
        TestCase("1' AND 1=1--", True, "boolean", "Boolean-based blind injection", "medium"),
        TestCase("' OR 1=1/*", True, "comment", "Comment-based injection", "high"),
        TestCase("admin' OR 'x'='x", True, "classic", "Classic OR with comparison", "high"),
        TestCase("1' WAITFOR DELAY '00:00:05'--", True, "time-based", "MSSQL time delay", "high"),
        TestCase("' OR 'a'='a' --", True, "classic", "Classic with comment", "high"),
        # Advanced evasion
        TestCase("%27%20OR%20%271%27%3D%271", True, "evasion", "URL-encoded injection", "high"),
        TestCase("' OR '1'='1' %00", True, "evasion", "Null byte injection", "high"),
        TestCase("' /*!50000OR*/ '1'='1", True, "evasion", "Version comment evasion", "high"),
        TestCase("' OR 0x313d31--", True, "evasion", "Hex encoding", "high"),
        # Second-order injection
        TestCase("admin' -- later used in query", True, "second-order", "Second-order injection", "high"),
    ]
    
    # Benign inputs - should NOT be detected
    BENIGN_INPUTS = [
        TestCase("john@example.com", False, "email", "Valid email address"),
        TestCase("John O'Brien", False, "name", "Name with apostrophe"),
        TestCase("Product #123", False, "product", "Product ID with hash"),
        TestCase("Price: $99.99", False, "price", "Price with dollar sign"),
        TestCase("2023-01-15", False, "date", "ISO date format"),
        TestCase("Hello World", False, "text", "Simple text"),
        TestCase("123456", False, "numeric", "Pure numeric input"),
        TestCase("user_name_123", False, "identifier", "Valid identifier"),
        TestCase("https://example.com/page?id=1", False, "url", "Valid URL"),
        TestCase("SELECT * is a SQL keyword", False, "text", "Text mentioning SQL"),
    ]
    
    @classmethod
    def get_all_test_cases(cls) -> List[TestCase]:
        """Get all test cases"""
        return cls.MALICIOUS_INPUTS + cls.BENIGN_INPUTS
    
    @classmethod
    def get_malicious_only(cls) -> List[TestCase]:
        """Get only malicious test cases"""
        return cls.MALICIOUS_INPUTS
    
    @classmethod
    def get_benign_only(cls) -> List[TestCase]:
        """Get only benign test cases"""
        return cls.BENIGN_INPUTS


class MutationFuzzer:
    """
    Mutation-based fuzzer for SQL injection testing.
    Generates variations of known payloads.
    """
    
    def __init__(self):
        """Initialize fuzzer"""
        self.mutation_strategies = [
            self._insert_random_chars,
            self._case_variation,
            self._encoding_variation,
            self._whitespace_variation,
            self._comment_insertion,
            self._null_byte_insertion,
        ]
    
    def mutate(self, payload: str, num_mutations: int = 5) -> List[str]:
        """
        Generate mutated versions of a payload.
        
        Args:
            payload: Original payload
            num_mutations: Number of mutations to generate
            
        Returns:
            List of mutated payloads
        """
        mutations = []
        
        for _ in range(num_mutations):
            strategy = random.choice(self.mutation_strategies)
            mutated = strategy(payload)
            if mutated and mutated != payload:
                mutations.append(mutated)
        
        return list(set(mutations))  # Remove duplicates
    
    def _insert_random_chars(self, payload: str) -> str:
        """Insert random characters"""
        if not payload:
            return payload
        
        pos = random.randint(0, len(payload))
        char = random.choice([' ', '\t', '\n', '/**/'])
        return payload[:pos] + char + payload[pos:]
    
    def _case_variation(self, payload: str) -> str:
        """Vary case of SQL keywords"""
        variations = []
        for word in payload.split():
            if random.random() < 0.5:
                variations.append(word.upper())
            else:
                variations.append(word.lower())
        return ' '.join(variations)
    
    def _encoding_variation(self, payload: str) -> str:
        """Apply different encodings"""
        encoding_type = random.choice(['url', 'hex', 'unicode'])
        
        if encoding_type == 'url':
            import urllib.parse
            return urllib.parse.quote(payload)
        elif encoding_type == 'hex':
            # Convert some characters to hex
            result = ""
            for char in payload:
                if random.random() < 0.3:
                    result += f"0x{ord(char):02x}"
                else:
                    result += char
            return result
        else:
            # Unicode encoding
            return payload.encode('unicode_escape').decode('ascii')
    
    def _whitespace_variation(self, payload: str) -> str:
        """Vary whitespace"""
        variations = [' ', '\t', '\n', '/**/']
        result = ""
        for char in payload:
            if char == ' ':
                result += random.choice(variations)
            else:
                result += char
        return result
    
    def _comment_insertion(self, payload: str) -> str:
        """Insert comments"""
        comment_styles = ['/**/', '--', '#', '/*comment*/']
        words = payload.split()
        if len(words) > 1:
            pos = random.randint(1, len(words) - 1)
            words.insert(pos, random.choice(comment_styles))
        return ' '.join(words)
    
    def _null_byte_insertion(self, payload: str) -> str:
        """Insert null bytes"""
        if not payload:
            return payload
        pos = random.randint(0, len(payload))
        return payload[:pos] + '%00' + payload[pos:]


class BenchmarkTester:
    """
    Benchmark tester for comparing detection accuracy.
    Tests against industry standards.
    """
    
    def __init__(self):
        """Initialize benchmark tester"""
        self.results = {
            'true_positives': 0,
            'true_negatives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'total_tests': 0,
        }
    
    def run_benchmark(self, detector_func) -> Dict[str, Any]:
        """
        Run benchmark tests.
        
        Args:
            detector_func: Function that takes input and returns (is_malicious: bool, confidence: float)
            
        Returns:
            Benchmark results
        """
        test_cases = SQLInjectionTestDataset.get_all_test_cases()
        
        for test_case in test_cases:
            try:
                is_malicious, confidence = detector_func(test_case.input_value)
                
                if is_malicious and test_case.is_malicious:
                    self.results['true_positives'] += 1
                elif not is_malicious and not test_case.is_malicious:
                    self.results['true_negatives'] += 1
                elif is_malicious and not test_case.is_malicious:
                    self.results['false_positives'] += 1
                else:
                    self.results['false_negatives'] += 1
                
                self.results['total_tests'] += 1
                
            except Exception as e:
                logger.error(f"Error testing {test_case.input_value}: {e}")
        
        return self.calculate_metrics()
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate accuracy metrics"""
        tp = self.results['true_positives']
        tn = self.results['true_negatives']
        fp = self.results['false_positives']
        fn = self.results['false_negatives']
        total = self.results['total_tests']
        
        metrics = {
            'accuracy': (tp + tn) / total if total > 0 else 0.0,
            'precision': tp / (tp + fp) if (tp + fp) > 0 else 0.0,
            'recall': tp / (tp + fn) if (tp + fn) > 0 else 0.0,
            'specificity': tn / (tn + fp) if (tn + fp) > 0 else 0.0,
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn,
            'total_tests': total,
        }
        
        # Calculate F1 score
        if metrics['precision'] + metrics['recall'] > 0:
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / (metrics['precision'] + metrics['recall'])
        else:
            metrics['f1_score'] = 0.0
        
        return metrics


class AdvancedSQLInjectionTests(unittest.TestCase):
    """
    Comprehensive unit tests for advanced SQL injection detection.
    """
    
    def setUp(self):
        """Set up test fixtures"""
        self.semantic_analyzer = SemanticAnalyzer()
        self.taint_tracker = TaintTracker()
        self.ensemble_detector = EnsembleDetector()
        self.impact_analyzer = RealImpactAnalyzer()
    
    def test_semantic_analyzer_malicious(self):
        """Test semantic analyzer with malicious inputs"""
        for test_case in SQLInjectionTestDataset.get_malicious_only():
            result = self.semantic_analyzer.analyze_input(test_case.input_value)
            self.assertTrue(
                result['is_suspicious'],
                f"Failed to detect: {test_case.description}"
            )
            self.assertGreater(
                result['risk_score'], 0.3,
                f"Risk score too low for: {test_case.description}"
            )
    
    def test_semantic_analyzer_benign(self):
        """Test semantic analyzer with benign inputs"""
        false_positives = 0
        for test_case in SQLInjectionTestDataset.get_benign_only():
            result = self.semantic_analyzer.analyze_input(test_case.input_value)
            if result['is_suspicious']:
                false_positives += 1
        
        # Allow max 20% false positive rate
        max_false_positives = len(SQLInjectionTestDataset.get_benign_only()) * 0.2
        self.assertLessEqual(
            false_positives, max_false_positives,
            f"Too many false positives: {false_positives}"
        )
    
    def test_taint_tracker_flow(self):
        """Test taint tracking data flow"""
        # Mark data as tainted
        tainted = self.taint_tracker.mark_tainted('user_input', "' OR 1=1--", 'GET')
        self.assertEqual(tainted.taint_level, TaintLevel.TAINTED)
        
        # Track flow
        self.taint_tracker.track_flow('user_input', 'query_param', 'assignment')
        
        # Check sink
        vuln = self.taint_tracker.check_sink('query_param', 'cursor.execute')
        self.assertIsNotNone(vuln)
        self.assertTrue(vuln['is_vulnerable'])
        self.assertGreater(vuln['risk_score'], 0.5)
    
    def test_taint_tracker_sanitization(self):
        """Test taint tracking with sanitization"""
        # Mark as tainted
        self.taint_tracker.mark_tainted('user_input', "' OR 1=1--", 'POST')
        
        # Apply sanitization
        self.taint_tracker.apply_sanitization('user_input', 'mysql_real_escape_string')
        
        # Check sink - should have lower risk
        vuln = self.taint_tracker.check_sink('user_input', 'query')
        self.assertIsNotNone(vuln)
        self.assertLess(vuln['risk_score'], 0.5)  # Risk reduced after sanitization
    
    def test_ensemble_detector_voting(self):
        """Test ensemble detector with multiple methods"""
        # Add detection results
        self.ensemble_detector.add_detection_result(
            DetectionResult(
                method=DetectionMethod.PATTERN_BASED,
                is_vulnerable=True,
                confidence=0.8,
                details={'pattern': 'OR injection'},
                evidence=['Pattern matched: OR']
            )
        )
        
        self.ensemble_detector.add_detection_result(
            DetectionResult(
                method=DetectionMethod.SEMANTIC_ANALYSIS,
                is_vulnerable=True,
                confidence=0.9,
                details={'risk_score': 0.85},
                evidence=['High risk score']
            )
        )
        
        self.ensemble_detector.add_detection_result(
            DetectionResult(
                method=DetectionMethod.TAINT_TRACKING,
                is_vulnerable=True,
                confidence=0.75,
                details={'tainted': True},
                evidence=['Tainted data flow']
            )
        )
        
        # Evaluate
        result = self.ensemble_detector.evaluate()
        self.assertTrue(result['is_vulnerable'])
        self.assertGreaterEqual(result['confidence'], 0.7)
        self.assertEqual(result['method_count'], 3)
    
    def test_impact_analyzer_workflow(self):
        """Test complete impact analysis workflow"""
        # Start analysis
        vuln_id = self.impact_analyzer.start_analysis(
            'http://example.com/page?id=1',
            'id',
            'union-based'
        )
        self.assertIsNotNone(vuln_id)
        self.assertTrue(vuln_id.startswith('SQLI-'))
        
        # Record data extraction
        self.impact_analyzer.record_data_extraction(
            'users',
            [
                {'id': '1', 'username': 'admin', 'email': 'admin@example.com'},
                {'id': '2', 'username': 'user', 'email': 'user@example.com'}
            ],
            ['id', 'username', 'email']
        )
        
        # Record schema
        self.impact_analyzer.record_schema_discovery(
            ['users', 'products', 'orders'],
            {'users': ['id', 'username', 'email'], 'products': ['id', 'name']}
        )
        
        # Finalize
        evidence = self.impact_analyzer.finalize_analysis('high', 0.85)
        
        self.assertEqual(evidence.total_rows_extracted, 2)
        self.assertTrue(evidence.sensitive_data_found)
        self.assertEqual(len(evidence.tables_discovered), 3)
        self.assertGreater(evidence.risk_score, 0)
    
    def test_mutation_fuzzing(self):
        """Test mutation fuzzer"""
        fuzzer = MutationFuzzer()
        original = "' OR '1'='1"
        
        mutations = fuzzer.mutate(original, num_mutations=10)
        self.assertGreater(len(mutations), 0)
        self.assertLessEqual(len(mutations), 10)
        
        # All mutations should be different from original
        for mutation in mutations:
            self.assertNotEqual(mutation, original)
    
    def test_benchmark_framework(self):
        """Test benchmark framework"""
        benchmark = BenchmarkTester()
        
        # Simple detector function for testing
        def simple_detector(input_value: str) -> Tuple[bool, float]:
            analyzer = SemanticAnalyzer()
            result = analyzer.analyze_input(input_value)
            return result['is_suspicious'], result['confidence']
        
        metrics = benchmark.run_benchmark(simple_detector)
        
        self.assertGreater(metrics['accuracy'], 0.5)  # At least 50% accuracy
        self.assertGreater(metrics['total_tests'], 0)


def run_comprehensive_tests():
    """Run all comprehensive tests"""
    suite = unittest.TestLoader().loadTestsFromTestCase(AdvancedSQLInjectionTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    # Run tests
    logging.basicConfig(level=logging.INFO)
    success = run_comprehensive_tests()
    exit(0 if success else 1)
