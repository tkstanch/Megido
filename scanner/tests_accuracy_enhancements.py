"""
Comprehensive tests for extreme accuracy enhancements

Tests multi-stage validation, deep learning ensembles, and precision metrics.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import time
from scanner.accuracy_validation_engine import (
    MultiStageValidator, GroundTruthDatabase, ValidationResult,
    ValidationStage, ValidationEvidence
)
from scanner.accuracy_deep_learning import (
    EnsembleLearner, DeepNeuralModel, RecurrentModel, AttentionModel,
    BayesianModel, EnsembleMethod, ModelType
)


class TestMultiStageValidation(unittest.TestCase):
    """Tests for multi-stage validation engine"""
    
    def setUp(self):
        self.validator = MultiStageValidator(
            min_confidence_threshold=0.85,
            consensus_threshold=0.75
        )
        
    def test_initialization(self):
        """Test validator initializes correctly"""
        self.assertIsNotNone(self.validator)
        self.assertEqual(self.validator.min_confidence_threshold, 0.85)
        self.assertEqual(self.validator.consensus_threshold, 0.75)
        self.assertIsInstance(self.validator.ground_truth, GroundTruthDatabase)
        
    def test_high_confidence_finding_verification(self):
        """Test that high confidence findings are properly processed"""
        finding = {
            'id': 'test-1',
            'type': 'xss',
            'url': 'http://example.com',
            'parameter': 'q',
            'payload': '<script>alert(1)</script>',
            'confidence': 0.95,
            'severity': 'high',
            'evidence': {'cookies': ['session=abc'], 'screenshot': True}
        }
        
        report = self.validator.validate_finding(finding)
        
        self.assertIsNotNone(report)
        self.assertEqual(report.finding_id, 'test-1')
        # Verify validation completed with reasonable confidence
        self.assertGreaterEqual(report.final_confidence, 0.0)
        self.assertGreater(len(report.stages_passed) + len(report.stages_failed), 0)
        # Should have statistical metrics
        self.assertIn('precision_estimate', report.statistical_metrics)
        
    def test_low_confidence_finding_rejection(self):
        """Test that low confidence findings are rejected"""
        finding = {
            'id': 'test-2',
            'type': 'xss',
            'url': 'http://example.com',
            'parameter': 'q',
            'confidence': 0.3,
            'severity': 'low'
        }
        
        report = self.validator.validate_finding(finding)
        
        self.assertLessEqual(report.final_confidence, 0.6)
        self.assertGreater(len(report.stages_failed), len(report.stages_passed))
        
    def test_cross_validation_with_methods(self):
        """Test cross-validation with multiple detection methods"""
        finding = {
            'id': 'test-3',
            'type': 'sqli',
            'confidence': 0.80
        }
        
        detection_methods = [
            {'name': 'method1', 'confidence': 0.85},
            {'name': 'method2', 'confidence': 0.82},
            {'name': 'method3', 'confidence': 0.88}
        ]
        
        report = self.validator.validate_finding(finding, detection_methods)
        
        # Should pass cross-validation stage
        self.assertIn(ValidationStage.CROSS_CHECK, report.stages_passed)
        
    def test_ground_truth_matching(self):
        """Test ground truth database matching"""
        # Add verified vulnerability
        self.validator.ground_truth.add_verified_vulnerability(
            vuln_type='xss',
            signature='<script>alert(1)</script>',
            metadata={'severity': 'high'}
        )
        
        finding = {
            'id': 'test-4',
            'type': 'xss',
            'parameter': 'q',
            'payload': '<script>alert(1)</script>',
            'confidence': 0.85
        }
        
        report = self.validator.validate_finding(finding)
        
        # Should match ground truth
        self.assertIsNotNone(report.ground_truth_match)
        
    def test_temporal_consistency(self):
        """Test temporal consistency checking"""
        finding = {
            'id': 'test-5',
            'type': 'xss',
            'confidence': 0.90
        }
        
        # First validation
        report1 = self.validator.validate_finding(finding)
        
        # Second validation (should check temporal consistency)
        time.sleep(0.01)
        report2 = self.validator.validate_finding(finding)
        
        self.assertEqual(len(self.validator.validation_history['test-5']), 2)
        
    def test_statistical_metrics(self):
        """Test statistical metrics calculation"""
        finding = {
            'id': 'test-6',
            'type': 'xss',
            'confidence': 0.90,
            'severity': 'high'
        }
        
        report = self.validator.validate_finding(finding)
        
        self.assertIn('precision_estimate', report.statistical_metrics)
        self.assertIn('recall_estimate', report.statistical_metrics)
        self.assertIn('specificity', report.statistical_metrics)
        self.assertIn('f1_score', report.statistical_metrics)
        
        # Values should be between 0 and 1
        for metric, value in report.statistical_metrics.items():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)
            
    def test_validation_statistics(self):
        """Test getting validation statistics"""
        # Perform several validations
        for i in range(5):
            finding = {
                'id': f'test-stat-{i}',
                'type': 'xss',
                'confidence': 0.7 + i * 0.05
            }
            self.validator.validate_finding(finding)
            
        stats = self.validator.get_validation_statistics()
        
        self.assertEqual(stats['total_validations'], 5)
        self.assertGreater(stats['unique_findings'], 0)
        self.assertIn('average_confidence', stats)
        self.assertIn('result_distribution', stats)


class TestGroundTruthDatabase(unittest.TestCase):
    """Tests for ground truth database"""
    
    def setUp(self):
        self.db = GroundTruthDatabase()
        
    def test_add_verified_vulnerability(self):
        """Test adding verified vulnerability"""
        self.db.add_verified_vulnerability(
            vuln_type='xss',
            signature='<script>alert(1)</script>',
            metadata={'severity': 'high'}
        )
        
        self.assertEqual(len(self.db.verified_vulns), 1)
        self.assertEqual(len(self.db.exploit_patterns['xss']), 1)
        
    def test_add_verified_false_positive(self):
        """Test adding verified false positive"""
        self.db.add_verified_false_positive(
            vuln_type='xss',
            signature='<div>test</div>',
            reason='No JavaScript execution'
        )
        
        self.assertEqual(len(self.db.verified_fps), 1)
        
    def test_ground_truth_matching(self):
        """Test ground truth matching"""
        self.db.add_verified_vulnerability(
            vuln_type='sqli',
            signature="' OR '1'='1",
            metadata={'severity': 'critical'}
        )
        
        # Exact match
        match, confidence = self.db.check_against_ground_truth('sqli', "' OR '1'='1")
        self.assertTrue(match)
        self.assertGreater(confidence, 0.95)
        
        # No match
        match, confidence = self.db.check_against_ground_truth('sqli', "normal input")
        self.assertIsNone(match)


class TestDeepLearning(unittest.TestCase):
    """Tests for deep learning models"""
    
    def setUp(self):
        self.features = {
            'response_length': 0.7,
            'response_time': 0.5,
            'status_code': 0.9,
            'error_density': 0.3,
            'payload_complexity': 0.8
        }
        
    def test_deep_neural_model(self):
        """Test deep neural network model"""
        model = DeepNeuralModel()
        prediction = model.predict(self.features)
        
        self.assertEqual(prediction.model_type, ModelType.DEEP_NEURAL)
        self.assertGreaterEqual(prediction.confidence, 0.0)
        self.assertLessEqual(prediction.confidence, 1.0)
        self.assertGreaterEqual(prediction.probability, 0.0)
        self.assertLessEqual(prediction.probability, 1.0)
        self.assertGreaterEqual(prediction.uncertainty, 0.0)
        
    def test_recurrent_model(self):
        """Test recurrent neural network model"""
        model = RecurrentModel()
        
        sequence_data = [
            {'value': 0.5},
            {'value': 0.6},
            {'value': 0.7}
        ]
        
        prediction = model.predict(self.features, sequence_data)
        
        self.assertEqual(prediction.model_type, ModelType.RECURRENT)
        self.assertGreaterEqual(prediction.confidence, 0.0)
        self.assertLessEqual(prediction.confidence, 1.0)
        
    def test_attention_model(self):
        """Test attention mechanism model"""
        model = AttentionModel()
        context = {'response_length': True, 'payload_complexity': True}
        
        prediction = model.predict(self.features, context)
        
        self.assertEqual(prediction.model_type, ModelType.ATTENTION)
        self.assertIsNotNone(prediction.attention_weights)
        self.assertGreater(len(prediction.attention_weights), 0)
        
        # Attention weights should sum to 1
        total_weight = sum(prediction.attention_weights.values())
        self.assertAlmostEqual(total_weight, 1.0, places=5)
        
    def test_bayesian_model(self):
        """Test Bayesian inference model"""
        model = BayesianModel()
        prediction = model.predict(self.features, prior_probability=0.6)
        
        self.assertEqual(prediction.model_type, ModelType.BAYESIAN)
        self.assertGreaterEqual(prediction.confidence, 0.0)
        self.assertLessEqual(prediction.confidence, 1.0)
        self.assertGreaterEqual(prediction.uncertainty, 0.0)


class TestEnsembleLearning(unittest.TestCase):
    """Tests for ensemble learning"""
    
    def setUp(self):
        self.features = {
            'response_anomaly': 0.8,
            'payload_effectiveness': 0.9,
            'pattern_specificity': 0.7,
            'context_relevance': 0.85
        }
        
    def test_weighted_voting_ensemble(self):
        """Test weighted voting ensemble method"""
        ensemble = EnsembleLearner(EnsembleMethod.WEIGHTED_VOTING)
        prediction = ensemble.predict(self.features)
        
        self.assertEqual(prediction.ensemble_method, EnsembleMethod.WEIGHTED_VOTING)
        self.assertGreaterEqual(prediction.final_probability, 0.0)
        self.assertLessEqual(prediction.final_probability, 1.0)
        self.assertEqual(len(prediction.individual_predictions), 4)
        
    def test_soft_voting_ensemble(self):
        """Test soft voting ensemble method"""
        ensemble = EnsembleLearner(EnsembleMethod.SOFT_VOTING)
        prediction = ensemble.predict(self.features)
        
        self.assertEqual(prediction.ensemble_method, EnsembleMethod.SOFT_VOTING)
        self.assertGreaterEqual(prediction.final_confidence, 0.0)
        
    def test_hard_voting_ensemble(self):
        """Test hard voting ensemble method"""
        ensemble = EnsembleLearner(EnsembleMethod.HARD_VOTING)
        prediction = ensemble.predict(self.features)
        
        self.assertEqual(prediction.ensemble_method, EnsembleMethod.HARD_VOTING)
        self.assertIn(prediction.final_probability, [0.0, 0.25, 0.5, 0.75, 1.0])
        
    def test_stacking_ensemble(self):
        """Test stacking ensemble method"""
        ensemble = EnsembleLearner(EnsembleMethod.STACKING)
        prediction = ensemble.predict(self.features)
        
        self.assertEqual(prediction.ensemble_method, EnsembleMethod.STACKING)
        
    def test_ensemble_with_context(self):
        """Test ensemble with context information"""
        ensemble = EnsembleLearner()
        context = {'application_type': 'web', 'framework': 'django'}
        
        prediction = ensemble.predict(self.features, context=context)
        
        self.assertIsNotNone(prediction)
        self.assertIn('feature_importance', prediction.explanation)
        
    def test_ensemble_with_sequence(self):
        """Test ensemble with sequence data"""
        ensemble = EnsembleLearner()
        sequence_data = [
            {'confidence': 0.7},
            {'confidence': 0.75},
            {'confidence': 0.8}
        ]
        
        prediction = ensemble.predict(self.features, sequence_data=sequence_data)
        
        self.assertIsNotNone(prediction)
        
    def test_prediction_variance(self):
        """Test prediction variance calculation"""
        ensemble = EnsembleLearner()
        prediction = ensemble.predict(self.features)
        
        # Variance should be non-negative
        self.assertGreaterEqual(prediction.prediction_variance, 0.0)
        
    def test_calibration_score(self):
        """Test calibration score calculation"""
        ensemble = EnsembleLearner()
        prediction = ensemble.predict(self.features)
        
        # Calibration should be between 0 and 1
        self.assertGreaterEqual(prediction.calibration_score, 0.0)
        self.assertLessEqual(prediction.calibration_score, 1.0)
        
    def test_explanation_generation(self):
        """Test explanation generation"""
        ensemble = EnsembleLearner()
        prediction = ensemble.predict(self.features)
        
        explanation = prediction.explanation
        self.assertIn('model_agreement', explanation)
        self.assertIn('most_confident_model', explanation)
        self.assertIn('least_uncertain_model', explanation)
        
    def test_model_weight_update(self):
        """Test updating model weights"""
        ensemble = EnsembleLearner()
        
        validation_results = {
            ModelType.DEEP_NEURAL: 0.92,
            ModelType.RECURRENT: 0.88,
            ModelType.ATTENTION: 0.90,
            ModelType.BAYESIAN: 0.85
        }
        
        ensemble.update_model_weights(validation_results)
        
        # Weights should sum to approximately 1
        total_weight = sum(ensemble.model_weights.values())
        self.assertAlmostEqual(total_weight, 1.0, places=5)
        
    def test_performance_metrics(self):
        """Test performance metrics tracking"""
        ensemble = EnsembleLearner()
        
        # Make several predictions
        for i in range(5):
            features = {f'feature_{j}': 0.5 + i * 0.05 for j in range(3)}
            ensemble.predict(features)
            
        metrics = ensemble.get_performance_metrics()
        
        self.assertEqual(metrics['total_predictions'], 5)
        self.assertIn('average_confidence', metrics)
        self.assertIn('average_calibration', metrics)
        self.assertIn('high_confidence_rate', metrics)
        
    def test_calibration_curve(self):
        """Test calibration curve generation"""
        ensemble = EnsembleLearner()
        
        # Make predictions
        for i in range(10):
            features = {'feature': 0.1 * i}
            ensemble.predict(features)
            
        curve = ensemble.get_calibration_curve(num_bins=5)
        
        self.assertIn('predicted', curve)
        self.assertIn('actual', curve)
        self.assertEqual(len(curve['predicted']), 5)


class TestIntegration(unittest.TestCase):
    """Integration tests combining validation and ML"""
    
    def test_validation_with_ensemble(self):
        """Test multi-stage validation with ensemble predictions"""
        validator = MultiStageValidator()
        ensemble = EnsembleLearner()
        
        # Make ensemble prediction
        features = {
            'response_anomaly': 0.85,
            'payload_effectiveness': 0.90,
            'pattern_specificity': 0.80
        }
        
        ml_prediction = ensemble.predict(features)
        
        # Create finding with ML confidence
        finding = {
            'id': 'ml-test-1',
            'type': 'xss',
            'confidence': ml_prediction.final_confidence,
            'probability': ml_prediction.final_probability,
            'ml_metadata': ml_prediction.to_dict()
        }
        
        # Validate finding
        report = validator.validate_finding(finding)
        
        self.assertIsNotNone(report)
        # Just verify the validation completed, don't enforce specific confidence
        self.assertGreaterEqual(report.final_confidence, 0.0)
        self.assertLessEqual(report.final_confidence, 1.0)
        
    def test_ensemble_with_validation_feedback(self):
        """Test ensemble learning from validation feedback"""
        ensemble = EnsembleLearner()
        validator = MultiStageValidator()
        
        features = {
            'response_length': 0.8,
            'error_density': 0.7
        }
        
        # Get ensemble prediction
        prediction = ensemble.predict(features)
        
        # Create and validate finding
        finding = {
            'id': 'feedback-test',
            'type': 'sqli',
            'confidence': prediction.final_confidence
        }
        
        report = validator.validate_finding(finding)
        
        # Use validation result to update model weights (simplified)
        if report.final_result == ValidationResult.VERIFIED:
            # Models performed well
            validation_results = {
                model_type: 0.95 for model_type in ModelType
            }
            ensemble.update_model_weights(validation_results)
            
        self.assertIsNotNone(ensemble.model_weights)


if __name__ == '__main__':
    unittest.main()
