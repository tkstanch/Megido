"""
Ensemble Detection System for SQL Injection

Combines multiple detection strategies:
- Pattern-based detection
- Semantic analysis
- Taint tracking
- ML-based prediction
- Boolean blind detection
- Time-based detection

Uses voting and confidence scoring to reduce false positives.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DetectionMethod(Enum):
    """Detection methods used in ensemble"""
    PATTERN_BASED = "pattern_based"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    TAINT_TRACKING = "taint_tracking"
    ML_PREDICTION = "ml_prediction"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectionResult:
    """Result from a single detection method"""
    method: DetectionMethod
    is_vulnerable: bool
    confidence: float
    details: Dict[str, Any]
    evidence: List[str]


class EnsembleDetector:
    """
    Ensemble detector that combines multiple detection methods
    for high-accuracy SQL injection detection.
    """
    
    def __init__(self):
        """Initialize ensemble detector"""
        self.detection_methods = []
        self.weights = {
            DetectionMethod.PATTERN_BASED: 0.15,
            DetectionMethod.SEMANTIC_ANALYSIS: 0.20,
            DetectionMethod.TAINT_TRACKING: 0.15,
            DetectionMethod.ML_PREDICTION: 0.20,
            DetectionMethod.BOOLEAN_BLIND: 0.15,
            DetectionMethod.TIME_BASED: 0.15,
            DetectionMethod.ERROR_BASED: 0.10,
        }
        self.min_confidence_threshold = 0.7
        self.min_methods_required = 2
    
    def add_detection_result(self, result: DetectionResult):
        """Add a detection result to the ensemble"""
        self.detection_methods.append(result)
    
    def evaluate(self) -> Dict[str, Any]:
        """
        Evaluate all detection results using ensemble voting.
        
        Returns:
            Final detection result with confidence and severity
        """
        if not self.detection_methods:
            return {
                'is_vulnerable': False,
                'confidence': 0.0,
                'severity': SeverityLevel.INFO.value,
                'methods_detected': [],
                'evidence': [],
                'explanation': "No detection methods executed"
            }
        
        # Calculate weighted vote
        weighted_score = 0.0
        methods_detected = []
        all_evidence = []
        method_details = {}
        
        for result in self.detection_methods:
            if result.is_vulnerable:
                weight = self.weights.get(result.method, 0.1)
                weighted_score += weight * result.confidence
                methods_detected.append(result.method.value)
                all_evidence.extend(result.evidence)
                method_details[result.method.value] = result.details
        
        # Normalize score
        total_weight = sum(self.weights.get(m.method, 0.1) for m in self.detection_methods)
        if total_weight > 0:
            weighted_score = weighted_score / total_weight
        
        # Determine if vulnerable
        is_vulnerable = (
            weighted_score >= self.min_confidence_threshold and
            len(methods_detected) >= self.min_methods_required
        )
        
        # Calculate severity
        severity = self._calculate_severity(weighted_score, methods_detected)
        
        # Generate explanation
        explanation = self._generate_explanation(
            is_vulnerable, weighted_score, methods_detected
        )
        
        return {
            'is_vulnerable': is_vulnerable,
            'confidence': weighted_score,
            'severity': severity.value,
            'methods_detected': methods_detected,
            'method_count': len(methods_detected),
            'evidence': list(set(all_evidence)),  # Remove duplicates
            'method_details': method_details,
            'explanation': explanation,
            'threshold_met': weighted_score >= self.min_confidence_threshold,
            'min_methods_met': len(methods_detected) >= self.min_methods_required
        }
    
    def _calculate_severity(self, confidence: float, methods: List[str]) -> SeverityLevel:
        """
        Calculate severity level based on confidence and detection methods.
        
        Args:
            confidence: Confidence score
            methods: List of methods that detected the vulnerability
            
        Returns:
            SeverityLevel enum
        """
        # Critical: High confidence and multiple detection methods
        if confidence >= 0.9 and len(methods) >= 4:
            return SeverityLevel.CRITICAL
        
        # High: Good confidence and multiple methods
        if confidence >= 0.75 and len(methods) >= 3:
            return SeverityLevel.HIGH
        
        # Medium: Moderate confidence
        if confidence >= 0.6 and len(methods) >= 2:
            return SeverityLevel.MEDIUM
        
        # Low: Lower confidence
        if confidence >= 0.4:
            return SeverityLevel.LOW
        
        return SeverityLevel.INFO
    
    def _generate_explanation(self, is_vulnerable: bool, confidence: float, methods: List[str]) -> str:
        """Generate human-readable explanation"""
        if not is_vulnerable:
            return f"No SQL injection detected. Confidence: {confidence:.2%}"
        
        method_str = ", ".join(methods)
        return (
            f"SQL injection detected with {confidence:.2%} confidence. "
            f"Detected by {len(methods)} method(s): {method_str}. "
            f"Multiple detection methods agree on vulnerability."
        )
    
    def get_detailed_report(self) -> Dict[str, Any]:
        """
        Get detailed report of all detection methods.
        
        Returns:
            Comprehensive report
        """
        evaluation = self.evaluate()
        
        return {
            'summary': evaluation,
            'individual_results': [
                {
                    'method': result.method.value,
                    'is_vulnerable': result.is_vulnerable,
                    'confidence': result.confidence,
                    'weight': self.weights.get(result.method, 0.1),
                    'evidence_count': len(result.evidence),
                    'details': result.details
                }
                for result in self.detection_methods
            ],
            'configuration': {
                'min_confidence_threshold': self.min_confidence_threshold,
                'min_methods_required': self.min_methods_required,
                'weights': {k.value: v for k, v in self.weights.items()}
            }
        }
    
    def adjust_threshold(self, new_threshold: float):
        """Adjust confidence threshold"""
        if 0.0 <= new_threshold <= 1.0:
            self.min_confidence_threshold = new_threshold
            logger.info(f"Adjusted confidence threshold to {new_threshold}")
    
    def adjust_weight(self, method: DetectionMethod, new_weight: float):
        """Adjust weight for a detection method"""
        if 0.0 <= new_weight <= 1.0:
            self.weights[method] = new_weight
            logger.info(f"Adjusted weight for {method.value} to {new_weight}")
    
    def reset(self):
        """Reset detector state"""
        self.detection_methods.clear()


class FeedbackSystem:
    """
    System for collecting feedback and improving detection.
    Allows manual override and learning from false positives/negatives.
    """
    
    def __init__(self):
        """Initialize feedback system"""
        self.feedback_history = []
        self.false_positives = []
        self.false_negatives = []
        self.true_positives = []
        self.true_negatives = []
    
    def add_feedback(self,
                    detection_result: Dict[str, Any],
                    actual_result: bool,
                    user_comment: str = "") -> Dict[str, Any]:
        """
        Add feedback for a detection result.
        
        Args:
            detection_result: Result from ensemble detector
            actual_result: Actual vulnerability status (True/False)
            user_comment: Optional user comment
            
        Returns:
            Feedback entry
        """
        predicted = detection_result['is_vulnerable']
        
        feedback = {
            'predicted': predicted,
            'actual': actual_result,
            'confidence': detection_result['confidence'],
            'severity': detection_result['severity'],
            'methods_detected': detection_result['methods_detected'],
            'user_comment': user_comment,
            'is_correct': predicted == actual_result
        }
        
        self.feedback_history.append(feedback)
        
        # Categorize feedback
        if predicted and actual_result:
            self.true_positives.append(feedback)
        elif not predicted and not actual_result:
            self.true_negatives.append(feedback)
        elif predicted and not actual_result:
            self.false_positives.append(feedback)
        else:
            self.false_negatives.append(feedback)
        
        logger.info(f"Feedback added: {'Correct' if feedback['is_correct'] else 'Incorrect'}")
        
        return feedback
    
    def get_accuracy_metrics(self) -> Dict[str, Any]:
        """
        Calculate accuracy metrics based on feedback.
        
        Returns:
            Metrics including precision, recall, F1-score
        """
        tp = len(self.true_positives)
        tn = len(self.true_negatives)
        fp = len(self.false_positives)
        fn = len(self.false_negatives)
        
        total = tp + tn + fp + fn
        
        if total == 0:
            return {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'total_feedback': 0
            }
        
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'total_feedback': total,
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn
        }
    
    def get_improvement_suggestions(self) -> List[str]:
        """
        Generate suggestions for improving detection.
        
        Returns:
            List of suggestions
        """
        suggestions = []
        metrics = self.get_accuracy_metrics()
        
        if metrics['false_positives'] > metrics['true_positives']:
            suggestions.append(
                "High false positive rate detected. Consider increasing confidence threshold "
                "or adjusting detection method weights."
            )
        
        if metrics['false_negatives'] > metrics['true_positives']:
            suggestions.append(
                "High false negative rate detected. Consider decreasing confidence threshold "
                "or enabling additional detection methods."
            )
        
        if metrics['precision'] < 0.7:
            suggestions.append(
                "Low precision. Review false positives and add patterns to whitelist."
            )
        
        if metrics['recall'] < 0.7:
            suggestions.append(
                "Low recall. Consider adding more detection patterns or lowering thresholds."
            )
        
        if not suggestions:
            suggestions.append("Detection performance is good. Continue monitoring.")
        
        return suggestions
    
    def export_feedback_data(self) -> Dict[str, Any]:
        """Export feedback data for analysis or training"""
        return {
            'feedback_history': self.feedback_history,
            'metrics': self.get_accuracy_metrics(),
            'suggestions': self.get_improvement_suggestions(),
            'false_positive_patterns': [
                fp['methods_detected'] for fp in self.false_positives
            ],
            'false_negative_patterns': [
                fn['methods_detected'] for fn in self.false_negatives
            ]
        }
