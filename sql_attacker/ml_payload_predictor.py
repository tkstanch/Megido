"""
Machine Learning Payload Predictor

Uses a simple neural network to predict payload effectiveness based on
historical success patterns. This is a lightweight ML implementation that
doesn't require external libraries like TensorFlow or PyTorch.
"""

import json
import math
import random
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class PayloadFeatures:
    """Feature vector for a payload"""
    length: float
    special_char_ratio: float
    quote_count: float
    comment_count: float
    keyword_count: float
    encoding_score: float
    complexity_score: float
    context_match_score: float


class SimpleNeuralNetwork:
    """
    Lightweight neural network for payload scoring.
    Single hidden layer feedforward network with backpropagation.
    """
    
    def __init__(self, input_size: int = 8, hidden_size: int = 12, output_size: int = 1):
        """
        Initialize neural network.
        
        Args:
            input_size: Number of input features
            hidden_size: Number of hidden layer neurons
            output_size: Number of output neurons (1 for success probability)
        """
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        
        # Initialize weights with Xavier initialization
        self.weights_input_hidden = self._xavier_init(input_size, hidden_size)
        self.bias_hidden = [0.0] * hidden_size
        
        self.weights_hidden_output = self._xavier_init(hidden_size, output_size)
        self.bias_output = [0.0] * output_size
        
        # Learning rate
        self.learning_rate = 0.01
        
        logger.info(f"Neural network initialized: {input_size}->{hidden_size}->{output_size}")
    
    def _xavier_init(self, n_in: int, n_out: int) -> List[List[float]]:
        """Xavier/Glorot initialization for weights"""
        limit = math.sqrt(6.0 / (n_in + n_out))
        return [[random.uniform(-limit, limit) for _ in range(n_out)] for _ in range(n_in)]
    
    def _sigmoid(self, x: float) -> float:
        """Sigmoid activation function"""
        return 1.0 / (1.0 + math.exp(-max(min(x, 500), -500)))  # Clamp to avoid overflow
    
    def _sigmoid_derivative(self, x: float) -> float:
        """Derivative of sigmoid"""
        s = self._sigmoid(x)
        return s * (1 - s)
    
    def _relu(self, x: float) -> float:
        """ReLU activation function"""
        return max(0, x)
    
    def _relu_derivative(self, x: float) -> float:
        """Derivative of ReLU"""
        return 1.0 if x > 0 else 0.0
    
    def forward(self, inputs: List[float]) -> Tuple[float, List[float], List[float]]:
        """
        Forward pass through the network.
        
        Args:
            inputs: Input feature vector
        
        Returns:
            Tuple of (output, hidden_activations, hidden_pre_activations)
        """
        # Input to hidden layer
        hidden_pre = []
        for j in range(self.hidden_size):
            activation = sum(inputs[i] * self.weights_input_hidden[i][j] 
                           for i in range(self.input_size))
            activation += self.bias_hidden[j]
            hidden_pre.append(activation)
        
        # Apply ReLU activation
        hidden = [self._relu(x) for x in hidden_pre]
        
        # Hidden to output layer
        output_pre = sum(hidden[j] * self.weights_hidden_output[j][0] 
                        for j in range(self.hidden_size))
        output_pre += self.bias_output[0]
        
        # Apply sigmoid to get probability
        output = self._sigmoid(output_pre)
        
        return output, hidden, hidden_pre
    
    def backward(self, inputs: List[float], hidden: List[float], 
                hidden_pre: List[float], output: float, target: float):
        """
        Backward pass to update weights.
        
        Args:
            inputs: Input feature vector
            hidden: Hidden layer activations
            hidden_pre: Hidden layer pre-activations
            output: Network output
            target: Target value (0 or 1)
        """
        # Output layer error
        output_error = output - target
        output_delta = output_error * self._sigmoid_derivative(output)
        
        # Hidden layer error
        hidden_errors = [output_delta * self.weights_hidden_output[j][0] 
                        for j in range(self.hidden_size)]
        hidden_deltas = [hidden_errors[j] * self._relu_derivative(hidden_pre[j]) 
                        for j in range(self.hidden_size)]
        
        # Update weights hidden -> output
        for j in range(self.hidden_size):
            self.weights_hidden_output[j][0] -= self.learning_rate * output_delta * hidden[j]
        self.bias_output[0] -= self.learning_rate * output_delta
        
        # Update weights input -> hidden
        for i in range(self.input_size):
            for j in range(self.hidden_size):
                self.weights_input_hidden[i][j] -= self.learning_rate * hidden_deltas[j] * inputs[i]
        
        for j in range(self.hidden_size):
            self.bias_hidden[j] -= self.learning_rate * hidden_deltas[j]
    
    def train(self, inputs: List[float], target: float):
        """
        Train the network on a single example.
        
        Args:
            inputs: Input feature vector
            target: Target output (0 or 1)
        """
        output, hidden, hidden_pre = self.forward(inputs)
        self.backward(inputs, hidden, hidden_pre, output, target)
    
    def predict(self, inputs: List[float]) -> float:
        """
        Predict success probability for input.
        
        Args:
            inputs: Input feature vector
        
        Returns:
            Predicted probability (0-1)
        """
        output, _, _ = self.forward(inputs)
        return output


class MLPayloadPredictor:
    """
    Machine Learning-based payload predictor using neural network.
    Predicts payload effectiveness based on features and historical data.
    """
    
    def __init__(self):
        """Initialize ML payload predictor"""
        self.network = SimpleNeuralNetwork(input_size=8, hidden_size=12, output_size=1)
        self.training_data = []
        self.feature_stats = {
            'length_mean': 20.0,
            'length_std': 10.0,
            'success_rate': 0.3,
        }
        
        logger.info("ML Payload Predictor initialized")
    
    def extract_features(self, payload: str, context: Dict[str, Any] = None) -> PayloadFeatures:
        """
        Extract features from a payload.
        
        Args:
            payload: SQL injection payload
            context: Context information (DB type, WAF, etc.)
        
        Returns:
            PayloadFeatures object
        """
        if not payload:
            return PayloadFeatures(0, 0, 0, 0, 0, 0, 0, 0)
        
        # Length (normalized to 0-1 range, assuming max 200 chars)
        length = min(len(payload) / 200.0, 1.0)
        
        # Special character ratio
        special_chars = sum(1 for c in payload if not c.isalnum() and c != ' ')
        special_char_ratio = special_chars / len(payload) if payload else 0
        
        # Quote count (normalized)
        quote_count = min((payload.count("'") + payload.count('"')) / 10.0, 1.0)
        
        # Comment count (normalized)
        comment_indicators = ['--', '#', '/*', '*/']
        comment_count = min(sum(payload.count(c) for c in comment_indicators) / 5.0, 1.0)
        
        # SQL keyword count (normalized)
        sql_keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'OR', 'AND', 'INSERT', 
                       'UPDATE', 'DELETE', 'DROP', 'EXEC', 'EXECUTE']
        keyword_count = min(sum(1 for k in sql_keywords if k in payload.upper()) / 5.0, 1.0)
        
        # Encoding score (detects URL encoding, hex, etc.)
        encoding_indicators = ['%', '0x', '\\x', '&#']
        encoding_score = min(sum(payload.count(e) for e in encoding_indicators) / 10.0, 1.0)
        
        # Complexity score (combination of factors)
        parentheses = payload.count('(') + payload.count(')')
        operators = payload.count('=') + payload.count('>') + payload.count('<')
        complexity_score = min((parentheses + operators) / 20.0, 1.0)
        
        # Context match score
        context_match_score = 0.5  # Default
        if context:
            # Boost if payload matches detected DB type
            detected_db = context.get('detected_db', '')
            if detected_db:
                if 'SLEEP' in payload.upper() and detected_db == 'mysql':
                    context_match_score = 0.9
                elif 'pg_sleep' in payload.lower() and detected_db == 'postgresql':
                    context_match_score = 0.9
                elif 'WAITFOR' in payload.upper() and detected_db == 'mssql':
                    context_match_score = 0.9
        
        return PayloadFeatures(
            length=length,
            special_char_ratio=special_char_ratio,
            quote_count=quote_count,
            comment_count=comment_count,
            keyword_count=keyword_count,
            encoding_score=encoding_score,
            complexity_score=complexity_score,
            context_match_score=context_match_score
        )
    
    def features_to_vector(self, features: PayloadFeatures) -> List[float]:
        """Convert features to input vector"""
        return [
            features.length,
            features.special_char_ratio,
            features.quote_count,
            features.comment_count,
            features.keyword_count,
            features.encoding_score,
            features.complexity_score,
            features.context_match_score,
        ]
    
    def predict_success_probability(self, payload: str, context: Dict[str, Any] = None) -> float:
        """
        Predict probability that payload will succeed.
        
        Args:
            payload: SQL injection payload
            context: Context information
        
        Returns:
            Success probability (0-1)
        """
        features = self.extract_features(payload, context)
        input_vector = self.features_to_vector(features)
        probability = self.network.predict(input_vector)
        
        logger.debug(f"Predicted success probability: {probability:.3f} for payload: {payload[:50]}")
        return probability
    
    def train_on_result(self, payload: str, success: bool, context: Dict[str, Any] = None):
        """
        Train the model based on a test result.
        
        Args:
            payload: Tested payload
            success: Whether payload succeeded (True) or failed (False)
            context: Context information
        """
        features = self.extract_features(payload, context)
        input_vector = self.features_to_vector(features)
        target = 1.0 if success else 0.0
        
        self.network.train(input_vector, target)
        
        # Store training example
        self.training_data.append({
            'payload': payload[:100],  # Store first 100 chars
            'success': success,
            'features': features,
        })
        
        # Update statistics
        self._update_statistics()
        
        logger.info(f"Trained on {'successful' if success else 'failed'} payload: {payload[:50]}")
    
    def _update_statistics(self):
        """Update feature statistics from training data"""
        if not self.training_data:
            return
        
        successes = sum(1 for d in self.training_data if d['success'])
        self.feature_stats['success_rate'] = successes / len(self.training_data)
        
        # Update feature means (for future normalization improvements)
        lengths = [d['features'].length for d in self.training_data]
        self.feature_stats['length_mean'] = sum(lengths) / len(lengths) if lengths else 20.0
    
    def rank_payloads(self, payloads: List[str], context: Dict[str, Any] = None) -> List[Tuple[str, float]]:
        """
        Rank payloads by predicted success probability.
        
        Args:
            payloads: List of payloads to rank
            context: Context information
        
        Returns:
            List of (payload, probability) tuples, sorted by probability (descending)
        """
        ranked = []
        for payload in payloads:
            prob = self.predict_success_probability(payload, context)
            ranked.append((payload, prob))
        
        # Sort by probability (descending)
        ranked.sort(key=lambda x: x[1], reverse=True)
        
        logger.info(f"Ranked {len(payloads)} payloads, top probability: {ranked[0][1]:.3f}")
        return ranked
    
    def get_best_payloads(self, payloads: List[str], n: int = 10, 
                         context: Dict[str, Any] = None) -> List[str]:
        """
        Get top N payloads by predicted success.
        
        Args:
            payloads: List of candidate payloads
            n: Number of top payloads to return
            context: Context information
        
        Returns:
            List of top N payloads
        """
        ranked = self.rank_payloads(payloads, context)
        return [payload for payload, _ in ranked[:n]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get ML model statistics"""
        return {
            'training_samples': len(self.training_data),
            'success_rate': self.feature_stats['success_rate'],
            'network_architecture': f"{self.network.input_size}-{self.network.hidden_size}-{self.network.output_size}",
            'learning_rate': self.network.learning_rate,
        }
    
    def save_model(self, filepath: str):
        """Save model weights to file"""
        model_data = {
            'weights_input_hidden': self.network.weights_input_hidden,
            'bias_hidden': self.network.bias_hidden,
            'weights_hidden_output': self.network.weights_hidden_output,
            'bias_output': self.network.bias_output,
            'feature_stats': self.feature_stats,
            'training_count': len(self.training_data),
        }
        
        with open(filepath, 'w') as f:
            json.dump(model_data, f)
        
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model weights from file"""
        try:
            with open(filepath, 'r') as f:
                model_data = json.load(f)
            
            self.network.weights_input_hidden = model_data['weights_input_hidden']
            self.network.bias_hidden = model_data['bias_hidden']
            self.network.weights_hidden_output = model_data['weights_hidden_output']
            self.network.bias_output = model_data['bias_output']
            self.feature_stats = model_data.get('feature_stats', self.feature_stats)
            
            logger.info(f"Model loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


class EnsemblePredictor:
    """
    Ensemble of multiple predictors for improved accuracy.
    Combines ML predictions with rule-based scoring.
    """
    
    def __init__(self):
        self.ml_predictor = MLPayloadPredictor()
        self.rule_weights = {
            'ml_score': 0.6,
            'length_penalty': 0.1,
            'complexity_bonus': 0.15,
            'context_match': 0.15,
        }
    
    def predict(self, payload: str, context: Dict[str, Any] = None) -> float:
        """
        Ensemble prediction combining ML and rules.
        
        Args:
            payload: SQL injection payload
            context: Context information
        
        Returns:
            Combined prediction score (0-1)
        """
        # ML prediction
        ml_score = self.ml_predictor.predict_success_probability(payload, context)
        
        # Rule-based adjustments
        length_penalty = 1.0 if len(payload) < 100 else 0.8
        
        complexity_bonus = 1.0
        if payload.count('(') > 3 or 'UNION' in payload.upper():
            complexity_bonus = 1.2
        
        context_match = 0.5
        if context and context.get('detected_db'):
            db = context['detected_db']
            if (db == 'mysql' and 'SLEEP' in payload.upper()) or \
               (db == 'postgresql' and 'pg_sleep' in payload.lower()):
                context_match = 1.0
        
        # Weighted combination
        combined = (
            ml_score * self.rule_weights['ml_score'] +
            length_penalty * self.rule_weights['length_penalty'] +
            complexity_bonus * self.rule_weights['complexity_bonus'] +
            context_match * self.rule_weights['context_match']
        )
        
        return min(combined, 1.0)
