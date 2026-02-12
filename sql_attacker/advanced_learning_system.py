"""
Advanced Learning System

Reinforcement learning for exploit selection, transfer learning across targets,
and ensemble prediction models with continuous improvement.
"""

import logging
import random
import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import statistics

logger = logging.getLogger(__name__)


@dataclass
class State:
    """Represents a state in the reinforcement learning environment"""
    target_characteristics: Dict[str, Any]
    attempted_techniques: List[str]
    success_history: List[bool]
    detection_events: int
    elapsed_time: float
    
    def to_feature_vector(self) -> List[float]:
        """Convert state to feature vector for learning"""
        features = []
        
        # Target features
        features.append(1.0 if self.target_characteristics.get('waf_detected') else 0.0)
        features.append(1.0 if self.target_characteristics.get('rate_limited') else 0.0)
        features.append(float(len(self.target_characteristics.get('security_headers', [])) / 5.0))
        
        # Attempt history
        features.append(float(len(self.attempted_techniques)) / 10.0)
        features.append(sum(self.success_history) / max(len(self.success_history), 1))
        
        # Detection and time
        features.append(min(float(self.detection_events) / 5.0, 1.0))
        features.append(min(self.elapsed_time / 300.0, 1.0))  # Normalize to 5 minutes
        
        return features


@dataclass
class Action:
    """Represents an action (technique selection)"""
    action_id: str
    technique: str
    payload_category: str
    aggressiveness: float  # 0.0 = stealthy, 1.0 = aggressive
    estimated_time: float


@dataclass
class Experience:
    """Experience tuple for replay buffer"""
    state: State
    action: Action
    reward: float
    next_state: State
    done: bool


class QTable:
    """Q-learning table for state-action values"""
    
    def __init__(self, learning_rate: float = 0.1, discount_factor: float = 0.9):
        """
        Initialize Q-table.
        
        Args:
            learning_rate: Learning rate (alpha)
            discount_factor: Discount factor (gamma)
        """
        self.q_values = defaultdict(lambda: defaultdict(float))
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
    
    def get_q_value(self, state_hash: str, action_id: str) -> float:
        """Get Q-value for state-action pair"""
        return self.q_values[state_hash][action_id]
    
    def update(self, state_hash: str, action_id: str, reward: float, 
              next_state_hash: str, next_actions: List[str]):
        """Update Q-value using Q-learning update rule"""
        current_q = self.get_q_value(state_hash, action_id)
        
        # Get max Q-value for next state
        max_next_q = max([self.get_q_value(next_state_hash, a) for a in next_actions], 
                        default=0.0)
        
        # Q-learning update
        new_q = current_q + self.learning_rate * (
            reward + self.discount_factor * max_next_q - current_q
        )
        
        self.q_values[state_hash][action_id] = new_q
    
    def get_best_action(self, state_hash: str, available_actions: List[str]) -> str:
        """Get action with highest Q-value for given state"""
        if not available_actions:
            return None
        
        action_values = [(action, self.get_q_value(state_hash, action)) 
                        for action in available_actions]
        return max(action_values, key=lambda x: x[1])[0]


class EnsemblePredictor:
    """Ensemble of prediction models with voting"""
    
    def __init__(self):
        """Initialize ensemble predictor"""
        self.models = {
            'q_learning': QTable(),
            'success_rate': defaultdict(lambda: {'success': 0, 'total': 0}),
            'context_based': defaultdict(lambda: defaultdict(float)),
        }
        self.model_weights = {
            'q_learning': 0.4,
            'success_rate': 0.3,
            'context_based': 0.3,
        }
    
    def predict(self, state: State, available_actions: List[Action]) -> Action:
        """
        Predict best action using ensemble voting.
        
        Args:
            state: Current state
            available_actions: List of available actions
        
        Returns:
            Best action according to ensemble
        """
        if not available_actions:
            return None
        
        # Get predictions from each model
        state_hash = self._hash_state(state)
        action_ids = [a.action_id for a in available_actions]
        
        # Model 1: Q-learning
        q_best = self.models['q_learning'].get_best_action(state_hash, action_ids)
        
        # Model 2: Success rate
        success_scores = {}
        for action in available_actions:
            stats = self.models['success_rate'][action.action_id]
            success_scores[action.action_id] = stats['success'] / max(stats['total'], 1)
        sr_best = max(success_scores, key=success_scores.get) if success_scores else action_ids[0]
        
        # Model 3: Context-based
        context_key = self._get_context_key(state.target_characteristics)
        context_scores = {}
        for action in available_actions:
            context_scores[action.action_id] = self.models['context_based'][context_key][action.action_id]
        cb_best = max(context_scores, key=context_scores.get) if context_scores else action_ids[0]
        
        # Weighted voting
        votes = defaultdict(float)
        votes[q_best] += self.model_weights['q_learning']
        votes[sr_best] += self.model_weights['success_rate']
        votes[cb_best] += self.model_weights['context_based']
        
        # Select action with most votes
        best_action_id = max(votes, key=votes.get)
        return next(a for a in available_actions if a.action_id == best_action_id)
    
    def update(self, experience: Experience):
        """Update all models with new experience"""
        state_hash = self._hash_state(experience.state)
        next_state_hash = self._hash_state(experience.next_state)
        available_actions = [experience.action.action_id]  # Simplified
        
        # Update Q-learning
        self.models['q_learning'].update(
            state_hash, 
            experience.action.action_id,
            experience.reward,
            next_state_hash,
            available_actions
        )
        
        # Update success rate
        stats = self.models['success_rate'][experience.action.action_id]
        stats['total'] += 1
        if experience.reward > 0:
            stats['success'] += 1
        
        # Update context-based
        context_key = self._get_context_key(experience.state.target_characteristics)
        self.models['context_based'][context_key][experience.action.action_id] += experience.reward
    
    def _hash_state(self, state: State) -> str:
        """Create hash of state for dictionary lookup"""
        features = state.to_feature_vector()
        # Discretize features
        discretized = tuple(round(f, 1) for f in features)
        return str(discretized)
    
    def _get_context_key(self, characteristics: Dict[str, Any]) -> str:
        """Get context key from target characteristics"""
        key_parts = []
        key_parts.append('waf' if characteristics.get('waf_detected') else 'no_waf')
        key_parts.append(characteristics.get('database_type', 'unknown'))
        key_parts.append(characteristics.get('security_posture', 'unknown'))
        return '_'.join(key_parts)


class TransferLearning:
    """Transfer learning across different targets"""
    
    def __init__(self):
        """Initialize transfer learning"""
        self.target_embeddings = {}
        self.similarity_cache = {}
        self.knowledge_base = defaultdict(list)
    
    def add_target_experience(self, target_id: str, 
                             characteristics: Dict[str, Any],
                             successful_techniques: List[str],
                             failed_techniques: List[str]):
        """Add experience from a target"""
        # Create embedding for target
        embedding = self._create_embedding(characteristics)
        self.target_embeddings[target_id] = {
            'embedding': embedding,
            'characteristics': characteristics,
            'successful': successful_techniques,
            'failed': failed_techniques,
        }
        
        # Update knowledge base
        context_key = self._get_context_signature(characteristics)
        self.knowledge_base[context_key].append({
            'target_id': target_id,
            'successful': successful_techniques,
            'failed': failed_techniques,
        })
    
    def recommend_techniques(self, target_characteristics: Dict[str, Any]) -> Dict[str, float]:
        """
        Recommend techniques based on similar past targets.
        
        Args:
            target_characteristics: Characteristics of new target
        
        Returns:
            Dictionary of {technique: confidence_score}
        """
        # Find similar targets
        new_embedding = self._create_embedding(target_characteristics)
        similar_targets = self._find_similar_targets(new_embedding, top_k=5)
        
        # Aggregate recommendations
        recommendations = defaultdict(float)
        total_similarity = 0.0
        
        for target_id, similarity in similar_targets:
            target_data = self.target_embeddings[target_id]
            
            # Weight by similarity
            for technique in target_data['successful']:
                recommendations[technique] += similarity
            
            # Penalize failed techniques
            for technique in target_data['failed']:
                recommendations[technique] -= similarity * 0.5
            
            total_similarity += similarity
        
        # Normalize scores
        if total_similarity > 0:
            recommendations = {k: v/total_similarity for k, v in recommendations.items()}
        
        return dict(recommendations)
    
    def _create_embedding(self, characteristics: Dict[str, Any]) -> List[float]:
        """Create embedding vector for target characteristics"""
        embedding = []
        
        # Binary features
        embedding.append(1.0 if characteristics.get('waf_detected') else 0.0)
        embedding.append(1.0 if characteristics.get('rate_limited') else 0.0)
        embedding.append(1.0 if characteristics.get('csrf_protection') else 0.0)
        
        # Categorical features (one-hot encoding)
        db_types = ['mysql', 'postgresql', 'mssql', 'oracle', 'unknown']
        db_type = characteristics.get('database_type', 'unknown')
        embedding.extend([1.0 if db == db_type else 0.0 for db in db_types])
        
        # Security posture (ordinal)
        posture_map = {'weak': 0.25, 'moderate': 0.5, 'strong': 0.75, 'hardened': 1.0}
        embedding.append(posture_map.get(characteristics.get('security_posture'), 0.5))
        
        return embedding
    
    def _find_similar_targets(self, embedding: List[float], top_k: int = 5) -> List[Tuple[str, float]]:
        """Find most similar targets using cosine similarity"""
        similarities = []
        
        for target_id, target_data in self.target_embeddings.items():
            similarity = self._cosine_similarity(embedding, target_data['embedding'])
            similarities.append((target_id, similarity))
        
        # Sort by similarity and return top k
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]
    
    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        if len(vec1) != len(vec2):
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = math.sqrt(sum(a * a for a in vec1))
        magnitude2 = math.sqrt(sum(b * b for b in vec2))
        
        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0
        
        return dot_product / (magnitude1 * magnitude2)
    
    def _get_context_signature(self, characteristics: Dict[str, Any]) -> str:
        """Get context signature for knowledge base"""
        parts = []
        parts.append(characteristics.get('database_type', 'unknown'))
        parts.append('waf' if characteristics.get('waf_detected') else 'no_waf')
        parts.append(characteristics.get('security_posture', 'unknown'))
        return '_'.join(parts)


class AdvancedLearningSystem:
    """
    Advanced learning system combining reinforcement learning,
    transfer learning, and ensemble methods.
    """
    
    def __init__(self, epsilon: float = 0.1, epsilon_decay: float = 0.995):
        """
        Initialize advanced learning system.
        
        Args:
            epsilon: Exploration rate for epsilon-greedy
            epsilon_decay: Decay rate for epsilon
        """
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.min_epsilon = 0.01
        
        # Learning components
        self.ensemble = EnsemblePredictor()
        self.transfer_learning = TransferLearning()
        self.experience_buffer = deque(maxlen=1000)
        
        # Available actions
        self.available_actions = self._initialize_actions()
        
        # Training statistics
        self.episodes = 0
        self.total_reward = 0.0
        self.avg_reward_history = []
        
        logger.info(f"Advanced learning system initialized with epsilon={epsilon}")
    
    def _initialize_actions(self) -> List[Action]:
        """Initialize available actions"""
        return [
            Action('error_based', 'error_based', 'standard', 0.5, 5.0),
            Action('time_based', 'time_based', 'blind', 0.3, 10.0),
            Action('boolean_blind', 'boolean_blind', 'blind', 0.2, 8.0),
            Action('union_based', 'union_based', 'extraction', 0.6, 7.0),
            Action('advanced_evasion', 'error_based', 'evasion', 0.4, 15.0),
        ]
    
    def select_action(self, state: State, available_actions: Optional[List[Action]] = None) -> Action:
        """
        Select action using epsilon-greedy strategy with ensemble.
        
        Args:
            state: Current state
            available_actions: List of available actions (uses all if None)
        
        Returns:
            Selected action
        """
        if available_actions is None:
            available_actions = self.available_actions
        
        # Epsilon-greedy exploration
        if random.random() < self.epsilon:
            # Explore: random action
            action = random.choice(available_actions)
            logger.debug(f"Exploring: selected {action.technique}")
        else:
            # Exploit: use ensemble prediction
            action = self.ensemble.predict(state, available_actions)
            logger.debug(f"Exploiting: selected {action.technique}")
        
        return action
    
    def learn_from_experience(self, experience: Experience):
        """
        Learn from a single experience.
        
        Args:
            experience: Experience tuple
        """
        # Add to buffer
        self.experience_buffer.append(experience)
        
        # Update ensemble
        self.ensemble.update(experience)
        
        # Update statistics
        self.total_reward += experience.reward
        
        # Decay epsilon
        self.epsilon = max(self.min_epsilon, self.epsilon * self.epsilon_decay)
        
        logger.debug(f"Learned from experience: reward={experience.reward:.2f}, epsilon={self.epsilon:.3f}")
    
    def batch_learn(self, batch_size: int = 32):
        """
        Perform batch learning from experience buffer.
        
        Args:
            batch_size: Number of experiences to sample
        """
        if len(self.experience_buffer) < batch_size:
            return
        
        # Sample random batch
        batch = random.sample(self.experience_buffer, batch_size)
        
        # Learn from each experience
        for experience in batch:
            self.ensemble.update(experience)
        
        logger.info(f"Batch learning complete: {batch_size} experiences")
    
    def update_from_target(self, target_id: str,
                          characteristics: Dict[str, Any],
                          successful_techniques: List[str],
                          failed_techniques: List[str]):
        """
        Update transfer learning knowledge from completed target.
        
        Args:
            target_id: Target identifier
            characteristics: Target characteristics
            successful_techniques: Techniques that succeeded
            failed_techniques: Techniques that failed
        """
        self.transfer_learning.add_target_experience(
            target_id,
            characteristics,
            successful_techniques,
            failed_techniques
        )
        
        self.episodes += 1
        avg_reward = self.total_reward / self.episodes if self.episodes > 0 else 0
        self.avg_reward_history.append(avg_reward)
        
        logger.info(f"Updated knowledge base from target {target_id}: "
                   f"{len(successful_techniques)} successful, "
                   f"{len(failed_techniques)} failed")
    
    def get_recommendations(self, target_characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get comprehensive recommendations for a new target.
        
        Args:
            target_characteristics: Characteristics of new target
        
        Returns:
            Dictionary with recommendations and confidence scores
        """
        # Get transfer learning recommendations
        transfer_recs = self.transfer_learning.recommend_techniques(target_characteristics)
        
        # Create state for ensemble prediction
        state = State(
            target_characteristics=target_characteristics,
            attempted_techniques=[],
            success_history=[],
            detection_events=0,
            elapsed_time=0.0
        )
        
        # Get ensemble prediction
        best_action = self.ensemble.predict(state, self.available_actions)
        
        recommendations = {
            'transfer_learning': transfer_recs,
            'ensemble_best': best_action.technique if best_action else None,
            'exploration_rate': self.epsilon,
            'episodes_trained': self.episodes,
            'avg_reward': self.avg_reward_history[-1] if self.avg_reward_history else 0.0,
        }
        
        return recommendations
    
    def generate_report(self) -> str:
        """Generate learning system report"""
        report = []
        report.append("=" * 70)
        report.append("ADVANCED LEARNING SYSTEM REPORT")
        report.append("=" * 70)
        
        report.append(f"\n[*] Training Statistics")
        report.append(f"Episodes: {self.episodes}")
        report.append(f"Total Reward: {self.total_reward:.2f}")
        if self.avg_reward_history:
            report.append(f"Average Reward: {self.avg_reward_history[-1]:.2f}")
            report.append(f"Reward Trend: {'+' if len(self.avg_reward_history) > 1 and self.avg_reward_history[-1] > self.avg_reward_history[-2] else '-'}")
        report.append(f"Exploration Rate: {self.epsilon:.3f}")
        report.append(f"Experience Buffer: {len(self.experience_buffer)}/{self.experience_buffer.maxlen}")
        
        report.append(f"\n[*] Knowledge Base")
        report.append(f"Targets Learned: {len(self.transfer_learning.target_embeddings)}")
        report.append(f"Context Patterns: {len(self.transfer_learning.knowledge_base)}")
        
        report.append("\n" + "=" * 70)
        return "\n".join(report)
