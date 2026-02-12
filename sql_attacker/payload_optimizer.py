"""
Intelligent Payload Optimizer

Tracks payload success rates and automatically optimizes payload selection
based on target characteristics and historical performance.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import statistics

logger = logging.getLogger(__name__)


class PayloadOptimizer:
    """
    Intelligent payload optimizer that learns from success/failure patterns
    and optimizes payload selection for future tests.
    """
    
    def __init__(self):
        """Initialize payload optimizer"""
        self.payload_stats = defaultdict(lambda: {
            'total_uses': 0,
            'successes': 0,
            'failures': 0,
            'avg_response_time': 0.0,
            'success_rate': 0.0,
            'contexts': defaultdict(int),  # Track which contexts work
        })
        self.target_profiles = {}
        self.ranked_payloads = []
        
    def record_payload_result(self, payload: str, success: bool, 
                             response_time: float = 0.0,
                             context: Optional[str] = None,
                             db_type: Optional[str] = None):
        """
        Record the result of a payload test.
        
        Args:
            payload: The payload that was tested
            success: Whether the payload succeeded
            response_time: Time taken for response
            context: Context (numeric, string, etc.)
            db_type: Database type if known
        """
        stats = self.payload_stats[payload]
        stats['total_uses'] += 1
        
        if success:
            stats['successes'] += 1
        else:
            stats['failures'] += 1
        
        # Update average response time
        old_avg = stats['avg_response_time']
        old_count = stats['total_uses'] - 1
        stats['avg_response_time'] = (old_avg * old_count + response_time) / stats['total_uses']
        
        # Update success rate
        stats['success_rate'] = stats['successes'] / stats['total_uses']
        
        # Track context
        if context:
            stats['contexts'][context] += 1
        
        # Track by database type
        if db_type:
            if 'db_types' not in stats:
                stats['db_types'] = defaultdict(lambda: {'success': 0, 'total': 0})
            stats['db_types'][db_type]['total'] += 1
            if success:
                stats['db_types'][db_type]['success'] += 1
        
        logger.debug(f"Payload stats updated: success_rate={stats['success_rate']:.2%}")
    
    def get_ranked_payloads(self, context: Optional[str] = None,
                           db_type: Optional[str] = None,
                           min_uses: int = 3) -> List[Tuple[str, float]]:
        """
        Get payloads ranked by effectiveness.
        
        Args:
            context: Filter by context (numeric, string)
            db_type: Filter by database type
            min_uses: Minimum uses to consider for ranking
        
        Returns:
            List of (payload, score) tuples, sorted by score
        """
        scored_payloads = []
        
        for payload, stats in self.payload_stats.items():
            # Skip payloads with insufficient data
            if stats['total_uses'] < min_uses:
                continue
            
            # Filter by context
            if context and context not in stats['contexts']:
                continue
            
            # Filter by database type
            if db_type and 'db_types' in stats:
                if db_type not in stats['db_types']:
                    continue
                # Use db-specific success rate
                db_stats = stats['db_types'][db_type]
                success_rate = db_stats['success'] / db_stats['total'] if db_stats['total'] > 0 else 0
            else:
                success_rate = stats['success_rate']
            
            # Calculate score (weighted combination of factors)
            score = self._calculate_payload_score(stats, success_rate)
            
            scored_payloads.append((payload, score))
        
        # Sort by score (highest first)
        ranked = sorted(scored_payloads, key=lambda x: x[1], reverse=True)
        
        self.ranked_payloads = ranked
        logger.info(f"Ranked {len(ranked)} payloads by effectiveness")
        
        return ranked
    
    def _calculate_payload_score(self, stats: Dict, success_rate: float) -> float:
        """
        Calculate effectiveness score for a payload.
        
        Args:
            stats: Payload statistics
            success_rate: Success rate for this payload
        
        Returns:
            Effectiveness score (0.0-1.0)
        """
        # Factors:
        # 1. Success rate (60% weight)
        # 2. Speed (faster is better) (20% weight)
        # 3. Reliability (more uses = more reliable) (20% weight)
        
        # Success rate component
        success_component = success_rate * 0.6
        
        # Speed component (normalize response time, lower is better)
        # Assume average response time of 1 second, max of 10 seconds
        avg_time = stats['avg_response_time']
        if avg_time > 0:
            speed_score = max(0, 1 - (avg_time / 10.0))
        else:
            speed_score = 0.5  # Neutral if no timing data
        speed_component = speed_score * 0.2
        
        # Reliability component (based on number of uses)
        # Use logarithmic scale, max out at 100 uses
        uses = stats['total_uses']
        reliability_score = min(1.0, (uses / 100.0) ** 0.5)  # Square root for smoother curve
        reliability_component = reliability_score * 0.2
        
        total_score = success_component + speed_component + reliability_component
        
        return total_score
    
    def get_optimal_payloads(self, count: int = 10, **filters) -> List[str]:
        """
        Get optimal payloads for testing.
        
        Args:
            count: Number of payloads to return
            **filters: Filters (context, db_type)
        
        Returns:
            List of optimal payloads
        """
        ranked = self.get_ranked_payloads(**filters)
        
        # Return top N payloads
        return [payload for payload, score in ranked[:count]]
    
    def create_target_profile(self, target_url: str, characteristics: Dict[str, Any]):
        """
        Create a profile for a target.
        
        Args:
            target_url: Target URL
            characteristics: Target characteristics (db_type, waf_detected, etc.)
        """
        self.target_profiles[target_url] = {
            'characteristics': characteristics,
            'optimal_payloads': [],
            'last_updated': None,
        }
        
        logger.info(f"Created target profile for: {target_url}")
    
    def update_target_profile(self, target_url: str, optimal_payloads: List[str]):
        """Update target profile with optimal payloads"""
        if target_url in self.target_profiles:
            self.target_profiles[target_url]['optimal_payloads'] = optimal_payloads
            self.target_profiles[target_url]['last_updated'] = None  # Would use datetime
    
    def get_recommendations(self, context: Optional[str] = None,
                          db_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Get payload recommendations based on current data.
        
        Args:
            context: Context filter
            db_type: Database type filter
        
        Returns:
            Recommendations dictionary
        """
        ranked = self.get_ranked_payloads(context=context, db_type=db_type, min_uses=1)
        
        if not ranked:
            return {
                'status': 'insufficient_data',
                'recommendations': [],
                'message': 'Not enough data to provide recommendations'
            }
        
        # Top performers
        top_payloads = ranked[:5]
        
        # Statistics
        if self.payload_stats:
            all_success_rates = [stats['success_rate'] for stats in self.payload_stats.values() 
                                if stats['total_uses'] > 0]
            avg_success_rate = statistics.mean(all_success_rates) if all_success_rates else 0
        else:
            avg_success_rate = 0
        
        return {
            'status': 'success',
            'top_payloads': [
                {
                    'payload': payload,
                    'score': score,
                    'stats': self.payload_stats[payload]
                }
                for payload, score in top_payloads
            ],
            'average_success_rate': avg_success_rate,
            'total_payloads_tracked': len(self.payload_stats),
            'recommendations': self._generate_recommendations(ranked, avg_success_rate)
        }
    
    def _generate_recommendations(self, ranked: List[Tuple[str, float]], 
                                 avg_success_rate: float) -> List[str]:
        """Generate textual recommendations"""
        recommendations = []
        
        if not ranked:
            recommendations.append("Collect more data by testing various payloads")
            return recommendations
        
        top_payload, top_score = ranked[0]
        
        if top_score > 0.8:
            recommendations.append(f"Payload '{top_payload[:50]}...' has excellent success rate ({top_score:.1%})")
            recommendations.append("Focus on similar payload patterns for faster detection")
        elif top_score > 0.5:
            recommendations.append(f"Best payload has moderate success ({top_score:.1%})")
            recommendations.append("Consider trying different injection contexts")
        else:
            recommendations.append("Low success rates detected")
            recommendations.append("Target may have strong protections or payloads need adjustment")
        
        if avg_success_rate < 0.3:
            recommendations.append("Consider enabling stealth mode and WAF bypass techniques")
        
        return recommendations
    
    def export_stats(self) -> Dict[str, Any]:
        """Export all statistics"""
        return {
            'payload_stats': dict(self.payload_stats),
            'target_profiles': self.target_profiles,
            'ranked_payloads': self.ranked_payloads,
        }
    
    def import_stats(self, data: Dict[str, Any]):
        """Import statistics from previous runs"""
        if 'payload_stats' in data:
            for payload, stats in data['payload_stats'].items():
                self.payload_stats[payload] = stats
        
        if 'target_profiles' in data:
            self.target_profiles = data['target_profiles']
        
        logger.info("Imported payload statistics")
    
    def generate_report(self) -> str:
        """Generate optimization report"""
        report = []
        report.append("=" * 60)
        report.append("PAYLOAD OPTIMIZATION REPORT")
        report.append("=" * 60)
        
        total_payloads = len(self.payload_stats)
        report.append(f"\nTotal Payloads Tracked: {total_payloads}")
        
        if total_payloads > 0:
            # Overall statistics
            total_uses = sum(s['total_uses'] for s in self.payload_stats.values())
            total_successes = sum(s['successes'] for s in self.payload_stats.values())
            overall_success = total_successes / total_uses if total_uses > 0 else 0
            
            report.append(f"Total Payload Uses: {total_uses}")
            report.append(f"Overall Success Rate: {overall_success:.1%}")
            
            # Top performers
            ranked = self.get_ranked_payloads(min_uses=1)
            if ranked:
                report.append(f"\nTop 5 Performing Payloads:")
                for i, (payload, score) in enumerate(ranked[:5], 1):
                    stats = self.payload_stats[payload]
                    report.append(f"\n{i}. Score: {score:.3f}")
                    report.append(f"   Payload: {payload[:60]}...")
                    report.append(f"   Success Rate: {stats['success_rate']:.1%} ({stats['successes']}/{stats['total_uses']})")
                    report.append(f"   Avg Response Time: {stats['avg_response_time']:.2f}s")
        else:
            report.append("\nNo payload data collected yet")
        
        report.append("\n" + "=" * 60)
        return "\n".join(report)
