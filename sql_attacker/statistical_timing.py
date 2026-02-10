"""
Statistical Timing Analysis Engine for Blind SQL Injection

Advanced statistical analysis of response times to reliably detect time-based
blind SQL injection with high accuracy and minimal false positives.
"""

import statistics
import time
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
import math
import logging

logger = logging.getLogger(__name__)


@dataclass
class TimingMeasurement:
    """Single timing measurement"""
    payload: str
    response_time: float
    status_code: int
    content_length: int
    timestamp: float
    baseline_deviation: float = 0.0


@dataclass
class TimingAnalysisResult:
    """Result of timing analysis"""
    is_vulnerable: bool
    confidence: float  # 0.0-1.0
    statistical_significance: float  # p-value
    measurements: List[TimingMeasurement]
    baseline_mean: float
    payload_mean: float
    effect_size: float  # Cohen's d
    analysis_method: str
    metadata: Dict[str, Any]


class StatisticalTimingAnalyzer:
    """
    Advanced statistical analyzer for time-based blind SQL injection.
    Uses multiple statistical tests and machine learning techniques.
    """
    
    def __init__(self, baseline_samples: int = 5, test_samples: int = 5,
                 confidence_threshold: float = 0.95, min_delay: float = 3.0):
        """
        Initialize statistical timing analyzer.
        
        Args:
            baseline_samples: Number of baseline measurements
            test_samples: Number of test payload measurements
            confidence_threshold: Minimum confidence for positive detection
            min_delay: Minimum expected delay in seconds
        """
        self.baseline_samples = baseline_samples
        self.test_samples = test_samples
        self.confidence_threshold = confidence_threshold
        self.min_delay = min_delay
        
        self.baseline_measurements = []
        self.test_measurements = []
        
        logger.info(f"Statistical timing analyzer initialized: samples={baseline_samples}/{test_samples}, threshold={confidence_threshold}")
    
    def add_baseline_measurement(self, response_time: float, status_code: int = 200,
                                 content_length: int = 0):
        """Add a baseline timing measurement"""
        measurement = TimingMeasurement(
            payload="baseline",
            response_time=response_time,
            status_code=status_code,
            content_length=content_length,
            timestamp=time.time()
        )
        self.baseline_measurements.append(measurement)
        logger.debug(f"Baseline measurement added: {response_time:.3f}s")
    
    def add_test_measurement(self, payload: str, response_time: float,
                            status_code: int = 200, content_length: int = 0):
        """Add a test payload timing measurement"""
        measurement = TimingMeasurement(
            payload=payload,
            response_time=response_time,
            status_code=status_code,
            content_length=content_length,
            timestamp=time.time()
        )
        self.test_measurements.append(measurement)
        logger.debug(f"Test measurement added: {response_time:.3f}s for payload: {payload[:50]}")
    
    def calculate_baseline_stats(self) -> Dict[str, float]:
        """Calculate baseline statistics"""
        if not self.baseline_measurements:
            return {'mean': 0.0, 'median': 0.0, 'std': 0.0, 'min': 0.0, 'max': 0.0}
        
        times = [m.response_time for m in self.baseline_measurements]
        
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'std': statistics.stdev(times) if len(times) > 1 else 0.0,
            'min': min(times),
            'max': max(times),
            'count': len(times)
        }
    
    def calculate_test_stats(self) -> Dict[str, float]:
        """Calculate test payload statistics"""
        if not self.test_measurements:
            return {'mean': 0.0, 'median': 0.0, 'std': 0.0, 'min': 0.0, 'max': 0.0}
        
        times = [m.response_time for m in self.test_measurements]
        
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'std': statistics.stdev(times) if len(times) > 1 else 0.0,
            'min': min(times),
            'max': max(times),
            'count': len(times)
        }
    
    def calculate_cohens_d(self, baseline_times: List[float], test_times: List[float]) -> float:
        """
        Calculate Cohen's d effect size.
        Measures the standardized difference between two means.
        
        Args:
            baseline_times: Baseline response times
            test_times: Test payload response times
        
        Returns:
            Cohen's d value (effect size)
        """
        if not baseline_times or not test_times:
            return 0.0
        
        mean1 = statistics.mean(baseline_times)
        mean2 = statistics.mean(test_times)
        
        if len(baseline_times) == 1 or len(test_times) == 1:
            # Can't calculate pooled std with single sample
            return abs(mean2 - mean1)
        
        std1 = statistics.stdev(baseline_times)
        std2 = statistics.stdev(test_times)
        
        # Pooled standard deviation
        n1 = len(baseline_times)
        n2 = len(test_times)
        pooled_std = math.sqrt(((n1 - 1) * std1**2 + (n2 - 1) * std2**2) / (n1 + n2 - 2))
        
        if pooled_std == 0:
            return 0.0
        
        cohens_d = (mean2 - mean1) / pooled_std
        return cohens_d
    
    def welchs_t_test(self, baseline_times: List[float], test_times: List[float]) -> Tuple[float, float]:
        """
        Perform Welch's t-test (doesn't assume equal variances).
        
        Args:
            baseline_times: Baseline response times
            test_times: Test payload response times
        
        Returns:
            Tuple of (t-statistic, p-value estimate)
        """
        if not baseline_times or not test_times:
            return 0.0, 1.0
        
        if len(baseline_times) < 2 or len(test_times) < 2:
            # Not enough samples for t-test
            return 0.0, 1.0
        
        mean1 = statistics.mean(baseline_times)
        mean2 = statistics.mean(test_times)
        var1 = statistics.variance(baseline_times)
        var2 = statistics.variance(test_times)
        n1 = len(baseline_times)
        n2 = len(test_times)
        
        # Welch's t-statistic
        numerator = mean2 - mean1
        denominator = math.sqrt(var1/n1 + var2/n2)
        
        if denominator == 0:
            return 0.0, 1.0
        
        t_stat = numerator / denominator
        
        # Degrees of freedom for Welch's test
        df = ((var1/n1 + var2/n2)**2) / ((var1/n1)**2/(n1-1) + (var2/n2)**2/(n2-1))
        
        # Simplified p-value estimation (for large t-stat, p is very small)
        # In practice, you'd use scipy.stats.t.sf(), but we avoid external deps
        if abs(t_stat) > 3:  # Very significant
            p_value = 0.001
        elif abs(t_stat) > 2:  # Significant
            p_value = 0.05
        elif abs(t_stat) > 1.5:  # Somewhat significant
            p_value = 0.15
        else:
            p_value = 0.5
        
        return t_stat, p_value
    
    def kolmogorov_smirnov_test(self, baseline_times: List[float], test_times: List[float]) -> float:
        """
        Simplified Kolmogorov-Smirnov test for distribution differences.
        
        Args:
            baseline_times: Baseline response times
            test_times: Test payload response times
        
        Returns:
            KS statistic (0-1, higher = more different)
        """
        if not baseline_times or not test_times:
            return 0.0
        
        # Sort both samples
        sorted_baseline = sorted(baseline_times)
        sorted_test = sorted(test_times)
        
        # Combine and sort all values
        all_values = sorted(set(sorted_baseline + sorted_test))
        
        max_diff = 0.0
        for value in all_values:
            # Empirical CDF for baseline
            cdf_baseline = sum(1 for x in sorted_baseline if x <= value) / len(sorted_baseline)
            # Empirical CDF for test
            cdf_test = sum(1 for x in sorted_test if x <= value) / len(sorted_test)
            
            diff = abs(cdf_baseline - cdf_test)
            max_diff = max(max_diff, diff)
        
        return max_diff
    
    def detect_outliers(self, times: List[float], threshold: float = 2.0) -> List[int]:
        """
        Detect outliers using modified Z-score method.
        
        Args:
            times: List of response times
            threshold: Z-score threshold for outliers
        
        Returns:
            List of indices of outliers
        """
        if len(times) < 3:
            return []
        
        median = statistics.median(times)
        mad = statistics.median([abs(t - median) for t in times])  # Median Absolute Deviation
        
        if mad == 0:
            return []
        
        modified_z_scores = [abs(0.6745 * (t - median) / mad) for t in times]
        outliers = [i for i, z in enumerate(modified_z_scores) if z > threshold]
        
        return outliers
    
    def analyze(self) -> TimingAnalysisResult:
        """
        Perform comprehensive statistical analysis.
        
        Returns:
            TimingAnalysisResult with detailed analysis
        """
        baseline_stats = self.calculate_baseline_stats()
        test_stats = self.calculate_test_stats()
        
        baseline_times = [m.response_time for m in self.baseline_measurements]
        test_times = [m.response_time for m in self.test_measurements]
        
        # Calculate effect size
        cohens_d = self.calculate_cohens_d(baseline_times, test_times)
        
        # Perform t-test
        t_stat, p_value = self.welchs_t_test(baseline_times, test_times)
        
        # KS test
        ks_stat = self.kolmogorov_smirnov_test(baseline_times, test_times)
        
        # Detect outliers
        baseline_outliers = self.detect_outliers(baseline_times)
        test_outliers = self.detect_outliers(test_times)
        
        # Calculate time difference
        time_diff = test_stats['mean'] - baseline_stats['mean']
        
        # Decision logic
        is_vulnerable = False
        confidence = 0.0
        
        # Multiple criteria for detection
        criteria_met = 0
        
        # Criterion 1: Mean difference meets minimum delay
        if time_diff >= self.min_delay * 0.8:  # 80% of expected delay
            criteria_met += 1
            confidence += 0.3
        
        # Criterion 2: Statistical significance (p-value)
        if p_value < 0.05:
            criteria_met += 1
            confidence += 0.3
        
        # Criterion 3: Large effect size (Cohen's d > 0.8 is large)
        if cohens_d > 0.8:
            criteria_met += 1
            confidence += 0.2
        
        # Criterion 4: Distribution difference (KS test)
        if ks_stat > 0.5:
            criteria_met += 1
            confidence += 0.1
        
        # Criterion 5: Consistent delay across samples
        if test_stats['std'] < test_stats['mean'] * 0.3:  # Low variance in test times
            criteria_met += 1
            confidence += 0.1
        
        # Require at least 3 criteria for positive detection
        if criteria_met >= 3:
            is_vulnerable = True
            confidence = min(confidence, 0.99)
        
        logger.info(f"Timing analysis: criteria_met={criteria_met}/5, confidence={confidence:.2f}, "
                   f"time_diff={time_diff:.2f}s, cohens_d={cohens_d:.2f}, p_value={p_value:.4f}")
        
        return TimingAnalysisResult(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            statistical_significance=p_value,
            measurements=self.baseline_measurements + self.test_measurements,
            baseline_mean=baseline_stats['mean'],
            payload_mean=test_stats['mean'],
            effect_size=cohens_d,
            analysis_method='multi_criteria_statistical',
            metadata={
                'baseline_stats': baseline_stats,
                'test_stats': test_stats,
                'time_difference': time_diff,
                'cohens_d': cohens_d,
                't_statistic': t_stat,
                'p_value': p_value,
                'ks_statistic': ks_stat,
                'criteria_met': criteria_met,
                'baseline_outliers': len(baseline_outliers),
                'test_outliers': len(test_outliers),
            }
        )
    
    def reset(self):
        """Reset measurements for new analysis"""
        self.baseline_measurements = []
        self.test_measurements = []
        logger.debug("Timing measurements reset")


class AdaptiveTimingAnalyzer:
    """
    Adaptive timing analyzer that learns optimal parameters from environment.
    """
    
    def __init__(self):
        self.network_latency = []
        self.server_response_times = []
        self.learned_baseline = None
    
    def learn_network_characteristics(self, measurements: List[TimingMeasurement]):
        """
        Learn network and server characteristics from measurements.
        
        Args:
            measurements: List of timing measurements
        """
        for m in measurements:
            self.network_latency.append(m.response_time)
        
        if len(self.network_latency) > 10:
            self.learned_baseline = statistics.median(self.network_latency)
            logger.info(f"Learned baseline response time: {self.learned_baseline:.3f}s")
    
    def get_adaptive_delay(self, target_delay: float = 5.0) -> float:
        """
        Get adaptive delay that accounts for network conditions.
        
        Args:
            target_delay: Desired delay in seconds
        
        Returns:
            Adjusted delay accounting for network latency
        """
        if self.learned_baseline:
            # Ensure delay is significantly above baseline
            return max(target_delay, self.learned_baseline * 3)
        return target_delay
    
    def get_adaptive_threshold(self) -> float:
        """
        Get adaptive threshold for time difference detection.
        
        Returns:
            Threshold in seconds
        """
        if self.learned_baseline:
            # Threshold should be at least 2x the baseline variance
            if len(self.network_latency) > 1:
                variance = statistics.stdev(self.network_latency)
                return max(3.0, self.learned_baseline + variance * 2)
        return 3.0


class TimingAttackOptimizer:
    """
    Optimizer for time-based attacks to reduce false positives and improve speed.
    """
    
    def __init__(self):
        self.successful_delays = []
        self.failed_delays = []
    
    def suggest_optimal_delay(self) -> float:
        """
        Suggest optimal delay based on past successes.
        
        Returns:
            Optimal delay in seconds
        """
        if self.successful_delays:
            # Use median of successful delays
            return statistics.median(self.successful_delays)
        return 5.0  # Default
    
    def suggest_sample_size(self, confidence_required: float = 0.95) -> int:
        """
        Suggest optimal number of samples needed.
        
        Args:
            confidence_required: Required confidence level
        
        Returns:
            Number of samples needed
        """
        # Higher confidence requires more samples
        if confidence_required >= 0.99:
            return 7
        elif confidence_required >= 0.95:
            return 5
        else:
            return 3
    
    def record_result(self, delay: float, success: bool):
        """Record attack result for optimization"""
        if success:
            self.successful_delays.append(delay)
        else:
            self.failed_delays.append(delay)
