"""
Fuzzy Logic Detection Module

Implements fuzzy logic-based detection to reduce false positives through:
- Similarity scoring across response patterns
- Header/content anomaly detection with fuzzy matching
- Error signature fuzziness
- Multi-dimensional confidence scoring
- Tolerance for ambiguous yet suspicious responses
"""

import logging
import difflib
import re
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class ResponseSignature:
    """Signature of a response for fuzzy matching"""
    status_code: int
    content_length: int
    content_hash: str
    header_fingerprint: str
    error_patterns: List[str]
    timing_ms: float
    unique_markers: Set[str]


@dataclass
class FuzzyMatch:
    """Result of a fuzzy matching operation"""
    similarity_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    matched_patterns: List[str]
    anomaly_indicators: List[str]
    verdict: str  # "vulnerable", "suspicious", "not_vulnerable", "uncertain"


class FuzzyLogicDetector:
    """
    Fuzzy logic-based detection system for SQL injection.
    
    Uses similarity scoring and pattern fuzzing to reduce false positives
    while maintaining detection of true vulnerabilities.
    """
    
    def __init__(self, similarity_threshold: float = 0.85, 
                 confidence_threshold: float = 0.70):
        """
        Initialize fuzzy logic detector.
        
        Args:
            similarity_threshold: Threshold for considering responses similar (0-1)
            confidence_threshold: Minimum confidence for positive detection (0-1)
        """
        self.similarity_threshold = similarity_threshold
        self.confidence_threshold = confidence_threshold
        
        # Baseline responses for comparison
        self.baseline_signatures: List[ResponseSignature] = []
        
        # Known error patterns with fuzzy matching
        self.error_patterns = self._initialize_error_patterns()
        
        # Response history for pattern learning
        self.response_history: List[ResponseSignature] = []
        
        # Anomaly weights for different indicators
        self.anomaly_weights = {
            'sql_error': 0.4,
            'content_length_change': 0.2,
            'header_anomaly': 0.15,
            'timing_anomaly': 0.15,
            'status_code_change': 0.1,
        }
    
    def _initialize_error_patterns(self) -> Dict[str, List[str]]:
        """Initialize SQL error patterns with fuzzy variations"""
        return {
            'mysql': [
                r"you have an error in your sql syntax",
                r"warning.*mysql",
                r"mysql_fetch",
                r"mysql_num_rows",
                r"supplied argument is not a valid mysql",
                r"unclosed quotation mark",
                r"syntax error.*near",
            ],
            'postgresql': [
                r"postgresql.*error",
                r"pg_query",
                r"pg_exec",
                r"supplied argument.*pg_",
                r"syntax error at or near",
                r"unterminated.*quoted",
            ],
            'mssql': [
                r"microsoft.*sql.*server",
                r"odbc.*sql.*server",
                r"sql server.*driver",
                r"unclosed quotation mark after the character string",
                r"incorrect syntax near",
                r"\[sql server\]",
            ],
            'oracle': [
                r"ora-\d+",
                r"oracle.*error",
                r"quoted string not properly terminated",
                r"sql command not properly ended",
            ],
            'sqlite': [
                r"sqlite.*error",
                r"sqlite3.*operationalerror",
                r"unrecognized token",
                r"near.*syntax error",
            ],
            'generic': [
                r"sql.*error",
                r"database.*error",
                r"syntax error",
                r"unterminated.*string",
                r"unexpected.*end.*input",
            ],
        }
    
    def set_baseline(self, status_code: int, headers: Dict[str, str],
                     body: str, response_time: float) -> None:
        """
        Set baseline response for comparison.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            response_time: Response time in seconds
        """
        signature = self._create_signature(status_code, headers, body, response_time)
        self.baseline_signatures.append(signature)
        logger.info(f"Baseline set: status={status_code}, length={len(body)}, time={response_time:.3f}s")
    
    def analyze_response(self, status_code: int, headers: Dict[str, str],
                        body: str, response_time: float, payload: str) -> FuzzyMatch:
        """
        Analyze a response using fuzzy logic.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            response_time: Response time in seconds
            payload: The payload that was used
            
        Returns:
            FuzzyMatch object with analysis results
        """
        # Create signature for this response
        signature = self._create_signature(status_code, headers, body, response_time)
        
        # Add to history
        self.response_history.append(signature)
        
        # Multi-dimensional analysis
        similarity_score = self._calculate_similarity(signature)
        error_score = self._detect_error_patterns(body)
        anomaly_score = self._detect_anomalies(signature)
        timing_score = self._analyze_timing(signature)
        
        # Fuzzy aggregation of scores
        confidence = self._fuzzy_aggregate([
            (error_score, self.anomaly_weights['sql_error']),
            (anomaly_score, self.anomaly_weights['content_length_change']),
            (timing_score, self.anomaly_weights['timing_anomaly']),
        ])
        
        # Determine verdict using fuzzy logic
        verdict = self._fuzzy_verdict(similarity_score, error_score, anomaly_score, confidence)
        
        # Collect matched patterns and indicators
        matched_patterns = self._get_matched_patterns(body)
        anomaly_indicators = self._get_anomaly_indicators(signature)
        
        return FuzzyMatch(
            similarity_score=similarity_score,
            confidence=confidence,
            matched_patterns=matched_patterns,
            anomaly_indicators=anomaly_indicators,
            verdict=verdict
        )
    
    def _create_signature(self, status_code: int, headers: Dict[str, str],
                         body: str, response_time: float) -> ResponseSignature:
        """Create a response signature"""
        # Calculate content hash
        content_hash = hashlib.md5(body.encode()).hexdigest()
        
        # Create header fingerprint
        important_headers = ['content-type', 'server', 'x-powered-by', 'set-cookie']
        header_str = '|'.join([
            f"{k}:{headers.get(k, '')}"
            for k in important_headers
        ])
        header_fingerprint = hashlib.md5(header_str.encode()).hexdigest()
        
        # Extract unique markers from body
        unique_markers = self._extract_unique_markers(body)
        
        # Find error patterns
        error_patterns = []
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    error_patterns.append(f"{db_type}:{pattern}")
        
        return ResponseSignature(
            status_code=status_code,
            content_length=len(body),
            content_hash=content_hash,
            header_fingerprint=header_fingerprint,
            error_patterns=error_patterns,
            timing_ms=response_time * 1000,
            unique_markers=unique_markers
        )
    
    def _extract_unique_markers(self, body: str) -> Set[str]:
        """Extract unique markers from response body"""
        markers = set()
        
        # Look for specific HTML elements, error codes, etc.
        # Extract titles
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
        if title_match:
            markers.add(f"title:{title_match.group(1)[:50]}")
        
        # Extract error codes
        error_codes = re.findall(r'\b(?:error|err)[:\s]*(\d+)\b', body, re.IGNORECASE)
        for code in error_codes[:5]:
            markers.add(f"error_code:{code}")
        
        # Extract server banners
        server_match = re.search(r'(apache|nginx|iis|lighttpd)/[\d.]+', body, re.IGNORECASE)
        if server_match:
            markers.add(f"server:{server_match.group(0)}")
        
        return markers
    
    def _calculate_similarity(self, signature: ResponseSignature) -> float:
        """
        Calculate similarity to baseline responses.
        
        Uses fuzzy matching to compare response signatures.
        """
        if not self.baseline_signatures:
            return 0.5  # No baseline, neutral score
        
        # Compare with each baseline
        similarities = []
        for baseline in self.baseline_signatures:
            # Content similarity
            if baseline.content_hash == signature.content_hash:
                content_sim = 1.0
            else:
                # Use length difference as proxy for content similarity
                len_diff = abs(baseline.content_length - signature.content_length)
                max_len = max(baseline.content_length, signature.content_length)
                content_sim = 1.0 - (len_diff / max_len) if max_len > 0 else 0.5
            
            # Header similarity
            header_sim = 1.0 if baseline.header_fingerprint == signature.header_fingerprint else 0.5
            
            # Status code similarity
            status_sim = 1.0 if baseline.status_code == signature.status_code else 0.0
            
            # Marker overlap
            if baseline.unique_markers and signature.unique_markers:
                common_markers = baseline.unique_markers & signature.unique_markers
                marker_sim = len(common_markers) / len(baseline.unique_markers | signature.unique_markers)
            else:
                marker_sim = 0.5
            
            # Weighted average
            overall_sim = (
                content_sim * 0.4 +
                header_sim * 0.2 +
                status_sim * 0.2 +
                marker_sim * 0.2
            )
            
            similarities.append(overall_sim)
        
        # Return average similarity to baselines
        return sum(similarities) / len(similarities)
    
    def _detect_error_patterns(self, body: str) -> float:
        """
        Detect SQL error patterns with fuzzy matching.
        
        Returns score from 0 (no errors) to 1 (definite error)
        """
        error_score = 0.0
        matches = []
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    matches.append((db_type, pattern))
                    error_score += 0.3  # Accumulate score
        
        # Apply fuzzy logic - multiple matches increase confidence
        if len(matches) >= 3:
            error_score = min(1.0, error_score * 1.2)  # Boost for multiple matches
        elif len(matches) == 2:
            error_score = min(1.0, error_score * 1.1)
        
        return min(1.0, error_score)
    
    def _detect_anomalies(self, signature: ResponseSignature) -> float:
        """
        Detect anomalies compared to baseline.
        
        Returns anomaly score from 0 (normal) to 1 (highly anomalous)
        """
        if not self.baseline_signatures:
            return 0.0
        
        anomaly_score = 0.0
        
        baseline = self.baseline_signatures[0]  # Use first baseline
        
        # Length anomaly (fuzzy)
        len_diff = abs(baseline.content_length - signature.content_length)
        if baseline.content_length > 0:
            len_change_pct = len_diff / baseline.content_length
            if len_change_pct > 0.3:  # >30% change
                anomaly_score += 0.4
            elif len_change_pct > 0.1:  # >10% change
                anomaly_score += 0.2
        
        # Status code anomaly
        if baseline.status_code != signature.status_code:
            anomaly_score += 0.3
        
        # Header anomaly
        if baseline.header_fingerprint != signature.header_fingerprint:
            anomaly_score += 0.2
        
        # Error pattern presence
        if signature.error_patterns:
            anomaly_score += 0.5
        
        return min(1.0, anomaly_score)
    
    def _analyze_timing(self, signature: ResponseSignature) -> float:
        """
        Analyze timing anomalies.
        
        Returns score from 0 (normal timing) to 1 (anomalous timing)
        """
        if not self.baseline_signatures:
            return 0.0
        
        baseline = self.baseline_signatures[0]
        
        # Calculate timing difference
        timing_diff = abs(baseline.timing_ms - signature.timing_ms)
        
        # Fuzzy timing analysis
        if timing_diff > 5000:  # >5 second difference
            return 0.9
        elif timing_diff > 3000:  # >3 second difference
            return 0.7
        elif timing_diff > 1000:  # >1 second difference
            return 0.4
        elif timing_diff > 500:  # >0.5 second difference
            return 0.2
        
        return 0.0
    
    def _fuzzy_aggregate(self, scores_and_weights: List[Tuple[float, float]]) -> float:
        """
        Aggregate multiple scores using fuzzy logic.
        
        Uses weighted average with non-linear scaling.
        """
        if not scores_and_weights:
            return 0.0
        
        # Weighted sum
        total_score = sum(score * weight for score, weight in scores_and_weights)
        total_weight = sum(weight for _, weight in scores_and_weights)
        
        if total_weight == 0:
            return 0.0
        
        # Normalize
        normalized = total_score / total_weight
        
        # Apply fuzzy membership function (S-curve)
        # This creates smooth transitions rather than hard thresholds
        if normalized < 0.3:
            return normalized * 0.5  # Low scores stay low
        elif normalized > 0.7:
            return 0.5 + (normalized - 0.7) * 1.67  # High scores amplified
        else:
            return 0.15 + (normalized - 0.3) * 0.875  # Middle range
        
        return min(1.0, max(0.0, normalized))
    
    def _fuzzy_verdict(self, similarity: float, error_score: float,
                       anomaly_score: float, confidence: float) -> str:
        """
        Determine verdict using fuzzy logic rules.
        
        Implements fuzzy inference system with linguistic variables.
        """
        # Define fuzzy membership functions
        def high(x): return max(0, min(1, (x - 0.6) / 0.3))
        def medium(x): return max(0, min((x - 0.3) / 0.2, (0.7 - x) / 0.2))
        def low(x): return max(0, min(1, (0.4 - x) / 0.3))
        
        # Evaluate membership
        error_high = high(error_score)
        error_medium = medium(error_score)
        error_low = low(error_score)
        
        anomaly_high = high(anomaly_score)
        anomaly_medium = medium(anomaly_score)
        anomaly_low = low(anomaly_score)
        
        sim_low = low(similarity)
        sim_medium = medium(similarity)
        
        # Fuzzy rules
        vulnerable = max(
            min(error_high, anomaly_high),  # High error AND high anomaly
            min(error_high, sim_low),  # High error AND low similarity
        )
        
        suspicious = max(
            min(error_medium, anomaly_medium),
            min(error_high, anomaly_low),
            min(error_low, anomaly_high),
        )
        
        not_vulnerable = max(
            min(error_low, anomaly_low),
            min(error_low, sim_medium),
        )
        
        # Defuzzification - choose verdict with highest membership
        memberships = [
            (vulnerable, "vulnerable"),
            (suspicious, "suspicious"),
            (not_vulnerable, "not_vulnerable"),
        ]
        
        memberships.sort(key=lambda x: x[0], reverse=True)
        
        # If confidence is low, report as uncertain
        if confidence < self.confidence_threshold:
            return "uncertain"
        
        return memberships[0][1]
    
    def _get_matched_patterns(self, body: str) -> List[str]:
        """Get list of matched error patterns"""
        patterns = []
        for db_type, pattern_list in self.error_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, body, re.IGNORECASE):
                    patterns.append(f"{db_type}:{pattern}")
        return patterns
    
    def _get_anomaly_indicators(self, signature: ResponseSignature) -> List[str]:
        """Get list of anomaly indicators"""
        indicators = []
        
        if not self.baseline_signatures:
            return indicators
        
        baseline = self.baseline_signatures[0]
        
        # Check for various anomalies
        if abs(baseline.content_length - signature.content_length) > baseline.content_length * 0.3:
            indicators.append(f"Large content length change: {baseline.content_length} -> {signature.content_length}")
        
        if baseline.status_code != signature.status_code:
            indicators.append(f"Status code change: {baseline.status_code} -> {signature.status_code}")
        
        if signature.error_patterns:
            indicators.append(f"SQL error patterns detected: {len(signature.error_patterns)}")
        
        timing_diff = abs(baseline.timing_ms - signature.timing_ms)
        if timing_diff > 1000:
            indicators.append(f"Timing anomaly: {timing_diff:.0f}ms difference")
        
        return indicators
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            'baseline_count': len(self.baseline_signatures),
            'response_history_count': len(self.response_history),
            'similarity_threshold': self.similarity_threshold,
            'confidence_threshold': self.confidence_threshold,
            'error_pattern_count': sum(len(p) for p in self.error_patterns.values()),
        }


if __name__ == "__main__":
    # Test the fuzzy logic detector
    logging.basicConfig(level=logging.INFO)
    
    detector = FuzzyLogicDetector()
    
    # Set baseline
    detector.set_baseline(
        status_code=200,
        headers={'content-type': 'text/html'},
        body="<html><body>Normal response</body></html>",
        response_time=0.1
    )
    
    # Test with SQL error
    result = detector.analyze_response(
        status_code=200,
        headers={'content-type': 'text/html'},
        body="<html><body>Error: You have an error in your SQL syntax</body></html>",
        response_time=0.15,
        payload="' OR 1=1--"
    )
    
    print(f"\n=== Fuzzy Logic Detection Result ===")
    print(f"Similarity: {result.similarity_score:.2f}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"Verdict: {result.verdict}")
    print(f"Matched patterns: {len(result.matched_patterns)}")
    print(f"Anomaly indicators: {result.anomaly_indicators}")
