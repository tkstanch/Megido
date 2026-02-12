"""
Integration Module for World-Class Enhancements

This module provides integration utilities to add confidence scoring
and enhanced false positive filtering to existing vulnerability scanners.

Usage Example:
    from scanner.world_class_integration import WorldClassScanner
    
    scanner = WorldClassScanner(xss_plugin)
    result = scanner.scan_with_enhancements(target_url, config)
"""

import logging
from typing import Dict, Any, List, Optional
from scanner.confidence_engine import (
    ConfidenceEngine,
    ConfidenceFactors,
    ResponseAnalyzer,
    calculate_finding_confidence
)
from scanner.enhanced_fp_filter import EnhancedFalsePositiveFilter

logger = logging.getLogger(__name__)


class WorldClassScanner:
    """
    Wrapper that adds world-class enhancements to existing scanners.
    
    This class wraps existing vulnerability scanners and adds:
    - Confidence scoring for all findings
    - Enhanced false positive filtering
    - Detailed quality metrics
    """
    
    def __init__(self, 
                 base_scanner: Any,
                 enable_confidence_scoring: bool = True,
                 enable_fp_filtering: bool = True,
                 similarity_threshold: float = 0.95):
        """
        Initialize world-class scanner wrapper.
        
        Args:
            base_scanner: Base scanner plugin to wrap
            enable_confidence_scoring: Enable confidence scoring
            enable_fp_filtering: Enable false positive filtering
            similarity_threshold: Similarity threshold for FP filter
        """
        self.base_scanner = base_scanner
        self.enable_confidence_scoring = enable_confidence_scoring
        self.enable_fp_filtering = enable_fp_filtering
        
        # Initialize enhancements
        if enable_confidence_scoring:
            self.confidence_engine = ConfidenceEngine()
            self.response_analyzer = ResponseAnalyzer()
        
        if enable_fp_filtering:
            self.fp_filter = EnhancedFalsePositiveFilter(
                similarity_threshold=similarity_threshold,
                learning_enabled=True
            )
    
    def scan_with_enhancements(self,
                              target_url: str,
                              vulnerability_data: Dict[str, Any] = None,
                              config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute scan with world-class enhancements.
        
        Args:
            target_url: Target URL to scan
            vulnerability_data: Vulnerability-specific data
            config: Configuration dictionary
            
        Returns:
            Enhanced scan results with confidence scores and FP filtering
        """
        vulnerability_data = vulnerability_data or {}
        config = config or {}
        
        logger.info(f"Starting world-class scan of {target_url}")
        
        # Execute base scanner
        result = self.base_scanner.execute_attack(
            target_url=target_url,
            vulnerability_data=vulnerability_data,
            config=config
        )
        
        if not result.get('success'):
            return result
        
        # Enhance findings
        original_findings = result.get('findings', [])
        enhanced_findings = []
        filtered_count = 0
        
        for finding in original_findings:
            # Apply false positive filtering if enabled
            if self.enable_fp_filtering:
                is_fp, fp_reason = self._check_false_positive(finding, target_url)
                if is_fp:
                    logger.debug(f"Filtered false positive: {fp_reason}")
                    filtered_count += 1
                    finding['filtered_as_fp'] = True
                    finding['fp_reason'] = fp_reason
                    continue  # Skip this finding
            
            # Apply confidence scoring if enabled
            if self.enable_confidence_scoring:
                confidence_score = self._calculate_confidence(finding)
                finding['confidence_score_obj'] = confidence_score
                finding['confidence'] = confidence_score.normalized_score / 100.0  # 0-1
                finding['confidence_level'] = confidence_score.confidence_level.label
                finding['confidence_factors'] = confidence_score.factors.to_dict()
            
            enhanced_findings.append(finding)
        
        # Update result
        result['findings'] = enhanced_findings
        result['original_finding_count'] = len(original_findings)
        result['filtered_count'] = filtered_count
        result['enhanced'] = True
        
        # Add quality metrics
        result['quality_metrics'] = self._calculate_quality_metrics(enhanced_findings)
        
        logger.info(f"Enhanced scan complete: {len(enhanced_findings)}/{len(original_findings)} findings kept "
                   f"({filtered_count} filtered as false positives)")
        
        return result
    
    def _check_false_positive(self, finding: Dict[str, Any], url: str) -> tuple:
        """
        Check if finding is a false positive.
        
        Returns:
            Tuple of (is_fp: bool, reason: str)
        """
        # Create mock response from finding data
        mock_response = type('MockResponse', (), {})()
        mock_response.text = finding.get('evidence', '')
        mock_response.status_code = 200
        mock_response.headers = {}
        
        # Check with response analyzer first
        if self.response_analyzer.is_likely_false_positive(mock_response):
            return True, "Response matches false positive pattern"
        
        # Check with enhanced filter
        return self.fp_filter.is_false_positive(
            url=url,
            response=mock_response,
            payload=finding.get('payload', ''),
            vulnerability_type=finding.get('type', '')
        )
    
    def _calculate_confidence(self, finding: Dict[str, Any]) -> Any:
        """Calculate confidence score for finding"""
        # Extract factors from finding
        factors = ConfidenceFactors(
            payload_effectiveness=self._calculate_payload_effectiveness(finding),
            response_anomaly=finding.get('response_anomaly', 0.5),
            verification_success=1.0 if finding.get('verified', False) else 0.0,
            pattern_specificity=0.7,  # Could be calculated from pattern
            context_relevance=finding.get('context_relevance', 0.6),
            error_signature=self._detect_error_signatures(finding),
            timing_analysis=finding.get('timing_analysis', 0.0),
            consistency_check=0.7,  # Multiple successful tests
        )
        
        # Extract metadata
        metadata = {
            'verified': finding.get('verified', False),
            'waf_detected': self._detect_waf_in_finding(finding),
            'rate_limited': False,  # Would need response object
            'successful_payloads': 1,
            'timing_anomaly': False,
            'matches_fp_pattern': False,
        }
        
        return self.confidence_engine.calculate_confidence(
            factors=factors,
            vulnerability_type=finding.get('type', ''),
            metadata=metadata
        )
    
    def _calculate_payload_effectiveness(self, finding: Dict[str, Any]) -> float:
        """Calculate how effective the payload was"""
        # If verified, high effectiveness
        if finding.get('verified', False):
            return 0.9
        
        # Check if payload is in evidence
        evidence = finding.get('evidence', '')
        payload = finding.get('payload', '')
        
        if payload and payload in evidence:
            return 0.7
        
        # Check for error indicators
        if any(keyword in evidence.lower() for keyword in ['error', 'exception', 'failed']):
            return 0.6
        
        return 0.5
    
    def _detect_error_signatures(self, finding: Dict[str, Any]) -> float:
        """Detect error signatures in finding"""
        evidence = finding.get('evidence', '').lower()
        
        # SQL error signatures
        sql_errors = ['sql', 'mysql', 'postgres', 'oracle', 'syntax error', 'database']
        sql_score = sum(1 for e in sql_errors if e in evidence) / len(sql_errors)
        
        # Generic error signatures
        generic_errors = ['error', 'exception', 'warning', 'failed']
        generic_score = sum(1 for e in generic_errors if e in evidence) / len(generic_errors)
        
        return max(sql_score, generic_score)
    
    def _detect_waf_in_finding(self, finding: Dict[str, Any]) -> bool:
        """Detect if WAF is mentioned in finding"""
        evidence = finding.get('evidence', '').lower()
        waf_keywords = ['waf', 'cloudflare', 'firewall', 'blocked', 'security policy']
        return any(keyword in evidence for keyword in waf_keywords)
    
    def _calculate_quality_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate quality metrics for findings"""
        if not findings:
            return {
                'average_confidence': 0.0,
                'high_confidence_count': 0,
                'verified_count': 0,
                'quality_score': 0.0,
            }
        
        confidences = [f.get('confidence', 0.5) for f in findings]
        avg_confidence = sum(confidences) / len(confidences)
        
        high_confidence_count = sum(1 for c in confidences if c >= 0.75)
        verified_count = sum(1 for f in findings if f.get('verified', False))
        
        # Overall quality score (0-100)
        quality_score = (
            avg_confidence * 50 +  # Average confidence contributes 50%
            (high_confidence_count / len(findings)) * 30 +  # High confidence rate contributes 30%
            (verified_count / len(findings)) * 20  # Verification rate contributes 20%
        ) * 100
        
        return {
            'average_confidence': avg_confidence,
            'high_confidence_count': high_confidence_count,
            'verified_count': verified_count,
            'total_findings': len(findings),
            'quality_score': quality_score,
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics from all enhancement components"""
        stats = {
            'base_scanner': str(self.base_scanner.name if hasattr(self.base_scanner, 'name') else 'Unknown'),
            'confidence_scoring_enabled': self.enable_confidence_scoring,
            'fp_filtering_enabled': self.enable_fp_filtering,
        }
        
        if self.enable_fp_filtering:
            stats['fp_filter_stats'] = self.fp_filter.get_statistics()
        
        return stats


def enhance_scanner(scanner: Any,
                   enable_confidence: bool = True,
                   enable_fp_filter: bool = True) -> WorldClassScanner:
    """
    Convenience function to enhance an existing scanner.
    
    Args:
        scanner: Scanner to enhance
        enable_confidence: Enable confidence scoring
        enable_fp_filter: Enable false positive filtering
        
    Returns:
        Enhanced WorldClassScanner instance
    """
    return WorldClassScanner(
        base_scanner=scanner,
        enable_confidence_scoring=enable_confidence,
        enable_fp_filtering=enable_fp_filter
    )


# Example usage
def example_usage():
    """
    Example of how to use world-class enhancements.
    """
    from scanner.plugins import get_registry
    
    # Get the XSS plugin
    registry = get_registry()
    xss_plugin = registry.get_plugin('xss')
    
    # Enhance it with world-class capabilities
    enhanced_scanner = enhance_scanner(xss_plugin)
    
    # Run enhanced scan
    result = enhanced_scanner.scan_with_enhancements(
        target_url='http://example.com/search',
        vulnerability_data={'parameter': 'q', 'method': 'GET'},
        config={'enable_dom_testing': True}
    )
    
    # Check results
    print(f"Findings: {len(result['findings'])}")
    print(f"Filtered: {result['filtered_count']}")
    print(f"Quality Score: {result['quality_metrics']['quality_score']:.1f}/100")
    
    # Display findings with confidence
    for finding in result['findings']:
        confidence_pct = finding.get('confidence', 0.5) * 100
        conf_level = finding.get('confidence_level', 'Unknown')
        print(f"  - {finding['type']}: {conf_level} ({confidence_pct:.1f}%)")


if __name__ == '__main__':
    example_usage()
