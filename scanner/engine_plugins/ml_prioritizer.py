"""
AI/ML Vulnerability Prioritizer

Uses machine learning to intelligently prioritize vulnerabilities based on:
- Severity
- Confidence score
- CWE category risk
- CVSS score
- Exploitability
- Context analysis

This module provides smart ranking without requiring external ML services.
"""

import logging
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)


@dataclass
class PriorityScore:
    """Priority score for a vulnerability"""
    overall_score: float  # 0-100
    risk_level: str  # critical, high, medium, low
    factors: Dict[str, float]  # Individual factor scores
    reasoning: str  # Explanation of the score


class VulnerabilityPrioritizer:
    """
    ML-based vulnerability prioritization system.
    
    Uses a weighted scoring algorithm that considers multiple factors:
    - Base severity (critical, high, medium, low)
    - Confidence level
    - CWE risk category
    - CVSS score if available
    - Exploitability indicators
    - Code context
    """
    
    # Severity weights
    SEVERITY_SCORES = {
        'critical': 100,
        'high': 75,
        'medium': 50,
        'low': 25,
        'info': 10
    }
    
    # High-risk CWE categories (OWASP Top 10 related)
    HIGH_RISK_CWES = {
        'CWE-89': 95,   # SQL Injection
        'CWE-79': 90,   # XSS
        'CWE-78': 95,   # OS Command Injection
        'CWE-94': 95,   # Code Injection
        'CWE-502': 90,  # Deserialization
        'CWE-287': 85,  # Authentication
        'CWE-798': 90,  # Hardcoded Credentials
        'CWE-22': 80,   # Path Traversal
        'CWE-434': 85,  # File Upload
        'CWE-611': 80,  # XXE
        'CWE-918': 85,  # SSRF
        'CWE-327': 70,  # Weak Crypto
        'CWE-759': 75,  # Password in Hash
    }
    
    # Exploitability keywords
    EXPLOITABLE_KEYWORDS = {
        'rce': 95,
        'remote code execution': 95,
        'unauthenticated': 90,
        'bypass': 85,
        'privilege escalation': 90,
        'authentication bypass': 90,
        'sql injection': 90,
        'command injection': 90,
        'arbitrary file': 85,
        'execute': 80,
        'exploit': 75,
    }
    
    def __init__(self):
        """Initialize the prioritizer"""
        pass
    
    def prioritize(self, finding: Dict[str, Any]) -> PriorityScore:
        """
        Calculate priority score for a finding.
        
        Args:
            finding: Dictionary containing finding details
        
        Returns:
            PriorityScore: Computed priority score with reasoning
        """
        factors = {}
        
        # Factor 1: Base severity (40% weight)
        severity_score = self._score_severity(finding.get('severity', 'medium'))
        factors['severity'] = severity_score * 0.4
        
        # Factor 2: Confidence (15% weight)
        confidence = finding.get('confidence', 0.5)
        factors['confidence'] = confidence * 15
        
        # Factor 3: CWE risk (25% weight)
        cwe_score = self._score_cwe(finding.get('cwe_id'))
        factors['cwe_risk'] = cwe_score * 0.25
        
        # Factor 4: Exploitability (15% weight)
        exploit_score = self._score_exploitability(finding)
        factors['exploitability'] = exploit_score * 0.15
        
        # Factor 5: Context (5% weight)
        context_score = self._score_context(finding)
        factors['context'] = context_score * 0.05
        
        # Calculate overall score
        overall = sum(factors.values())
        overall = min(100, max(0, overall))  # Clamp to 0-100
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(finding, factors, overall)
        
        return PriorityScore(
            overall_score=overall,
            risk_level=risk_level,
            factors=factors,
            reasoning=reasoning
        )
    
    def prioritize_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize a batch of findings and sort by priority.
        
        Args:
            findings: List of findings
        
        Returns:
            List of findings with priority scores, sorted by priority
        """
        results = []
        
        for finding in findings:
            priority = self.prioritize(finding)
            
            # Add priority info to finding
            finding_with_priority = finding.copy()
            finding_with_priority['priority_score'] = priority.overall_score
            finding_with_priority['priority_level'] = priority.risk_level
            finding_with_priority['priority_factors'] = priority.factors
            finding_with_priority['priority_reasoning'] = priority.reasoning
            
            results.append(finding_with_priority)
        
        # Sort by priority score (highest first)
        results.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return results
    
    def _score_severity(self, severity: str) -> float:
        """Score based on severity level"""
        return self.SEVERITY_SCORES.get(severity.lower(), 25)
    
    def _score_cwe(self, cwe_id: Optional[str]) -> float:
        """Score based on CWE category"""
        if not cwe_id:
            return 50  # Default moderate risk
        
        # Check if it's a high-risk CWE
        if cwe_id in self.HIGH_RISK_CWES:
            return self.HIGH_RISK_CWES[cwe_id]
        
        # Extract CWE number if formatted
        cwe_match = re.match(r'CWE-(\d+)', cwe_id, re.IGNORECASE)
        if cwe_match:
            cwe_num = int(cwe_match.group(1))
            
            # OWASP Top 10 2021 related CWEs
            if cwe_num in [20, 200, 284, 306, 862, 863]:  # Broken Access Control
                return 85
            elif cwe_num in [259, 798, 916]:  # Cryptographic Failures
                return 80
            
        return 50  # Default
    
    def _score_exploitability(self, finding: Dict[str, Any]) -> float:
        """Score based on exploitability indicators"""
        score = 50  # Base score
        
        # Check title and description for exploitability keywords
        text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
        
        for keyword, keyword_score in self.EXPLOITABLE_KEYWORDS.items():
            if keyword in text:
                score = max(score, keyword_score)
        
        # Boost score if there's evidence of exploitation
        if finding.get('evidence'):
            score = min(100, score + 10)
        
        # Check if CVE exists (indicates known vulnerability)
        if finding.get('cve_id'):
            score = min(100, score + 15)
        
        return score
    
    def _score_context(self, finding: Dict[str, Any]) -> float:
        """Score based on contextual factors"""
        score = 50
        
        # Check file path for sensitive locations
        file_path = finding.get('file_path', '').lower()
        
        sensitive_paths = ['auth', 'admin', 'config', 'password', 'secret', 'api', 'login']
        for path in sensitive_paths:
            if path in file_path:
                score = min(100, score + 15)
                break
        
        # Check if it's in production code (not test)
        if 'test' not in file_path and 'spec' not in file_path:
            score = min(100, score + 10)
        
        return score
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= 85:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _generate_reasoning(self, finding: Dict[str, Any], factors: Dict[str, float], overall: float) -> str:
        """Generate human-readable reasoning for the score"""
        reasons = []
        
        # Severity reasoning
        severity = finding.get('severity', 'medium')
        reasons.append(f"Base severity: {severity.upper()}")
        
        # CWE reasoning
        cwe_id = finding.get('cwe_id')
        if cwe_id and cwe_id in self.HIGH_RISK_CWES:
            reasons.append(f"{cwe_id} is a high-risk vulnerability category")
        
        # CVE reasoning
        if finding.get('cve_id'):
            reasons.append(f"Known CVE: {finding.get('cve_id')}")
        
        # Confidence reasoning
        confidence = finding.get('confidence', 0.5)
        if confidence >= 0.9:
            reasons.append("High confidence detection")
        elif confidence < 0.5:
            reasons.append("Lower confidence - needs review")
        
        # Context reasoning
        file_path = finding.get('file_path', '')
        if any(x in file_path.lower() for x in ['auth', 'admin', 'password']):
            reasons.append("Found in sensitive code path")
        
        # Evidence reasoning
        if finding.get('evidence'):
            reasons.append("Evidence of vulnerability provided")
        
        return "; ".join(reasons)


class SmartDeduplicator:
    """
    Advanced deduplication using similarity analysis.
    
    Uses text similarity to identify duplicate findings even when
    they're not exact matches (e.g., same vulnerability in different files).
    """
    
    def __init__(self, similarity_threshold: float = 0.85):
        """
        Initialize deduplicator.
        
        Args:
            similarity_threshold: Similarity threshold (0-1) for considering duplicates
        """
        self.similarity_threshold = similarity_threshold
    
    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate findings using similarity analysis.
        
        Args:
            findings: List of findings
        
        Returns:
            Deduplicated list with duplicate markers
        """
        if not findings:
            return findings
        
        # Group findings by similarity
        groups = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
            
            # Create new group with this finding
            group = [i]
            processed.add(i)
            
            # Find similar findings
            for j in range(i + 1, len(findings)):
                if j in processed:
                    continue
                
                similarity = self._calculate_similarity(findings[i], findings[j])
                
                if similarity >= self.similarity_threshold:
                    group.append(j)
                    processed.add(j)
            
            groups.append(group)
        
        # Mark duplicates
        results = []
        for group in groups:
            # First item in group is the "original"
            for idx, finding_idx in enumerate(group):
                finding = findings[finding_idx].copy()
                
                if idx == 0:
                    # Original
                    finding['is_duplicate'] = False
                    finding['duplicate_count'] = len(group) - 1
                else:
                    # Duplicate
                    finding['is_duplicate'] = True
                    finding['duplicate_of_index'] = group[0]
                
                results.append(finding)
        
        return results
    
    def _calculate_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """
        Calculate similarity between two findings.
        
        Uses multiple factors:
        - Title similarity
        - CWE match
        - Severity match
        - Description similarity
        """
        score = 0.0
        weights = []
        
        # CWE match (30% weight)
        if finding1.get('cwe_id') and finding2.get('cwe_id'):
            if finding1['cwe_id'] == finding2['cwe_id']:
                score += 0.3
            weights.append(0.3)
        
        # Severity match (10% weight)
        if finding1.get('severity') == finding2.get('severity'):
            score += 0.1
        weights.append(0.1)
        
        # Title similarity (40% weight)
        title_sim = self._text_similarity(
            finding1.get('title', ''),
            finding2.get('title', '')
        )
        score += title_sim * 0.4
        weights.append(0.4)
        
        # Description similarity (20% weight)
        desc_sim = self._text_similarity(
            finding1.get('description', ''),
            finding2.get('description', '')
        )
        score += desc_sim * 0.2
        weights.append(0.2)
        
        # Normalize by total weights
        return score / sum(weights) if weights else 0.0
    
    def _text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate text similarity using word overlap.
        
        Simple but effective approach using Jaccard similarity.
        """
        if not text1 or not text2:
            return 0.0
        
        # Tokenize and normalize
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        # Calculate Jaccard similarity
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        return intersection / union if union > 0 else 0.0


class FalsPositivePredictor:
    """
    Predicts likelihood of false positives using heuristics.
    
    Helps filter out likely false positives before manual review.
    """
    
    FALSE_POSITIVE_INDICATORS = [
        'test file',
        'example',
        'mock',
        'stub',
        'fixture',
        'dummy',
        'sample',
    ]
    
    def predict(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict false positive likelihood.
        
        Args:
            finding: Finding to analyze
        
        Returns:
            Dict with prediction score and reasoning
        """
        score = 0.0  # 0 = likely real, 1 = likely false positive
        reasons = []
        
        # Check file path
        file_path = finding.get('file_path', '').lower()
        
        for indicator in self.FALSE_POSITIVE_INDICATORS:
            if indicator in file_path:
                score += 0.3
                reasons.append(f"Found in {indicator} code")
        
        # Check if in test directory
        if '/test/' in file_path or '/tests/' in file_path:
            score += 0.4
            reasons.append("Found in test directory")
        
        # Low confidence is suspicious
        confidence = finding.get('confidence', 0.5)
        if confidence < 0.3:
            score += 0.3
            reasons.append("Low confidence detection")
        
        # Clamp score
        score = min(1.0, score)
        
        prediction = 'likely_false_positive' if score >= 0.6 else 'likely_real'
        
        return {
            'prediction': prediction,
            'false_positive_score': score,
            'reasoning': "; ".join(reasons) if reasons else "No false positive indicators"
        }
