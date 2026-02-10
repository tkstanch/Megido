"""
Advanced Vulnerability Scanner Module

This module extends the enhanced scanner with enterprise-grade features:
- Risk scoring and prioritization
- Incremental scanning with change tracking
- Advanced reporting (HTML, JSON, executive summaries)
- False positive management and learning
- Compliance framework mapping (GDPR, PCI-DSS, OWASP)
- Automated remediation suggestions
- Performance profiling and optimization
- Plugin system for extensibility
"""

import os
import json
import hashlib
import pickle
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set, Tuple, Callable
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
from collections import defaultdict
import re

# Import from enhanced scanner
from discover.sensitive_scanner_enhanced import (
    EnhancedSensitiveInfoScanner,
    PatternProvider,
    SensitivePatterns,
    ExternalPatternProvider,
    HeuristicScanner,
    ContextAnalyzer
)


# ============================================================================
# Risk Scoring System
# ============================================================================

class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class RiskScore:
    """Comprehensive risk score for a finding."""
    base_severity: str  # critical, high, medium, low
    context_factor: float  # 0.0 - 2.0 (config file = higher)
    exposure_factor: float  # 0.0 - 2.0 (public repo = higher)
    age_factor: float  # 0.0 - 1.0 (older = lower risk if not exploited)
    entropy_factor: float  # 0.0 - 1.0 (higher entropy = higher risk)
    composite_score: float = 0.0
    risk_level: str = "medium"
    
    def __post_init__(self):
        """Calculate composite risk score."""
        self.composite_score = self._calculate_composite()
        self.risk_level = self._determine_risk_level()
    
    def _calculate_composite(self) -> float:
        """
        Calculate composite risk score using weighted factors.
        
        Formula: base * (1 + context + exposure) * (1 + entropy) * age
        Range: 0-100
        """
        # Base severity scores
        severity_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        base = severity_scores.get(self.base_severity.lower(), 5.0)
        
        # Apply multiplicative factors
        context_mult = 1.0 + (self.context_factor * 0.5)
        exposure_mult = 1.0 + (self.exposure_factor * 0.5)
        entropy_mult = 1.0 + (self.entropy_factor * 0.3)
        
        score = base * context_mult * exposure_mult * entropy_mult * self.age_factor
        
        # Normalize to 0-100
        return min(100.0, max(0.0, score * 5))
    
    def _determine_risk_level(self) -> str:
        """Determine risk level from composite score."""
        if self.composite_score >= 80:
            return "critical"
        elif self.composite_score >= 60:
            return "high"
        elif self.composite_score >= 40:
            return "medium"
        elif self.composite_score >= 20:
            return "low"
        else:
            return "info"


class RiskScoringEngine:
    """Engine for calculating and managing risk scores."""
    
    def __init__(self, exposure_level: str = 'medium'):
        """
        Initialize risk scoring engine.
        
        Args:
            exposure_level: Overall exposure level (low/medium/high)
        """
        self.exposure_level = exposure_level
        self.exposure_factors = {
            'low': 0.5,
            'medium': 1.0,
            'high': 1.5
        }
    
    def calculate_risk_score(self, finding: Dict[str, Any]) -> RiskScore:
        """
        Calculate comprehensive risk score for a finding.
        
        Args:
            finding: Finding dictionary with metadata
            
        Returns:
            RiskScore object with composite score
        """
        # Extract base severity
        base_severity = finding.get('severity', 'medium')
        
        # Context factor (config files are higher risk)
        context_factor = 0.0
        if finding.get('source_type') == 'file':
            file_context = finding.get('file_context', {})
            if file_context.get('is_config_file'):
                context_factor = 2.0
            else:
                context_factor = 1.0
        else:
            context_factor = 1.5  # URLs have medium-high context risk
        
        # Exposure factor
        exposure_factor = self.exposure_factors.get(self.exposure_level, 1.0)
        
        # Age factor (newer findings are higher risk)
        age_factor = 1.0  # Default, could be calculated from file modification time
        
        # Entropy factor
        entropy_factor = 0.0
        if 'entropy' in finding:
            # Normalize entropy (typical range 0-8) to 0-1
            entropy_factor = min(1.0, finding['entropy'] / 8.0)
        elif finding.get('detection_method') == 'heuristic':
            entropy_factor = 0.7  # Heuristic findings likely have high entropy
        
        return RiskScore(
            base_severity=base_severity,
            context_factor=context_factor,
            exposure_factor=exposure_factor,
            age_factor=age_factor,
            entropy_factor=entropy_factor
        )
    
    def prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize findings by risk score.
        
        Args:
            findings: List of findings
            
        Returns:
            Sorted list with risk scores attached
        """
        scored_findings = []
        
        for finding in findings:
            risk_score = self.calculate_risk_score(finding)
            finding['risk_score'] = asdict(risk_score)
            scored_findings.append(finding)
        
        # Sort by composite score (descending)
        scored_findings.sort(
            key=lambda x: x['risk_score']['composite_score'],
            reverse=True
        )
        
        return scored_findings


# ============================================================================
# Incremental Scanning System
# ============================================================================

@dataclass
class FileState:
    """State of a scanned file."""
    path: str
    checksum: str
    last_scanned: datetime
    findings_count: int
    has_findings: bool


class IncrementalScanner:
    """
    Scanner that tracks file changes and only scans modified files.
    """
    
    def __init__(self, state_file: str = '.vuln_scan_state.pkl'):
        """
        Initialize incremental scanner.
        
        Args:
            state_file: Path to state persistence file
        """
        self.state_file = state_file
        self.file_states: Dict[str, FileState] = {}
        self._load_state()
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate MD5 checksum of file."""
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    def _load_state(self):
        """Load scan state from disk."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'rb') as f:
                    self.file_states = pickle.load(f)
            except Exception as e:
                logging.warning(f"Failed to load scan state: {e}")
                self.file_states = {}
    
    def _save_state(self):
        """Save scan state to disk."""
        try:
            with open(self.state_file, 'wb') as f:
                pickle.dump(self.file_states, f)
        except Exception as e:
            logging.error(f"Failed to save scan state: {e}")
    
    def has_file_changed(self, file_path: str) -> bool:
        """
        Check if file has changed since last scan.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file changed or never scanned, False otherwise
        """
        if file_path not in self.file_states:
            return True
        
        current_checksum = self._calculate_checksum(file_path)
        stored_checksum = self.file_states[file_path].checksum
        
        return current_checksum != stored_checksum
    
    def get_changed_files(self, file_paths: List[str]) -> List[str]:
        """
        Filter list to only files that have changed.
        
        Args:
            file_paths: List of file paths to check
            
        Returns:
            List of changed file paths
        """
        return [f for f in file_paths if self.has_file_changed(f)]
    
    def update_file_state(self, file_path: str, findings_count: int):
        """
        Update state for a scanned file.
        
        Args:
            file_path: Path to file
            findings_count: Number of findings in file
        """
        checksum = self._calculate_checksum(file_path)
        
        self.file_states[file_path] = FileState(
            path=file_path,
            checksum=checksum,
            last_scanned=datetime.now(),
            findings_count=findings_count,
            has_findings=findings_count > 0
        )
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get statistics about scanned files."""
        total_files = len(self.file_states)
        files_with_findings = sum(1 for s in self.file_states.values() if s.has_findings)
        total_findings = sum(s.findings_count for s in self.file_states.values())
        
        return {
            'total_files_tracked': total_files,
            'files_with_findings': files_with_findings,
            'total_findings': total_findings,
            'last_scan': max([s.last_scanned for s in self.file_states.values()], 
                            default=datetime.now())
        }
    
    def save(self):
        """Save current state to disk."""
        self._save_state()


# ============================================================================
# False Positive Management
# ============================================================================

@dataclass
class FindingClassification:
    """Classification of a finding by user."""
    finding_hash: str
    classification: str  # 'true_positive', 'false_positive', 'acceptable_risk'
    reason: str
    classified_by: str
    classified_at: datetime


class FalsePositiveManager:
    """
    Manage false positives and learn from user feedback.
    """
    
    def __init__(self, allowlist_file: str = '.vuln_scan_allowlist.json'):
        """
        Initialize false positive manager.
        
        Args:
            allowlist_file: Path to allowlist file
        """
        self.allowlist_file = allowlist_file
        self.allowlist: Dict[str, FindingClassification] = {}
        self.patterns_to_ignore: Set[str] = set()
        self._load_allowlist()
    
    def _finding_hash(self, finding: Dict[str, Any]) -> str:
        """Generate unique hash for a finding."""
        # Hash based on type, value, and source
        key = f"{finding['type']}:{finding['value']}:{finding.get('source', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def _load_allowlist(self):
        """Load allowlist from disk."""
        if os.path.exists(self.allowlist_file):
            try:
                with open(self.allowlist_file, 'r') as f:
                    data = json.load(f)
                    for item in data.get('classifications', []):
                        item['classified_at'] = datetime.fromisoformat(item['classified_at'])
                        classification = FindingClassification(**item)
                        self.allowlist[classification.finding_hash] = classification
                    
                    self.patterns_to_ignore = set(data.get('patterns_to_ignore', []))
            except Exception as e:
                logging.warning(f"Failed to load allowlist: {e}")
    
    def _save_allowlist(self):
        """Save allowlist to disk."""
        try:
            data = {
                'classifications': [
                    {
                        **asdict(c),
                        'classified_at': c.classified_at.isoformat()
                    }
                    for c in self.allowlist.values()
                ],
                'patterns_to_ignore': list(self.patterns_to_ignore)
            }
            
            with open(self.allowlist_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save allowlist: {e}")
    
    def classify_finding(self, finding: Dict[str, Any], classification: str,
                        reason: str, classified_by: str = 'user'):
        """
        Classify a finding as true/false positive.
        
        Args:
            finding: Finding dictionary
            classification: Classification type
            reason: Reason for classification
            classified_by: Who classified it
        """
        finding_hash = self._finding_hash(finding)
        
        self.allowlist[finding_hash] = FindingClassification(
            finding_hash=finding_hash,
            classification=classification,
            reason=reason,
            classified_by=classified_by,
            classified_at=datetime.now()
        )
        
        self._save_allowlist()
    
    def is_false_positive(self, finding: Dict[str, Any]) -> bool:
        """
        Check if finding is classified as false positive.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if false positive, False otherwise
        """
        finding_hash = self._finding_hash(finding)
        
        if finding_hash in self.allowlist:
            classification = self.allowlist[finding_hash]
            return classification.classification in ['false_positive', 'acceptable_risk']
        
        return False
    
    def filter_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out false positives from findings list.
        
        Args:
            findings: List of findings
            
        Returns:
            Filtered list without false positives
        """
        return [f for f in findings if not self.is_false_positive(f)]
    
    def add_pattern_to_ignore(self, pattern: str):
        """Add a pattern to the ignore list."""
        self.patterns_to_ignore.add(pattern)
        self._save_allowlist()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get false positive management statistics."""
        classifications = list(self.allowlist.values())
        
        return {
            'total_classified': len(classifications),
            'false_positives': sum(1 for c in classifications 
                                  if c.classification == 'false_positive'),
            'true_positives': sum(1 for c in classifications 
                                 if c.classification == 'true_positive'),
            'acceptable_risks': sum(1 for c in classifications 
                                   if c.classification == 'acceptable_risk'),
            'patterns_ignored': len(self.patterns_to_ignore)
        }


# ============================================================================
# Compliance Framework Mapping
# ============================================================================

class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    OWASP_TOP_10 = "owasp_top10"
    HIPAA = "hipaa"
    SOC2 = "soc2"


@dataclass
class ComplianceMapping:
    """Mapping of finding to compliance requirement."""
    framework: ComplianceFramework
    requirement_id: str
    requirement_name: str
    severity: str
    description: str


class ComplianceMapper:
    """
    Map findings to compliance framework requirements.
    """
    
    def __init__(self):
        """Initialize compliance mapper with framework mappings."""
        self.mappings = self._initialize_mappings()
    
    def _initialize_mappings(self) -> Dict[str, List[ComplianceMapping]]:
        """Initialize compliance framework mappings."""
        mappings = defaultdict(list)
        
        # GDPR Mappings
        sensitive_patterns = [
            'AWS Access Key', 'API Key', 'Password', 'Private Key',
            'Database Connection', 'JWT Token', 'Bearer Token'
        ]
        for pattern in sensitive_patterns:
            mappings[pattern].append(ComplianceMapping(
                framework=ComplianceFramework.GDPR,
                requirement_id="Art. 32",
                requirement_name="Security of Processing",
                severity="high",
                description="Personal data must be protected with appropriate technical measures"
            ))
        
        # PCI-DSS Mappings
        pci_patterns = [
            'Credit Card Number', 'AWS Access Key', 'API Key',
            'Password', 'Private Key'
        ]
        for pattern in pci_patterns:
            mappings[pattern].append(ComplianceMapping(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="Req 3.4",
                requirement_name="Protect Cardholder Data",
                severity="critical",
                description="Render PAN unreadable anywhere it is stored"
            ))
        
        # OWASP Top 10 Mappings
        owasp_patterns = [
            'AWS Access Key', 'API Key', 'Password', 'Private Key',
            'Secret', 'Token', 'Database Connection'
        ]
        for pattern in owasp_patterns:
            mappings[pattern].append(ComplianceMapping(
                framework=ComplianceFramework.OWASP_TOP_10,
                requirement_id="A02:2021",
                requirement_name="Cryptographic Failures",
                severity="high",
                description="Exposure of sensitive data due to weak cryptography"
            ))
        
        # HIPAA Mappings
        hipaa_patterns = [
            'SSN', 'Patient', 'Medical', 'Health',
            'Password', 'Private Key', 'API Key'
        ]
        for pattern in hipaa_patterns:
            mappings[pattern].append(ComplianceMapping(
                framework=ComplianceFramework.HIPAA,
                requirement_id="164.312(a)(2)(iv)",
                requirement_name="Encryption and Decryption",
                severity="high",
                description="Implement mechanisms to encrypt and decrypt ePHI"
            ))
        
        return dict(mappings)
    
    def get_compliance_mappings(self, finding: Dict[str, Any]) -> List[ComplianceMapping]:
        """
        Get compliance mappings for a finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            List of applicable compliance mappings
        """
        finding_type = finding.get('type', '')
        
        # Find mappings that match the finding type
        applicable_mappings = []
        
        for pattern, mappings in self.mappings.items():
            if pattern.lower() in finding_type.lower():
                applicable_mappings.extend(mappings)
        
        return applicable_mappings
    
    def generate_compliance_report(self, findings: List[Dict[str, Any]],
                                   framework: Optional[ComplianceFramework] = None) -> Dict[str, Any]:
        """
        Generate compliance report for findings.
        
        Args:
            findings: List of findings
            framework: Specific framework to report on (None for all)
            
        Returns:
            Compliance report dictionary
        """
        framework_findings = defaultdict(list)
        requirement_counts = defaultdict(int)
        
        for finding in findings:
            mappings = self.get_compliance_mappings(finding)
            
            for mapping in mappings:
                if framework is None or mapping.framework == framework:
                    framework_findings[mapping.framework.value].append({
                        'finding': finding,
                        'mapping': asdict(mapping)
                    })
                    requirement_counts[f"{mapping.framework.value}:{mapping.requirement_id}"] += 1
        
        return {
            'frameworks': dict(framework_findings),
            'requirement_counts': dict(requirement_counts),
            'total_violations': sum(requirement_counts.values()),
            'affected_frameworks': list(framework_findings.keys())
        }


# ============================================================================
# Remediation Engine
# ============================================================================

@dataclass
class RemediationSuggestion:
    """Suggested remediation for a finding."""
    finding_type: str
    action: str
    description: str
    code_snippet: Optional[str]
    effort_estimate: str  # 'low', 'medium', 'high'
    priority: int  # 1-5
    references: List[str]


class RemediationEngine:
    """
    Provide automated remediation suggestions for findings.
    """
    
    def __init__(self):
        """Initialize remediation engine with suggestion templates."""
        self.suggestions = self._initialize_suggestions()
    
    def _initialize_suggestions(self) -> Dict[str, RemediationSuggestion]:
        """Initialize remediation suggestion templates."""
        suggestions = {}
        
        # AWS Keys
        suggestions['AWS Access Key'] = RemediationSuggestion(
            finding_type='AWS Access Key',
            action='Move to environment variable or AWS Secrets Manager',
            description='Store AWS credentials securely using environment variables or AWS Secrets Manager',
            code_snippet='''# Before (INSECURE):
# aws_key = "AKIAIOSFODNN7EXAMPLE"

# After (SECURE):
import os
aws_key = os.environ.get('AWS_ACCESS_KEY_ID')

# Or use AWS Secrets Manager:
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='my/aws/key')''',
            effort_estimate='low',
            priority=5,
            references=[
                'https://docs.aws.amazon.com/secretsmanager/',
                'https://12factor.net/config'
            ]
        )
        
        # API Keys
        suggestions['Generic API Key'] = RemediationSuggestion(
            finding_type='Generic API Key',
            action='Move to environment variable or secrets management',
            description='Store API keys in environment variables or use a secrets manager',
            code_snippet='''# Before (INSECURE):
# api_key = "my-secret-key-12345"

# After (SECURE):
import os
api_key = os.environ.get('API_KEY')

# Or use dotenv for development:
from dotenv import load_dotenv
load_dotenv()
api_key = os.environ.get('API_KEY')''',
            effort_estimate='low',
            priority=4,
            references=[
                'https://pypi.org/project/python-dotenv/',
                'https://www.vaultproject.io/'
            ]
        )
        
        # Passwords
        suggestions['Password Field'] = RemediationSuggestion(
            finding_type='Password Field',
            action='Use secure password storage and hashing',
            description='Never store passwords in plain text. Use bcrypt, argon2, or similar',
            code_snippet='''# Before (INSECURE):
# password = "mypassword123"

# After (SECURE):
import bcrypt

# Storing password:
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verifying password:
if bcrypt.checkpw(user_password.encode(), hashed):
    print("Password correct")''',
            effort_estimate='medium',
            priority=5,
            references=[
                'https://pypi.org/project/bcrypt/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'
            ]
        )
        
        # Private Keys
        suggestions['Private Key'] = RemediationSuggestion(
            finding_type='Private Key',
            action='Remove from repository and use secure key management',
            description='Never commit private keys. Use key management systems',
            code_snippet='''# 1. Remove key from repository:
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/key.pem" \
  --prune-empty --tag-name-filter cat -- --all

# 2. Add to .gitignore:
echo "*.pem" >> .gitignore
echo "*.key" >> .gitignore

# 3. Use environment variable or key management:
import os
key_path = os.environ.get('PRIVATE_KEY_PATH')''',
            effort_estimate='high',
            priority=5,
            references=[
                'https://help.github.com/en/github/authenticating-to-github/removing-sensitive-data-from-a-repository',
                'https://docs.aws.amazon.com/kms/'
            ]
        )
        
        # Database Connections
        suggestions['Database Connection'] = RemediationSuggestion(
            finding_type='Database Connection',
            action='Use environment variables for connection strings',
            description='Store database credentials in environment variables',
            code_snippet='''# Before (INSECURE):
# db_url = "postgres://user:pass@host/db"

# After (SECURE):
import os
db_url = os.environ.get('DATABASE_URL')

# Or construct from separate variables:
db_host = os.environ.get('DB_HOST')
db_user = os.environ.get('DB_USER')
db_pass = os.environ.get('DB_PASSWORD')
db_name = os.environ.get('DB_NAME')''',
            effort_estimate='low',
            priority=5,
            references=[
                'https://www.postgresql.org/docs/current/libpq-envars.html',
                'https://12factor.net/config'
            ]
        )
        
        # JWT Tokens
        suggestions['JWT Token'] = RemediationSuggestion(
            finding_type='JWT Token',
            action='Use secure token storage and rotation',
            description='Store JWT tokens securely and implement token rotation',
            code_snippet='''# Secure JWT handling:
import jwt
import os

# Generate token with secret from env:
secret = os.environ.get('JWT_SECRET_KEY')
token = jwt.encode({'user': 'id'}, secret, algorithm='HS256')

# Verify token:
try:
    payload = jwt.decode(token, secret, algorithms=['HS256'])
except jwt.InvalidTokenError:
    # Handle invalid token
    pass

# Implement token rotation and short expiry:
from datetime import datetime, timedelta
exp = datetime.utcnow() + timedelta(hours=1)
token = jwt.encode({'exp': exp, 'user': 'id'}, secret)''',
            effort_estimate='medium',
            priority=4,
            references=[
                'https://pyjwt.readthedocs.io/',
                'https://auth0.com/docs/tokens/concepts/token-best-practices'
            ]
        )
        
        return suggestions
    
    def get_remediation(self, finding: Dict[str, Any]) -> Optional[RemediationSuggestion]:
        """
        Get remediation suggestion for a finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            RemediationSuggestion if available, None otherwise
        """
        finding_type = finding.get('type', '')
        
        # Try exact match first
        if finding_type in self.suggestions:
            return self.suggestions[finding_type]
        
        # Try partial match
        for pattern, suggestion in self.suggestions.items():
            if pattern.lower() in finding_type.lower():
                return suggestion
        
        # Return generic suggestion
        return RemediationSuggestion(
            finding_type=finding_type,
            action='Review and remove sensitive data',
            description='This finding contains potentially sensitive information that should be reviewed',
            code_snippet=None,
            effort_estimate='medium',
            priority=3,
            references=[
                'https://owasp.org/www-project-top-ten/',
                'https://cheatsheetseries.owasp.org/'
            ]
        )
    
    def generate_remediation_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive remediation report.
        
        Args:
            findings: List of findings
            
        Returns:
            Remediation report dictionary
        """
        remediations = []
        effort_distribution = {'low': 0, 'medium': 0, 'high': 0}
        
        for finding in findings:
            remediation = self.get_remediation(finding)
            if remediation:
                remediations.append({
                    'finding': finding,
                    'remediation': asdict(remediation)
                })
                effort_distribution[remediation.effort_estimate] += 1
        
        # Sort by priority
        remediations.sort(key=lambda x: x['remediation']['priority'], reverse=True)
        
        return {
            'remediations': remediations,
            'total_items': len(remediations),
            'effort_distribution': effort_distribution,
            'estimated_total_effort': self._estimate_total_effort(effort_distribution)
        }
    
    def _estimate_total_effort(self, distribution: Dict[str, int]) -> str:
        """Estimate total remediation effort."""
        # Rough effort estimates in hours
        effort_hours = {
            'low': 1,
            'medium': 4,
            'high': 16
        }
        
        total_hours = sum(distribution[level] * effort_hours[level] 
                         for level in distribution)
        
        if total_hours < 8:
            return f"{total_hours} hours (< 1 day)"
        elif total_hours < 40:
            days = total_hours / 8
            return f"{total_hours} hours (~{days:.1f} days)"
        else:
            weeks = total_hours / 40
            return f"{total_hours} hours (~{weeks:.1f} weeks)"


# ============================================================================
# Performance Profiling
# ============================================================================

@dataclass
class ScanMetrics:
    """Metrics for a scan operation."""
    scan_id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    files_scanned: int
    urls_scanned: int
    patterns_matched: int
    findings_count: int
    cache_hits: int
    cache_misses: int
    memory_usage_mb: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            **asdict(self),
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat()
        }


class PerformanceProfiler:
    """
    Profile and track scanner performance metrics.
    """
    
    def __init__(self):
        """Initialize performance profiler."""
        self.metrics_history: List[ScanMetrics] = []
        self.current_scan_id = None
        self.current_start_time = None
    
    def start_scan(self, scan_id: Optional[str] = None):
        """Start profiling a scan."""
        self.current_scan_id = scan_id or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.current_start_time = datetime.now()
    
    def end_scan(self, files_scanned: int, urls_scanned: int, 
                 patterns_matched: int, findings_count: int,
                 cache_hits: int = 0, cache_misses: int = 0) -> ScanMetrics:
        """
        End profiling and record metrics.
        
        Args:
            files_scanned: Number of files scanned
            urls_scanned: Number of URLs scanned
            patterns_matched: Number of pattern matches
            findings_count: Number of findings
            cache_hits: Number of cache hits
            cache_misses: Number of cache misses
            
        Returns:
            ScanMetrics object
        """
        end_time = datetime.now()
        duration = (end_time - self.current_start_time).total_seconds()
        
        # Get memory usage (rough estimate)
        try:
            import psutil
            process = psutil.Process(os.getpid())
            memory_mb = process.memory_info().rss / 1024 / 1024
        except ImportError:
            memory_mb = 0.0
        
        metrics = ScanMetrics(
            scan_id=self.current_scan_id,
            start_time=self.current_start_time,
            end_time=end_time,
            duration_seconds=duration,
            files_scanned=files_scanned,
            urls_scanned=urls_scanned,
            patterns_matched=patterns_matched,
            findings_count=findings_count,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            memory_usage_mb=memory_mb
        )
        
        self.metrics_history.append(metrics)
        return metrics
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics across all scans."""
        if not self.metrics_history:
            return {}
        
        total_scans = len(self.metrics_history)
        avg_duration = sum(m.duration_seconds for m in self.metrics_history) / total_scans
        avg_findings = sum(m.findings_count for m in self.metrics_history) / total_scans
        total_findings = sum(m.findings_count for m in self.metrics_history)
        
        cache_efficiency = 0.0
        total_cache_ops = sum(m.cache_hits + m.cache_misses for m in self.metrics_history)
        if total_cache_ops > 0:
            total_hits = sum(m.cache_hits for m in self.metrics_history)
            cache_efficiency = (total_hits / total_cache_ops) * 100
        
        return {
            'total_scans': total_scans,
            'average_duration_seconds': round(avg_duration, 2),
            'average_findings_per_scan': round(avg_findings, 1),
            'total_findings_all_scans': total_findings,
            'cache_efficiency_percent': round(cache_efficiency, 1),
            'total_files_scanned': sum(m.files_scanned for m in self.metrics_history),
            'total_urls_scanned': sum(m.urls_scanned for m in self.metrics_history)
        }
    
    def save_metrics(self, output_file: str):
        """Save metrics history to file."""
        try:
            data = [m.to_dict() for m in self.metrics_history]
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save metrics: {e}")


# ============================================================================
# Plugin System
# ============================================================================

class PluginInterface:
    """Base interface for scanner plugins."""
    
    def get_name(self) -> str:
        """Return plugin name."""
        raise NotImplementedError
    
    def get_version(self) -> str:
        """Return plugin version."""
        return "1.0.0"
    
    def initialize(self, config: Dict[str, Any]):
        """Initialize plugin with configuration."""
        pass
    
    def pre_scan(self, targets: List[str]) -> List[str]:
        """
        Hook called before scanning.
        Can modify target list.
        """
        return targets
    
    def post_scan(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Hook called after scanning.
        Can modify findings.
        """
        return findings
    
    def analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze individual finding.
        Can add metadata or modify finding.
        """
        return finding


class PluginManager:
    """
    Manage scanner plugins.
    """
    
    def __init__(self, plugin_dir: str = 'plugins'):
        """
        Initialize plugin manager.
        
        Args:
            plugin_dir: Directory containing plugins
        """
        self.plugin_dir = plugin_dir
        self.plugins: List[PluginInterface] = []
        self.plugin_registry: Dict[str, PluginInterface] = {}
    
    def discover_plugins(self):
        """Discover and load plugins from plugin directory."""
        if not os.path.exists(self.plugin_dir):
            logging.info(f"Plugin directory {self.plugin_dir} does not exist")
            return
        
        # This is a simplified plugin discovery
        # In production, would use proper module loading
        logging.info(f"Scanning for plugins in {self.plugin_dir}")
    
    def register_plugin(self, plugin: PluginInterface):
        """
        Register a plugin.
        
        Args:
            plugin: Plugin instance
        """
        name = plugin.get_name()
        self.plugins.append(plugin)
        self.plugin_registry[name] = plugin
        logging.info(f"Registered plugin: {name} v{plugin.get_version()}")
    
    def execute_pre_scan(self, targets: List[str]) -> List[str]:
        """Execute pre-scan hooks for all plugins."""
        for plugin in self.plugins:
            try:
                targets = plugin.pre_scan(targets)
            except Exception as e:
                logging.error(f"Error in plugin {plugin.get_name()} pre_scan: {e}")
        return targets
    
    def execute_post_scan(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute post-scan hooks for all plugins."""
        for plugin in self.plugins:
            try:
                findings = plugin.post_scan(findings)
            except Exception as e:
                logging.error(f"Error in plugin {plugin.get_name()} post_scan: {e}")
        return findings
    
    def execute_analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analyze_finding hooks for all plugins."""
        for plugin in self.plugins:
            try:
                finding = plugin.analyze_finding(finding)
            except Exception as e:
                logging.error(f"Error in plugin {plugin.get_name()} analyze_finding: {e}")
        return finding
    
    def get_plugin_info(self) -> List[Dict[str, str]]:
        """Get information about loaded plugins."""
        return [
            {'name': p.get_name(), 'version': p.get_version()}
            for p in self.plugins
        ]


# ============================================================================
# Advanced Scanner Integration
# ============================================================================

class AdvancedVulnerabilityScanner(EnhancedSensitiveInfoScanner):
    """
    Advanced scanner integrating all enterprise features.
    """
    
    def __init__(self,
                 pattern_providers: Optional[List[PatternProvider]] = None,
                 timeout: int = 10,
                 max_workers: int = 5,
                 enable_heuristics: bool = True,
                 enable_ml: bool = False,
                 ml_model_path: Optional[str] = None,
                 cache_ttl: int = 3600,
                 log_level: str = 'INFO',
                 # Advanced features
                 enable_risk_scoring: bool = True,
                 enable_incremental_scan: bool = True,
                 enable_false_positive_mgmt: bool = True,
                 enable_compliance_mapping: bool = True,
                 enable_remediation: bool = True,
                 enable_profiling: bool = True,
                 enable_plugins: bool = False,
                 exposure_level: str = 'medium',
                 state_file: str = '.vuln_scan_state.pkl',
                 allowlist_file: str = '.vuln_scan_allowlist.json'):
        """
        Initialize advanced scanner.
        
        Args:
            All EnhancedSensitiveInfoScanner args plus:
            enable_risk_scoring: Enable risk scoring engine
            enable_incremental_scan: Enable incremental scanning
            enable_false_positive_mgmt: Enable false positive management
            enable_compliance_mapping: Enable compliance framework mapping
            enable_remediation: Enable remediation suggestions
            enable_profiling: Enable performance profiling
            enable_plugins: Enable plugin system
            exposure_level: Overall exposure level (low/medium/high)
            state_file: Path to state file for incremental scanning
            allowlist_file: Path to allowlist file
        """
        # Initialize base scanner
        super().__init__(
            pattern_providers=pattern_providers,
            timeout=timeout,
            max_workers=max_workers,
            enable_heuristics=enable_heuristics,
            enable_ml=enable_ml,
            ml_model_path=ml_model_path,
            cache_ttl=cache_ttl,
            log_level=log_level
        )
        
        # Initialize advanced components
        self.risk_scorer = RiskScoringEngine(exposure_level) if enable_risk_scoring else None
        self.incremental_scanner = IncrementalScanner(state_file) if enable_incremental_scan else None
        self.fp_manager = FalsePositiveManager(allowlist_file) if enable_false_positive_mgmt else None
        self.compliance_mapper = ComplianceMapper() if enable_compliance_mapping else None
        self.remediation_engine = RemediationEngine() if enable_remediation else None
        self.profiler = PerformanceProfiler() if enable_profiling else None
        self.plugin_manager = PluginManager() if enable_plugins else None
        
        self.logger.info("Advanced scanner initialized with enterprise features")
    
    def scan_with_advanced_features(self,
                                   targets: List[str],
                                   target_type: str = 'file',
                                   incremental: bool = True) -> Dict[str, Any]:
        """
        Perform scan with all advanced features.
        
        Args:
            targets: List of targets (files or URLs)
            target_type: Type of targets ('file' or 'url')
            incremental: Use incremental scanning if enabled
            
        Returns:
            Comprehensive scan results with all advanced features
        """
        # Start profiling
        if self.profiler:
            self.profiler.start_scan()
        
        # Plugin pre-scan hook
        if self.plugin_manager:
            targets = self.plugin_manager.execute_pre_scan(targets)
        
        # Incremental scan filter
        if incremental and self.incremental_scanner and target_type == 'file':
            original_count = len(targets)
            targets = self.incremental_scanner.get_changed_files(targets)
            self.logger.info(f"Incremental scan: {len(targets)}/{original_count} files changed")
        
        # Perform actual scan
        if target_type == 'file':
            results = self.scan_files(targets)
        elif target_type == 'url':
            results = self.scan_urls(targets)
        else:
            raise ValueError(f"Unknown target type: {target_type}")
        
        # Collect all findings
        all_findings = []
        for result in results:
            if result['success']:
                all_findings.extend(result['findings'])
        
        # Update incremental scan state
        if self.incremental_scanner and target_type == 'file':
            for result in results:
                if result['success']:
                    findings_count = len(result['findings'])
                    self.incremental_scanner.update_file_state(
                        result['source'],
                        findings_count
                    )
            self.incremental_scanner.save()
        
        # Filter false positives
        if self.fp_manager:
            original_count = len(all_findings)
            all_findings = self.fp_manager.filter_findings(all_findings)
            filtered_count = original_count - len(all_findings)
            if filtered_count > 0:
                self.logger.info(f"Filtered {filtered_count} false positives")
        
        # Add risk scores
        if self.risk_scorer:
            all_findings = self.risk_scorer.prioritize_findings(all_findings)
        
        # Add compliance mappings
        compliance_report = None
        if self.compliance_mapper:
            for finding in all_findings:
                mappings = self.compliance_mapper.get_compliance_mappings(finding)
                finding['compliance_mappings'] = [asdict(m) for m in mappings]
            
            compliance_report = self.compliance_mapper.generate_compliance_report(all_findings)
        
        # Generate remediation suggestions
        remediation_report = None
        if self.remediation_engine:
            remediation_report = self.remediation_engine.generate_remediation_report(all_findings)
        
        # Plugin post-scan hook
        if self.plugin_manager:
            all_findings = self.plugin_manager.execute_post_scan(all_findings)
        
        # End profiling
        metrics = None
        if self.profiler:
            files_scanned = len(results) if target_type == 'file' else 0
            urls_scanned = len(results) if target_type == 'url' else 0
            metrics = self.profiler.end_scan(
                files_scanned=files_scanned,
                urls_scanned=urls_scanned,
                patterns_matched=len(self.patterns),
                findings_count=len(all_findings),
                cache_hits=0,  # Would need to track this
                cache_misses=0
            )
        
        # Compile comprehensive results
        return {
            'success': True,
            'scan_type': target_type,
            'targets_scanned': len(results),
            'targets_requested': len(targets),
            'findings': all_findings,
            'findings_count': len(all_findings),
            'risk_scores_enabled': self.risk_scorer is not None,
            'incremental_scan_enabled': self.incremental_scanner is not None,
            'false_positive_filtering_enabled': self.fp_manager is not None,
            'compliance_report': compliance_report,
            'remediation_report': remediation_report,
            'performance_metrics': metrics.to_dict() if metrics else None,
            'raw_results': results
        }


# ============================================================================
# Example Plugin Implementation
# ============================================================================

class GitSecretsScannerPlugin(PluginInterface):
    """
    Example plugin that integrates with git-secrets or similar tools.
    """
    
    def get_name(self) -> str:
        return "GitSecretsScanner"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def pre_scan(self, targets: List[str]) -> List[str]:
        """Filter out files in .gitignore."""
        # In production, would actually read .gitignore
        return [t for t in targets if not t.endswith('.gitignore')]
    
    def analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add git-specific metadata to findings."""
        if finding.get('source_type') == 'file':
            # Could add git blame info, commit history, etc.
            finding['git_metadata'] = {
                'in_version_control': True,
                'needs_history_cleanup': finding.get('severity') == 'critical'
            }
        return finding
