"""
Real Impact Analyzer and Evidence Capture System

Automatically captures and documents the real-world impact of SQL injection:
- Data extraction evidence
- Schema enumeration
- Privilege escalation details
- System impact assessment
- JSON evidence generation
"""

import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class ImpactType(Enum):
    """Types of impact"""
    DATA_EXTRACTION = "data_extraction"
    DATA_MODIFICATION = "data_modification"
    SCHEMA_ENUMERATION = "schema_enumeration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_COMMAND = "system_command"
    FILE_ACCESS = "file_access"
    AUTHENTICATION_BYPASS = "authentication_bypass"


class DataSensitivity(Enum):
    """Sensitivity levels for extracted data"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    CRITICAL = "critical"


@dataclass
class ExtractedData:
    """Represents data extracted via SQL injection"""
    table_name: str
    column_name: str
    value: str
    row_index: int
    sensitivity: DataSensitivity
    data_type: str


@dataclass
class AffectedTable:
    """Information about an affected database table"""
    table_name: str
    rows_affected: int
    columns_accessed: List[str]
    operation: str  # SELECT, INSERT, UPDATE, DELETE
    evidence: str


@dataclass
class PrivilegeInfo:
    """Information about database privileges"""
    user: str
    privileges: List[str]
    is_admin: bool
    can_read: bool
    can_write: bool
    can_execute: bool
    can_grant: bool


@dataclass
class ImpactEvidence:
    """Complete evidence of SQL injection impact"""
    vulnerability_id: str
    timestamp: str
    target_url: str
    vulnerable_parameter: str
    injection_type: str
    
    # Impact details
    impact_types: List[str]
    severity: str
    confidence: float
    
    # Data extraction
    extracted_data: List[Dict[str, Any]]
    sensitive_data_found: bool
    total_rows_extracted: int
    
    # Database information
    database_name: Optional[str]
    database_version: Optional[str]
    database_user: Optional[str]
    
    # Schema information
    tables_discovered: List[str]
    columns_discovered: Dict[str, List[str]]
    
    # Affected resources
    affected_tables: List[Dict[str, Any]]
    
    # Privilege information
    privilege_info: Optional[Dict[str, Any]]
    privilege_escalation_possible: bool
    
    # System impact
    system_commands_executed: List[str]
    files_accessed: List[str]
    
    # Evidence and proof
    successful_payloads: List[str]
    request_evidence: List[Dict[str, Any]]
    response_evidence: List[Dict[str, Any]]
    
    # Risk assessment
    risk_score: int  # 0-100
    exploitability_score: float  # 0.0-1.0
    business_impact: str
    
    # Recommendations
    recommendations: List[str]


class RealImpactAnalyzer:
    """
    Analyzes and documents the real-world impact of SQL injection vulnerabilities.
    Captures evidence in structured JSON format.
    """
    
    # Patterns for sensitive data detection
    SENSITIVE_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'password_hash': r'\b[a-fA-F0-9]{32,64}\b',
        'api_key': r'[a-zA-Z0-9_\-]{32,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    }
    
    def __init__(self):
        """Initialize impact analyzer"""
        self.current_evidence: Optional[ImpactEvidence] = None
        self.evidence_history: List[ImpactEvidence] = []
    
    def start_analysis(self,
                      target_url: str,
                      vulnerable_parameter: str,
                      injection_type: str) -> str:
        """
        Start a new impact analysis session.
        
        Args:
            target_url: Target URL
            vulnerable_parameter: Vulnerable parameter name
            injection_type: Type of SQL injection
            
        Returns:
            Vulnerability ID
        """
        vuln_id = self._generate_vulnerability_id(target_url, vulnerable_parameter)
        
        self.current_evidence = ImpactEvidence(
            vulnerability_id=vuln_id,
            timestamp=datetime.utcnow().isoformat(),
            target_url=target_url,
            vulnerable_parameter=vulnerable_parameter,
            injection_type=injection_type,
            impact_types=[],
            severity="unknown",
            confidence=0.0,
            extracted_data=[],
            sensitive_data_found=False,
            total_rows_extracted=0,
            database_name=None,
            database_version=None,
            database_user=None,
            tables_discovered=[],
            columns_discovered={},
            affected_tables=[],
            privilege_info=None,
            privilege_escalation_possible=False,
            system_commands_executed=[],
            files_accessed=[],
            successful_payloads=[],
            request_evidence=[],
            response_evidence=[],
            risk_score=0,
            exploitability_score=0.0,
            business_impact="unknown",
            recommendations=[]
        )
        
        logger.info(f"Started impact analysis: {vuln_id}")
        return vuln_id
    
    def _generate_vulnerability_id(self, url: str, param: str) -> str:
        """Generate unique vulnerability ID"""
        unique_str = f"{url}:{param}:{datetime.utcnow().isoformat()}"
        return f"SQLI-{hashlib.md5(unique_str.encode()).hexdigest()[:12].upper()}"
    
    def record_data_extraction(self,
                              table_name: str,
                              data: List[Dict[str, str]],
                              columns: List[str]):
        """
        Record extracted data.
        
        Args:
            table_name: Name of the table
            data: Extracted data rows
            columns: Column names
        """
        if not self.current_evidence:
            logger.error("No active analysis session")
            return
        
        # Add impact type
        if ImpactType.DATA_EXTRACTION.value not in self.current_evidence.impact_types:
            self.current_evidence.impact_types.append(ImpactType.DATA_EXTRACTION.value)
        
        # Process each row
        for row_idx, row in enumerate(data):
            for col_name, value in row.items():
                # Detect sensitivity
                sensitivity = self._detect_sensitivity(col_name, value)
                
                extracted = ExtractedData(
                    table_name=table_name,
                    column_name=col_name,
                    value=str(value),
                    row_index=row_idx,
                    sensitivity=sensitivity,
                    data_type=type(value).__name__
                )
                
                self.current_evidence.extracted_data.append(asdict(extracted))
                
                if sensitivity in [DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED, DataSensitivity.CRITICAL]:
                    self.current_evidence.sensitive_data_found = True
        
        self.current_evidence.total_rows_extracted += len(data)
        
        # Track affected table
        affected = AffectedTable(
            table_name=table_name,
            rows_affected=len(data),
            columns_accessed=columns,
            operation="SELECT",
            evidence=f"Extracted {len(data)} rows with {len(columns)} columns"
        )
        self.current_evidence.affected_tables.append(asdict(affected))
        
        logger.info(f"Recorded data extraction: {table_name}, {len(data)} rows")
    
    def record_schema_discovery(self,
                               tables: List[str],
                               columns_by_table: Dict[str, List[str]]):
        """
        Record discovered schema information.
        
        Args:
            tables: List of table names
            columns_by_table: Dictionary mapping table names to columns
        """
        if not self.current_evidence:
            logger.error("No active analysis session")
            return
        
        if ImpactType.SCHEMA_ENUMERATION.value not in self.current_evidence.impact_types:
            self.current_evidence.impact_types.append(ImpactType.SCHEMA_ENUMERATION.value)
        
        self.current_evidence.tables_discovered.extend(tables)
        self.current_evidence.columns_discovered.update(columns_by_table)
        
        logger.info(f"Recorded schema: {len(tables)} tables, {sum(len(cols) for cols in columns_by_table.values())} columns")
    
    def record_database_info(self,
                            db_name: Optional[str] = None,
                            db_version: Optional[str] = None,
                            db_user: Optional[str] = None):
        """Record database information"""
        if not self.current_evidence:
            return
        
        if db_name:
            self.current_evidence.database_name = db_name
        if db_version:
            self.current_evidence.database_version = db_version
        if db_user:
            self.current_evidence.database_user = db_user
        
        logger.info(f"Recorded database info: {db_name} ({db_version}), user: {db_user}")
    
    def record_privilege_info(self, privilege_info: PrivilegeInfo):
        """Record privilege escalation information"""
        if not self.current_evidence:
            return
        
        if ImpactType.PRIVILEGE_ESCALATION.value not in self.current_evidence.impact_types:
            self.current_evidence.impact_types.append(ImpactType.PRIVILEGE_ESCALATION.value)
        
        self.current_evidence.privilege_info = asdict(privilege_info)
        self.current_evidence.privilege_escalation_possible = privilege_info.is_admin or privilege_info.can_grant
        
        logger.info(f"Recorded privilege info: {privilege_info.user}, admin={privilege_info.is_admin}")
    
    def record_successful_payload(self, payload: str, request_data: Dict[str, Any], response_data: Dict[str, Any]):
        """Record a successful payload with request/response evidence"""
        if not self.current_evidence:
            return
        
        self.current_evidence.successful_payloads.append(payload)
        
        # Sanitize and record request
        self.current_evidence.request_evidence.append({
            'timestamp': datetime.utcnow().isoformat(),
            'payload': payload,
            'method': request_data.get('method', 'GET'),
            'url': request_data.get('url', ''),
            'headers': self._sanitize_headers(request_data.get('headers', {})),
            'parameters': request_data.get('parameters', {})
        })
        
        # Record response
        self.current_evidence.response_evidence.append({
            'timestamp': datetime.utcnow().isoformat(),
            'status_code': response_data.get('status_code', 0),
            'content_length': response_data.get('content_length', 0),
            'content_snippet': response_data.get('content', '')[:500],  # First 500 chars
            'headers': self._sanitize_headers(response_data.get('headers', {}))
        })
    
    def record_system_command(self, command: str, output: str):
        """Record system command execution"""
        if not self.current_evidence:
            return
        
        if ImpactType.SYSTEM_COMMAND.value not in self.current_evidence.impact_types:
            self.current_evidence.impact_types.append(ImpactType.SYSTEM_COMMAND.value)
        
        self.current_evidence.system_commands_executed.append({
            'command': command,
            'output': output[:200],  # First 200 chars
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.warning(f"Recorded system command execution: {command}")
    
    def record_file_access(self, file_path: str, operation: str):
        """Record file system access"""
        if not self.current_evidence:
            return
        
        if ImpactType.FILE_ACCESS.value not in self.current_evidence.impact_types:
            self.current_evidence.impact_types.append(ImpactType.FILE_ACCESS.value)
        
        self.current_evidence.files_accessed.append({
            'path': file_path,
            'operation': operation,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.warning(f"Recorded file access: {file_path}")
    
    def finalize_analysis(self, severity: str, confidence: float) -> ImpactEvidence:
        """
        Finalize the impact analysis and generate complete evidence.
        
        Args:
            severity: Final severity (critical, high, medium, low)
            confidence: Confidence score
            
        Returns:
            Complete ImpactEvidence object
        """
        if not self.current_evidence:
            raise ValueError("No active analysis session")
        
        self.current_evidence.severity = severity
        self.current_evidence.confidence = confidence
        
        # Calculate risk score
        self.current_evidence.risk_score = self._calculate_risk_score()
        self.current_evidence.exploitability_score = self._calculate_exploitability()
        
        # Assess business impact
        self.current_evidence.business_impact = self._assess_business_impact()
        
        # Generate recommendations
        self.current_evidence.recommendations = self._generate_recommendations()
        
        # Save to history
        self.evidence_history.append(self.current_evidence)
        
        logger.info(f"Finalized analysis: {self.current_evidence.vulnerability_id}")
        
        return self.current_evidence
    
    def _detect_sensitivity(self, column_name: str, value: str) -> DataSensitivity:
        """Detect data sensitivity level"""
        col_lower = column_name.lower()
        val_str = str(value).lower()
        
        # Critical sensitivity patterns
        if any(keyword in col_lower for keyword in ['password', 'secret', 'private_key', 'ssn', 'credit_card']):
            return DataSensitivity.CRITICAL
        
        # Restricted patterns
        if any(keyword in col_lower for keyword in ['salary', 'medical', 'confidential', 'token', 'api_key']):
            return DataSensitivity.RESTRICTED
        
        # Confidential patterns
        if any(keyword in col_lower for keyword in ['email', 'phone', 'address', 'dob', 'personal']):
            return DataSensitivity.CONFIDENTIAL
        
        # Check value patterns
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            import re
            if re.search(pattern, val_str):
                if pattern_name in ['password_hash', 'ssn', 'credit_card']:
                    return DataSensitivity.CRITICAL
                elif pattern_name in ['api_key']:
                    return DataSensitivity.RESTRICTED
                else:
                    return DataSensitivity.CONFIDENTIAL
        
        return DataSensitivity.INTERNAL
    
    def _calculate_risk_score(self) -> int:
        """Calculate risk score (0-100)"""
        if not self.current_evidence:
            return 0
        
        score = 0
        
        # Base score for vulnerability existence
        score += 20
        
        # Data extraction impact
        if self.current_evidence.total_rows_extracted > 0:
            score += min(20, self.current_evidence.total_rows_extracted)
        
        # Sensitive data found
        if self.current_evidence.sensitive_data_found:
            score += 25
        
        # Schema enumeration
        if len(self.current_evidence.tables_discovered) > 0:
            score += 10
        
        # Privilege escalation
        if self.current_evidence.privilege_escalation_possible:
            score += 20
        
        # System commands
        if self.current_evidence.system_commands_executed:
            score += 30
        
        # File access
        if self.current_evidence.files_accessed:
            score += 25
        
        return min(score, 100)
    
    def _calculate_exploitability(self) -> float:
        """Calculate exploitability score (0.0-1.0)"""
        if not self.current_evidence:
            return 0.0
        
        score = 0.0
        
        # Multiple successful payloads increase exploitability
        if len(self.current_evidence.successful_payloads) > 0:
            score += 0.3
        
        # Data extraction proves exploitability
        if self.current_evidence.total_rows_extracted > 0:
            score += 0.4
        
        # High confidence
        score += self.current_evidence.confidence * 0.3
        
        return min(score, 1.0)
    
    def _assess_business_impact(self) -> str:
        """Assess business impact"""
        if not self.current_evidence:
            return "unknown"
        
        risk = self.current_evidence.risk_score
        
        if risk >= 80:
            return "critical - immediate action required"
        elif risk >= 60:
            return "high - significant data breach possible"
        elif risk >= 40:
            return "medium - data exposure likely"
        elif risk >= 20:
            return "low - limited exposure"
        else:
            return "minimal - no data extracted"
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        if not self.current_evidence:
            return []
        
        recommendations = []
        
        # Always recommend parameterized queries
        recommendations.append("Use parameterized queries or prepared statements")
        recommendations.append("Implement input validation and sanitization")
        
        if self.current_evidence.sensitive_data_found:
            recommendations.append("Encrypt sensitive data at rest")
            recommendations.append("Implement data access controls and monitoring")
        
        if self.current_evidence.privilege_escalation_possible:
            recommendations.append("Apply principle of least privilege")
            recommendations.append("Restrict database user permissions")
        
        if self.current_evidence.system_commands_executed:
            recommendations.append("URGENT: Disable dangerous database functions (xp_cmdshell, etc.)")
            recommendations.append("Review and restrict stored procedure permissions")
        
        if len(self.current_evidence.tables_discovered) > 5:
            recommendations.append("Implement database activity monitoring")
            recommendations.append("Consider using a web application firewall (WAF)")
        
        recommendations.append("Conduct regular security audits and penetration testing")
        
        return recommendations
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize headers to remove sensitive information"""
        sanitized = {}
        sensitive_headers = {'authorization', 'cookie', 'x-api-key', 'x-auth-token'}
        
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def export_json_evidence(self, evidence: Optional[ImpactEvidence] = None) -> str:
        """
        Export evidence as JSON.
        
        Args:
            evidence: Evidence to export (uses current if None)
            
        Returns:
            JSON string
        """
        if evidence is None:
            evidence = self.current_evidence
        
        if not evidence:
            return json.dumps({'error': 'No evidence available'}, indent=2)
        
        return json.dumps(asdict(evidence), indent=2, default=str)
    
    def export_summary_report(self, evidence: Optional[ImpactEvidence] = None) -> str:
        """
        Export human-readable summary report.
        
        Args:
            evidence: Evidence to export (uses current if None)
            
        Returns:
            Formatted text report
        """
        if evidence is None:
            evidence = self.current_evidence
        
        if not evidence:
            return "No evidence available"
        
        report = f"""
SQL INJECTION IMPACT REPORT
{'=' * 80}

Vulnerability ID: {evidence.vulnerability_id}
Timestamp: {evidence.timestamp}
Target: {evidence.target_url}
Vulnerable Parameter: {evidence.vulnerable_parameter}
Injection Type: {evidence.injection_type}

SEVERITY ASSESSMENT
{'-' * 80}
Severity: {evidence.severity.upper()}
Confidence: {evidence.confidence:.2%}
Risk Score: {evidence.risk_score}/100
Exploitability: {evidence.exploitability_score:.2%}
Business Impact: {evidence.business_impact}

IMPACT SUMMARY
{'-' * 80}
Impact Types: {', '.join(evidence.impact_types)}
Data Extracted: {evidence.total_rows_extracted} rows
Sensitive Data Found: {'Yes' if evidence.sensitive_data_found else 'No'}
Tables Discovered: {len(evidence.tables_discovered)}
Privilege Escalation: {'Possible' if evidence.privilege_escalation_possible else 'No'}

DATABASE INFORMATION
{'-' * 80}
Database: {evidence.database_name or 'Unknown'}
Version: {evidence.database_version or 'Unknown'}
User: {evidence.database_user or 'Unknown'}

RECOMMENDATIONS
{'-' * 80}
"""
        for idx, rec in enumerate(evidence.recommendations, 1):
            report += f"{idx}. {rec}\n"
        
        report += f"\n{'=' * 80}\n"
        
        return report
