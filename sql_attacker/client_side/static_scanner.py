"""
Static JavaScript Scanner for Client-Side SQL Injection

Scans JavaScript source code for unsafe usage of openDatabase, localStorage,
and indexedDB with tainted input.
"""

import re
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of client-side vulnerabilities"""
    UNSAFE_OPEN_DATABASE = "unsafe_openDatabase"
    UNSAFE_LOCAL_STORAGE = "unsafe_localStorage"
    UNSAFE_INDEXED_DB = "unsafe_indexedDB"
    UNSAFE_WEB_SQL = "unsafe_webSQL"
    TAINTED_INPUT = "tainted_input"
    SQL_CONCATENATION = "sql_concatenation"


@dataclass
class StaticFinding:
    """Represents a finding from static analysis"""
    vulnerability_type: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    confidence: str = "MEDIUM"

    def to_dict(self):
        return asdict(self)


class JavaScriptStaticScanner:
    """
    Static scanner for JavaScript code to detect client-side SQL injection vulnerabilities
    """
    
    # Patterns for unsafe database operations
    PATTERNS = {
        'openDatabase': [
            r'openDatabase\s*\(',
            r'\.openDatabase\s*\(',
        ],
        'localStorage': [
            r'localStorage\.setItem\s*\(\s*[^,]+\s*,\s*[^)]*\+',  # Concatenation in localStorage
            r'localStorage\[\s*[^\]]*\]\s*=\s*[^;]*\+',  # Assignment with concatenation
        ],
        'indexedDB': [
            r'indexedDB\.open\s*\(',
            r'\.createObjectStore\s*\(',
            r'\.add\s*\([^)]*\+',  # Concatenation in add
            r'\.put\s*\([^)]*\+',  # Concatenation in put
        ],
        'webSQL': [
            r'executeSql\s*\(\s*["\'].*?\+',  # SQL concatenation
            r'transaction\s*\(\s*function',
        ],
        'tainted_input': [
            r'document\.location',
            r'window\.location',
            r'document\.URL',
            r'document\.referrer',
            r'window\.name',
            r'location\.hash',
            r'location\.search',
            r'\.value',  # Form input values
            r'\.innerHTML',
            r'\.innerText',
        ],
        'sql_concatenation': [
            r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE).*?\+',
            r'["\']SELECT.*?\+.*?["\']',
            r'["\']INSERT.*?\+.*?["\']',
            r'["\']UPDATE.*?\+.*?["\']',
        ],
    }
    
    def __init__(self):
        """Initialize the static scanner"""
        self.findings: List[StaticFinding] = []
    
    def scan_file(self, file_path: str, content: Optional[str] = None) -> List[StaticFinding]:
        """
        Scan a JavaScript file for vulnerabilities
        
        Args:
            file_path: Path to JavaScript file
            content: Optional file content (if already loaded)
            
        Returns:
            List of findings
        """
        self.findings = []
        
        try:
            if content is None:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            
            lines = content.split('\n')
            
            # Scan for patterns
            self._scan_open_database(lines, file_path)
            self._scan_local_storage(lines, file_path)
            self._scan_indexed_db(lines, file_path)
            self._scan_web_sql(lines, file_path)
            self._scan_tainted_input(lines, file_path)
            
            logger.info(f"Scanned {file_path}: found {len(self.findings)} issues")
            return self.findings
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return self.findings
    
    def scan_code(self, code: str, file_name: str = "inline") -> List[StaticFinding]:
        """
        Scan JavaScript code string
        
        Args:
            code: JavaScript code to scan
            file_name: Optional file name for reporting
            
        Returns:
            List of findings
        """
        return self.scan_file(file_name, content=code)
    
    def _scan_open_database(self, lines: List[str], file_path: str):
        """Scan for unsafe openDatabase usage"""
        for i, line in enumerate(lines, 1):
            for pattern in self.PATTERNS['openDatabase']:
                if re.search(pattern, line):
                    # Check if input is tainted
                    if self._has_tainted_input(line):
                        finding = StaticFinding(
                            vulnerability_type=VulnerabilityType.UNSAFE_OPEN_DATABASE.value,
                            severity="HIGH",
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description="openDatabase() called with potentially tainted input. "
                                      "This could lead to SQL injection in Web SQL Database.",
                            recommendation="Use parameterized queries and validate all inputs before "
                                         "using them in database operations.",
                            confidence="HIGH"
                        )
                        self.findings.append(finding)
                    else:
                        finding = StaticFinding(
                            vulnerability_type=VulnerabilityType.UNSAFE_OPEN_DATABASE.value,
                            severity="MEDIUM",
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description="openDatabase() usage detected. Verify that inputs are "
                                      "properly validated.",
                            recommendation="Ensure all database operations use parameterized queries.",
                            confidence="MEDIUM"
                        )
                        self.findings.append(finding)
    
    def _scan_local_storage(self, lines: List[str], file_path: str):
        """Scan for unsafe localStorage usage"""
        for i, line in enumerate(lines, 1):
            for pattern in self.PATTERNS['localStorage']:
                if re.search(pattern, line):
                    if self._has_tainted_input(line):
                        finding = StaticFinding(
                            vulnerability_type=VulnerabilityType.UNSAFE_LOCAL_STORAGE.value,
                            severity="MEDIUM",
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description="localStorage operation with concatenation and potentially "
                                      "tainted input. This could lead to data injection.",
                            recommendation="Sanitize and validate all inputs before storing. "
                                         "Use JSON.stringify() for structured data.",
                            confidence="HIGH"
                        )
                        self.findings.append(finding)
    
    def _scan_indexed_db(self, lines: List[str], file_path: str):
        """Scan for unsafe indexedDB usage"""
        for i, line in enumerate(lines, 1):
            for pattern in self.PATTERNS['indexedDB']:
                if re.search(pattern, line):
                    if '+' in line and self._has_tainted_input(line):
                        finding = StaticFinding(
                            vulnerability_type=VulnerabilityType.UNSAFE_INDEXED_DB.value,
                            severity="HIGH",
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description="IndexedDB operation with concatenation and potentially "
                                      "tainted input. This could lead to data corruption or injection.",
                            recommendation="Use structured objects and validate inputs before "
                                         "storing in IndexedDB.",
                            confidence="HIGH"
                        )
                        self.findings.append(finding)
    
    def _scan_web_sql(self, lines: List[str], file_path: str):
        """Scan for unsafe Web SQL usage"""
        for i, line in enumerate(lines, 1):
            for pattern in self.PATTERNS['webSQL']:
                if re.search(pattern, line):
                    # Check for SQL concatenation
                    if re.search(r'executeSql\s*\(\s*["\'].*?\+', line):
                        finding = StaticFinding(
                            vulnerability_type=VulnerabilityType.UNSAFE_WEB_SQL.value,
                            severity="CRITICAL",
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description="Web SQL executeSql() with string concatenation. "
                                      "This is a classic SQL injection vulnerability.",
                            recommendation="Always use parameterized queries with the '?' placeholder "
                                         "and pass values as array: executeSql(sql, [val1, val2])",
                            confidence="HIGH"
                        )
                        self.findings.append(finding)
    
    def _scan_tainted_input(self, lines: List[str], file_path: str):
        """Scan for tainted input sources"""
        for i, line in enumerate(lines, 1):
            # Check for SQL operations with tainted input
            has_sql = any(re.search(pattern, line, re.IGNORECASE) 
                         for pattern in self.PATTERNS['sql_concatenation'])
            has_tainted = self._has_tainted_input(line)
            
            if has_sql and has_tainted:
                finding = StaticFinding(
                    vulnerability_type=VulnerabilityType.SQL_CONCATENATION.value,
                    severity="CRITICAL",
                    file_path=file_path,
                    line_number=i,
                    code_snippet=line.strip(),
                    description="SQL query constructed with string concatenation using "
                              "potentially tainted input from user or URL.",
                    recommendation="Never concatenate user input into SQL queries. "
                                 "Use parameterized queries or prepared statements.",
                    confidence="HIGH"
                )
                self.findings.append(finding)
    
    def _has_tainted_input(self, line: str) -> bool:
        """Check if line contains tainted input sources"""
        for pattern in self.PATTERNS['tainted_input']:
            if re.search(pattern, line):
                return True
        return False
    
    def scan_directory(self, directory_path: str) -> List[StaticFinding]:
        """
        Recursively scan a directory for JavaScript files
        
        Args:
            directory_path: Path to directory
            
        Returns:
            Combined list of findings from all files
        """
        import os
        
        all_findings = []
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                    file_path = os.path.join(root, file)
                    findings = self.scan_file(file_path)
                    all_findings.extend(findings)
        
        logger.info(f"Scanned directory {directory_path}: found {len(all_findings)} total issues")
        return all_findings
    
    def get_report(self, findings: Optional[List[StaticFinding]] = None) -> Dict[str, Any]:
        """
        Generate a report from findings
        
        Args:
            findings: Optional list of findings (uses self.findings if not provided)
            
        Returns:
            Structured report
        """
        if findings is None:
            findings = self.findings
        
        return {
            'total_findings': len(findings),
            'by_severity': self._count_by_severity(findings),
            'by_type': self._count_by_type(findings),
            'by_confidence': self._count_by_confidence(findings),
            'findings': [f.to_dict() for f in findings],
        }
    
    def _count_by_severity(self, findings: List[StaticFinding]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
    
    def _count_by_type(self, findings: List[StaticFinding]) -> Dict[str, int]:
        """Count findings by vulnerability type"""
        counts = {}
        for finding in findings:
            counts[finding.vulnerability_type] = counts.get(finding.vulnerability_type, 0) + 1
        return counts
    
    def _count_by_confidence(self, findings: List[StaticFinding]) -> Dict[str, int]:
        """Count findings by confidence level"""
        counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
        return counts
    
    def generate_html_report(self, findings: Optional[List[StaticFinding]] = None, 
                           output_file: str = "static_scan_report.html") -> str:
        """
        Generate an HTML report
        
        Args:
            findings: Optional list of findings
            output_file: Output file path
            
        Returns:
            Path to generated report
        """
        if findings is None:
            findings = self.findings
        
        report = self.get_report(findings)
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>JavaScript Static Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #d32f2f; }}
        .high {{ border-left: 5px solid #f57c00; }}
        .medium {{ border-left: 5px solid #ffa000; }}
        .low {{ border-left: 5px solid #388e3c; }}
        .code {{ background: #f5f5f5; padding: 10px; border-radius: 3px; font-family: monospace; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; }}
    </style>
</head>
<body>
    <h1>JavaScript Static Analysis Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Findings: {report['total_findings']}</p>
        <p>Critical: {report['by_severity']['CRITICAL']}</p>
        <p>High: {report['by_severity']['HIGH']}</p>
        <p>Medium: {report['by_severity']['MEDIUM']}</p>
        <p>Low: {report['by_severity']['LOW']}</p>
    </div>
    
    <h2>Findings</h2>
"""
        
        for finding in findings:
            severity_class = finding.severity.lower()
            html += f"""
    <div class="finding {severity_class}">
        <h3>[{finding.severity}] {finding.vulnerability_type}</h3>
        <p><strong>File:</strong> {finding.file_path}:{finding.line_number}</p>
        <p><strong>Description:</strong> {finding.description}</p>
        <div class="code">{finding.code_snippet}</div>
        <p><strong>Recommendation:</strong> {finding.recommendation}</p>
        <p><strong>Confidence:</strong> {finding.confidence}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f"HTML report generated: {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return ""
