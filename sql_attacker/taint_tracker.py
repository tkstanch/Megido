"""
Hybrid Static/Dynamic Taint Tracking for SQL Injection Detection

Implements taint analysis to track user input flow through the application:
- Static taint analysis for code review
- Dynamic taint tracking for runtime monitoring
- Data flow analysis
- Sanitization detection
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class TaintLevel(Enum):
    """Taint level of data"""
    CLEAN = 0
    SANITIZED = 1
    SUSPICIOUS = 2
    TAINTED = 3


class SanitizationType(Enum):
    """Types of sanitization"""
    ESCAPED = "escaped"
    VALIDATED = "validated"
    ENCODED = "encoded"
    FILTERED = "filtered"
    NONE = "none"


@dataclass
class TaintedData:
    """Represents tainted data in the system"""
    value: str
    source: str
    taint_level: TaintLevel
    sanitization: SanitizationType
    flow_path: List[str]
    confidence: float


class TaintTracker:
    """
    Hybrid taint tracking system for SQL injection detection.
    Tracks user input from source to sink.
    """
    
    # Common sanitization functions
    SANITIZATION_FUNCTIONS = {
        'escape': SanitizationType.ESCAPED,
        'quote': SanitizationType.ESCAPED,
        'addslashes': SanitizationType.ESCAPED,
        'mysql_real_escape_string': SanitizationType.ESCAPED,
        'pg_escape_string': SanitizationType.ESCAPED,
        'validate': SanitizationType.VALIDATED,
        'filter': SanitizationType.FILTERED,
        'encode': SanitizationType.ENCODED,
        'urlencode': SanitizationType.ENCODED,
        'htmlspecialchars': SanitizationType.ENCODED,
    }
    
    # SQL sinks (dangerous functions/operations)
    SQL_SINKS = [
        'execute', 'query', 'exec', 'prepare', 'raw',
        'executeQuery', 'executeSql', 'executeUpdate',
        'cursor.execute', 'db.query', 'connection.query'
    ]
    
    def __init__(self):
        """Initialize taint tracker"""
        self.tainted_sources: Dict[str, TaintedData] = {}
        self.sanitized_data: Set[str] = set()
        self.flow_graph: Dict[str, List[str]] = {}
        self.vulnerability_sinks: List[Dict[str, Any]] = []
    
    def mark_tainted(self, variable_name: str, value: str, source: str = "user_input") -> TaintedData:
        """
        Mark data as tainted (from user input).
        
        Args:
            variable_name: Name of the variable
            value: Value of the variable
            source: Source of the taint (e.g., "GET", "POST", "COOKIE")
            
        Returns:
            TaintedData object
        """
        tainted = TaintedData(
            value=value,
            source=source,
            taint_level=TaintLevel.TAINTED,
            sanitization=SanitizationType.NONE,
            flow_path=[variable_name],
            confidence=1.0
        )
        
        self.tainted_sources[variable_name] = tainted
        logger.debug(f"Marked {variable_name} as tainted from {source}")
        
        return tainted
    
    def apply_sanitization(self, variable_name: str, sanitization_func: str) -> Optional[TaintedData]:
        """
        Apply sanitization to tainted data.
        
        Args:
            variable_name: Name of the variable
            sanitization_func: Name of sanitization function applied
            
        Returns:
            Updated TaintedData or None if not tracked
        """
        if variable_name not in self.tainted_sources:
            return None
        
        tainted = self.tainted_sources[variable_name]
        
        # Determine sanitization type
        sanit_type = SanitizationType.NONE
        for func_pattern, s_type in self.SANITIZATION_FUNCTIONS.items():
            if func_pattern in sanitization_func.lower():
                sanit_type = s_type
                break
        
        # Update taint level based on sanitization
        if sanit_type in [SanitizationType.ESCAPED, SanitizationType.VALIDATED]:
            tainted.taint_level = TaintLevel.SANITIZED
            tainted.confidence *= 0.3  # Reduced risk
        elif sanit_type in [SanitizationType.FILTERED, SanitizationType.ENCODED]:
            tainted.taint_level = TaintLevel.SUSPICIOUS
            tainted.confidence *= 0.6  # Some risk remains
        
        tainted.sanitization = sanit_type
        tainted.flow_path.append(f"sanitized:{sanitization_func}")
        
        self.sanitized_data.add(variable_name)
        logger.debug(f"Applied sanitization {sanitization_func} to {variable_name}")
        
        return tainted
    
    def track_flow(self, from_var: str, to_var: str, operation: str = "assignment"):
        """
        Track data flow from one variable to another.
        
        Args:
            from_var: Source variable
            to_var: Destination variable
            operation: Type of operation (assignment, concatenation, etc.)
        """
        # Initialize flow graph entry
        if from_var not in self.flow_graph:
            self.flow_graph[from_var] = []
        
        self.flow_graph[from_var].append(to_var)
        
        # Propagate taint
        if from_var in self.tainted_sources:
            from_tainted = self.tainted_sources[from_var]
            
            # Create or update taint for destination
            if to_var in self.tainted_sources:
                to_tainted = self.tainted_sources[to_var]
                # Merge flow paths
                to_tainted.flow_path.extend(from_tainted.flow_path)
                # Take higher taint level
                if from_tainted.taint_level.value > to_tainted.taint_level.value:
                    to_tainted.taint_level = from_tainted.taint_level
            else:
                # Create new tainted data
                self.tainted_sources[to_var] = TaintedData(
                    value=from_tainted.value,
                    source=from_tainted.source,
                    taint_level=from_tainted.taint_level,
                    sanitization=from_tainted.sanitization,
                    flow_path=from_tainted.flow_path + [f"{operation}:{to_var}"],
                    confidence=from_tainted.confidence
                )
            
            logger.debug(f"Tracked flow: {from_var} -> {to_var} via {operation}")
    
    def check_sink(self, variable_name: str, sink_function: str) -> Optional[Dict[str, Any]]:
        """
        Check if tainted data reaches a dangerous sink.
        
        Args:
            variable_name: Variable being used in sink
            sink_function: SQL sink function (e.g., "execute", "query")
            
        Returns:
            Vulnerability information if found, None otherwise
        """
        if variable_name not in self.tainted_sources:
            return None
        
        tainted = self.tainted_sources[variable_name]
        
        # Check if it's a SQL sink
        is_sql_sink = any(sink in sink_function.lower() for sink in self.SQL_SINKS)
        
        if not is_sql_sink:
            return None
        
        # Calculate risk based on taint level and sanitization
        risk_score = self._calculate_risk(tainted)
        
        vulnerability = {
            'variable': variable_name,
            'sink': sink_function,
            'source': tainted.source,
            'taint_level': tainted.taint_level.name,
            'sanitization': tainted.sanitization.name,
            'flow_path': tainted.flow_path,
            'risk_score': risk_score,
            'confidence': tainted.confidence,
            'is_vulnerable': risk_score > 0.5
        }
        
        if vulnerability['is_vulnerable']:
            self.vulnerability_sinks.append(vulnerability)
            logger.warning(f"Vulnerable sink detected: {sink_function} with {variable_name}")
        
        return vulnerability
    
    def _calculate_risk(self, tainted: TaintedData) -> float:
        """
        Calculate risk score for tainted data.
        
        Args:
            tainted: TaintedData object
            
        Returns:
            Risk score (0.0 to 1.0)
        """
        base_risk = {
            TaintLevel.CLEAN: 0.0,
            TaintLevel.SANITIZED: 0.2,
            TaintLevel.SUSPICIOUS: 0.5,
            TaintLevel.TAINTED: 0.9
        }
        
        risk = base_risk[tainted.taint_level]
        
        # Adjust for sanitization
        if tainted.sanitization in [SanitizationType.ESCAPED, SanitizationType.VALIDATED]:
            risk *= 0.3
        elif tainted.sanitization in [SanitizationType.FILTERED, SanitizationType.ENCODED]:
            risk *= 0.6
        
        # Adjust for confidence
        risk *= tainted.confidence
        
        return min(risk, 1.0)
    
    def analyze_code_snippet(self, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Perform static taint analysis on code snippet.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            Analysis results
        """
        results = {
            'tainted_sources': [],
            'vulnerable_sinks': [],
            'flow_paths': [],
            'recommendations': []
        }
        
        # Simple pattern-based static analysis
        if language == "python":
            results.update(self._analyze_python_code(code))
        elif language == "php":
            results.update(self._analyze_php_code(code))
        elif language == "java":
            results.update(self._analyze_java_code(code))
        
        return results
    
    def _analyze_python_code(self, code: str) -> Dict[str, Any]:
        """Analyze Python code for taint flow"""
        results = {
            'tainted_sources': [],
            'vulnerable_sinks': [],
            'recommendations': []
        }
        
        # Find user input sources
        input_patterns = [
            r'request\.GET\.get\([\'"](\w+)[\'"]',
            r'request\.POST\.get\([\'"](\w+)[\'"]',
            r'request\.args\.get\([\'"](\w+)[\'"]',
            r'request\.form\.get\([\'"](\w+)[\'"]',
            r'input\([\'"]([^\'\"]+)[\'"]',
        ]
        
        for pattern in input_patterns:
            for match in re.finditer(pattern, code):
                results['tainted_sources'].append({
                    'param': match.group(1) if match.groups() else 'unknown',
                    'line': code[:match.start()].count('\n') + 1
                })
        
        # Find SQL sinks
        sink_patterns = [
            r'cursor\.execute\([^)]*\)',
            r'connection\.execute\([^)]*\)',
            r'\.query\([^)]*\)',
            r'\.raw\([^)]*\)',
        ]
        
        for pattern in sink_patterns:
            for match in re.finditer(pattern, code):
                results['vulnerable_sinks'].append({
                    'sink': match.group(0),
                    'line': code[:match.start()].count('\n') + 1
                })
        
        # Generate recommendations
        if results['tainted_sources'] and results['vulnerable_sinks']:
            results['recommendations'].append("Use parameterized queries or ORM")
            results['recommendations'].append("Validate and sanitize all user inputs")
            results['recommendations'].append("Use prepared statements")
        
        return results
    
    def _analyze_php_code(self, code: str) -> Dict[str, Any]:
        """Analyze PHP code for taint flow"""
        results = {
            'tainted_sources': [],
            'vulnerable_sinks': [],
            'recommendations': []
        }
        
        # Find user input sources
        input_patterns = [
            r'\$_GET\[[\'"](\w+)[\'"]\]',
            r'\$_POST\[[\'"](\w+)[\'"]\]',
            r'\$_COOKIE\[[\'"](\w+)[\'"]\]',
            r'\$_REQUEST\[[\'"](\w+)[\'"]\]',
        ]
        
        for pattern in input_patterns:
            for match in re.finditer(pattern, code):
                results['tainted_sources'].append({
                    'param': match.group(1),
                    'line': code[:match.start()].count('\n') + 1
                })
        
        # Find SQL sinks
        sink_patterns = [
            r'mysql_query\([^)]*\)',
            r'mysqli_query\([^)]*\)',
            r'\$pdo->query\([^)]*\)',
            r'\$pdo->exec\([^)]*\)',
        ]
        
        for pattern in sink_patterns:
            for match in re.finditer(pattern, code):
                results['vulnerable_sinks'].append({
                    'sink': match.group(0),
                    'line': code[:match.start()].count('\n') + 1
                })
        
        if results['tainted_sources'] and results['vulnerable_sinks']:
            results['recommendations'].append("Use PDO with prepared statements")
            results['recommendations'].append("Use mysqli_real_escape_string()")
            results['recommendations'].append("Validate input types and formats")
        
        return results
    
    def _analyze_java_code(self, code: str) -> Dict[str, Any]:
        """Analyze Java code for taint flow"""
        results = {
            'tainted_sources': [],
            'vulnerable_sinks': [],
            'recommendations': []
        }
        
        # Find user input sources
        input_patterns = [
            r'request\.getParameter\([\'"](\w+)[\'"]',
            r'request\.getHeader\([\'"](\w+)[\'"]',
        ]
        
        for pattern in input_patterns:
            for match in re.finditer(pattern, code):
                results['tainted_sources'].append({
                    'param': match.group(1),
                    'line': code[:match.start()].count('\n') + 1
                })
        
        # Find SQL sinks
        sink_patterns = [
            r'statement\.execute\([^)]*\)',
            r'statement\.executeQuery\([^)]*\)',
            r'statement\.executeUpdate\([^)]*\)',
        ]
        
        for pattern in sink_patterns:
            for match in re.finditer(pattern, code):
                results['vulnerable_sinks'].append({
                    'sink': match.group(0),
                    'line': code[:match.start()].count('\n') + 1
                })
        
        if results['tainted_sources'] and results['vulnerable_sinks']:
            results['recommendations'].append("Use PreparedStatement instead of Statement")
            results['recommendations'].append("Use parameterized queries")
            results['recommendations'].append("Validate and sanitize inputs")
        
        return results
    
    def get_vulnerability_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive vulnerability report.
        
        Returns:
            Report with all vulnerabilities found
        """
        return {
            'total_tainted_sources': len(self.tainted_sources),
            'total_vulnerabilities': len(self.vulnerability_sinks),
            'tainted_sources': {
                name: {
                    'source': data.source,
                    'taint_level': data.taint_level.name,
                    'sanitization': data.sanitization.name,
                    'confidence': data.confidence
                }
                for name, data in self.tainted_sources.items()
            },
            'vulnerabilities': self.vulnerability_sinks,
            'flow_graph': self.flow_graph
        }
    
    def reset(self):
        """Reset taint tracker state"""
        self.tainted_sources.clear()
        self.sanitized_data.clear()
        self.flow_graph.clear()
        self.vulnerability_sinks.clear()
        logger.info("Taint tracker reset")
