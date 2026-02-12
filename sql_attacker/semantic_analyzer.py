"""
Advanced Semantic Analysis Module for SQL Injection Detection

Implements AST-based semantic analysis to reduce false positives:
- SQL syntax parsing and validation
- Context-aware pattern matching
- Semantic understanding of SQL queries
- Hybrid static/dynamic analysis
"""

import ast
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SQLContext(Enum):
    """SQL injection context types"""
    STRING_LITERAL = "string_literal"
    NUMERIC_LITERAL = "numeric_literal"
    IDENTIFIER = "identifier"
    COMMENT = "comment"
    WHERE_CLAUSE = "where_clause"
    ORDER_BY = "order_by"
    UNION_SELECT = "union_select"
    UNKNOWN = "unknown"


@dataclass
class SQLToken:
    """Represents a SQL token in the query"""
    type: str
    value: str
    position: int
    context: SQLContext


class SemanticAnalyzer:
    """
    Advanced semantic analyzer for SQL injection detection.
    Uses AST-like parsing and context analysis to reduce false positives.
    """
    
    # SQL keywords for context detection
    SQL_KEYWORDS = {
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'ORDER', 'BY',
        'GROUP', 'HAVING', 'UNION', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER',
        'ON', 'AND', 'OR', 'NOT', 'IN', 'EXISTS', 'BETWEEN', 'LIKE', 'IS', 'NULL'
    }
    
    # SQL functions
    SQL_FUNCTIONS = {
        'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'CONCAT', 'SUBSTRING', 'CHAR',
        'ASCII', 'LENGTH', 'SLEEP', 'BENCHMARK', 'WAITFOR', 'PG_SLEEP',
        'LOAD_FILE', 'INTO', 'OUTFILE', 'DUMPFILE'
    }
    
    # Dangerous SQL patterns (high risk)
    DANGEROUS_PATTERNS = [
        r'UNION\s+(?:ALL\s+)?SELECT',
        r';\s*(?:DROP|DELETE|UPDATE|INSERT)',
        r'INTO\s+(?:OUTFILE|DUMPFILE)',
        r'LOAD_FILE\s*\(',
        r'xp_cmdshell',
        r'sp_executesql',
        r'EXEC\s*\(',
    ]
    
    def __init__(self):
        """Initialize the semantic analyzer"""
        self.whitelist_patterns = []
        self.context_rules = {}
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default semantic analysis rules"""
        # Whitelist common legitimate patterns
        self.whitelist_patterns = [
            r'^[a-zA-Z0-9_\-\.@]+$',  # Simple alphanumeric
            r'^\d+$',  # Pure numeric
            r'^[a-zA-Z\s]+$',  # Pure alphabetic with spaces
        ]
        
        # Context-specific rules
        self.context_rules = {
            SQLContext.NUMERIC_LITERAL: {
                'allowed_patterns': [r'^\d+$', r'^-?\d+\.?\d*$'],
                'suspicious_patterns': [r'[^\d\.\-]']
            },
            SQLContext.STRING_LITERAL: {
                'allowed_patterns': [r'^[^\'\"]*$'],
                'suspicious_patterns': [r'[\'\"]\s*(?:OR|AND)', r'--', r'/\*', r'\*/']
            }
        }
    
    def analyze_input(self, input_value: str, context: SQLContext = SQLContext.UNKNOWN) -> Dict[str, Any]:
        """
        Perform semantic analysis on input value.
        
        Args:
            input_value: The input to analyze
            context: The SQL context of the input
            
        Returns:
            Analysis results with risk score and details
        """
        result = {
            'risk_score': 0.0,
            'is_suspicious': False,
            'detected_patterns': [],
            'context': context.value,
            'tokens': [],
            'semantic_issues': [],
            'confidence': 0.0
        }
        
        if not input_value:
            return result
        
        # Check whitelist first
        if self._is_whitelisted(input_value):
            result['confidence'] = 0.95
            return result
        
        # Tokenize the input
        tokens = self._tokenize(input_value)
        result['tokens'] = [{'type': t.type, 'value': t.value} for t in tokens]
        
        # Analyze tokens for SQL injection patterns
        risk_score = 0.0
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, input_value, re.IGNORECASE):
                risk_score += 0.3
                result['detected_patterns'].append(pattern)
                result['semantic_issues'].append(f"Dangerous pattern detected: {pattern}")
        
        # Check for SQL keywords
        keyword_count = sum(1 for token in tokens if token.value.upper() in self.SQL_KEYWORDS)
        if keyword_count > 2:
            risk_score += 0.2 * min(keyword_count, 5)
            result['semantic_issues'].append(f"Multiple SQL keywords detected: {keyword_count}")
        
        # Check for comment injection
        if self._contains_sql_comment(input_value):
            risk_score += 0.15
            result['semantic_issues'].append("SQL comment detected")
        
        # Check for quote escaping attempts
        if self._contains_quote_escape(input_value):
            risk_score += 0.15
            result['semantic_issues'].append("Quote escape attempt detected")
        
        # Check for stacked queries
        if ';' in input_value and any(kw in input_value.upper() for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
            risk_score += 0.25
            result['semantic_issues'].append("Stacked query detected")
        
        # Context-specific validation
        if context != SQLContext.UNKNOWN:
            context_risk = self._validate_context(input_value, context)
            risk_score += context_risk
            if context_risk > 0:
                result['semantic_issues'].append(f"Context validation failed for {context.value}")
        
        # Normalize risk score
        result['risk_score'] = min(risk_score, 1.0)
        result['is_suspicious'] = result['risk_score'] > 0.3
        result['confidence'] = min(result['risk_score'] * 1.2, 1.0)
        
        return result
    
    def _tokenize(self, input_value: str) -> List[SQLToken]:
        """
        Tokenize SQL input for analysis.
        
        Args:
            input_value: Input to tokenize
            
        Returns:
            List of SQLToken objects
        """
        tokens = []
        position = 0
        
        # Simple tokenization (can be enhanced with proper SQL parser)
        token_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*|'[^']*'|\"[^\"]*\"|\d+|[^\w\s])"
        
        for match in re.finditer(token_pattern, input_value):
            value = match.group(0)
            token_type = self._classify_token(value)
            context = self._infer_context(value, token_type)
            
            token = SQLToken(
                type=token_type,
                value=value,
                position=position,
                context=context
            )
            tokens.append(token)
            position += 1
        
        return tokens
    
    def _classify_token(self, value: str) -> str:
        """Classify a token type"""
        if value.upper() in self.SQL_KEYWORDS:
            return 'KEYWORD'
        elif value.upper() in self.SQL_FUNCTIONS:
            return 'FUNCTION'
        elif value.startswith("'") or value.startswith('"'):
            return 'STRING_LITERAL'
        elif value.isdigit():
            return 'NUMERIC_LITERAL'
        elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', value):
            return 'IDENTIFIER'
        else:
            return 'OPERATOR'
    
    def _infer_context(self, value: str, token_type: str) -> SQLContext:
        """Infer SQL context from token"""
        if token_type == 'STRING_LITERAL':
            return SQLContext.STRING_LITERAL
        elif token_type == 'NUMERIC_LITERAL':
            return SQLContext.NUMERIC_LITERAL
        elif token_type == 'IDENTIFIER':
            return SQLContext.IDENTIFIER
        else:
            return SQLContext.UNKNOWN
    
    def _is_whitelisted(self, input_value: str) -> bool:
        """Check if input matches whitelist patterns"""
        for pattern in self.whitelist_patterns:
            if re.match(pattern, input_value):
                return True
        return False
    
    def _validate_context(self, input_value: str, context: SQLContext) -> float:
        """
        Validate input against context rules.
        
        Returns:
            Risk score (0.0 to 1.0)
        """
        if context not in self.context_rules:
            return 0.0
        
        rules = self.context_rules[context]
        risk = 0.0
        
        # Check allowed patterns
        allowed = rules.get('allowed_patterns', [])
        if allowed and not any(re.match(p, input_value) for p in allowed):
            risk += 0.15
        
        # Check suspicious patterns
        suspicious = rules.get('suspicious_patterns', [])
        for pattern in suspicious:
            if re.search(pattern, input_value):
                risk += 0.2
        
        return risk
    
    def _contains_sql_comment(self, input_value: str) -> bool:
        """Check for SQL comment patterns"""
        comment_patterns = [r'--', r'/\*', r'\*/', r'#']
        return any(pattern in input_value for pattern in comment_patterns)
    
    def _contains_quote_escape(self, input_value: str) -> bool:
        """Check for quote escape attempts"""
        escape_patterns = [r"\\['\"']", r"''", r'""', r"['\"]\\"]
        return any(re.search(pattern, input_value) for pattern in escape_patterns)
    
    def add_whitelist_pattern(self, pattern: str):
        """Add a pattern to the whitelist"""
        self.whitelist_patterns.append(pattern)
        logger.info(f"Added whitelist pattern: {pattern}")
    
    def remove_whitelist_pattern(self, pattern: str):
        """Remove a pattern from the whitelist"""
        if pattern in self.whitelist_patterns:
            self.whitelist_patterns.remove(pattern)
            logger.info(f"Removed whitelist pattern: {pattern}")
    
    def validate_sql_syntax(self, query: str, db_type: str = 'mysql') -> Tuple[bool, str]:
        """
        Validate SQL syntax (basic validation).
        
        Args:
            query: SQL query to validate
            db_type: Database type (mysql, postgresql, mssql, oracle)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Basic syntax validation
        try:
            # Check balanced parentheses
            if query.count('(') != query.count(')'):
                return False, "Unbalanced parentheses"
            
            # Check balanced quotes
            if query.count("'") % 2 != 0:
                return False, "Unbalanced single quotes"
            
            if query.count('"') % 2 != 0:
                return False, "Unbalanced double quotes"
            
            # Check for common syntax errors
            if re.search(r',\s*(?:FROM|WHERE|GROUP|ORDER|HAVING)', query, re.IGNORECASE):
                return False, "Trailing comma before clause"
            
            return True, ""
            
        except Exception as e:
            return False, str(e)
    
    def get_injection_confidence(self, analysis_result: Dict[str, Any]) -> float:
        """
        Calculate overall confidence that input is SQL injection.
        
        Args:
            analysis_result: Result from analyze_input()
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not analysis_result['is_suspicious']:
            return 0.0
        
        # Weight different factors
        weights = {
            'risk_score': 0.4,
            'pattern_count': 0.3,
            'semantic_issues': 0.3
        }
        
        risk = analysis_result['risk_score']
        pattern_score = min(len(analysis_result['detected_patterns']) * 0.2, 1.0)
        semantic_score = min(len(analysis_result['semantic_issues']) * 0.15, 1.0)
        
        confidence = (
            risk * weights['risk_score'] +
            pattern_score * weights['pattern_count'] +
            semantic_score * weights['semantic_issues']
        )
        
        return min(confidence, 1.0)
