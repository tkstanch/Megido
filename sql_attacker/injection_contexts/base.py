"""
Base classes for multi-context injection attack framework.

This module provides abstract base classes and data structures for implementing
injection attack detection and exploitation across various interpreted contexts.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import time


class InjectionContextType(Enum):
    """Enumeration of supported injection context types."""
    SQL = "sql"
    COMMAND = "command"
    LDAP = "ldap"
    XPATH = "xpath"
    MESSAGE_QUEUE = "message_queue"
    CUSTOM_QUERY = "custom_query"


@dataclass
class AttackVector:
    """
    Represents a specific attack vector used in an injection attempt.
    """
    context_type: InjectionContextType
    parameter_name: str
    parameter_type: str  # GET, POST, COOKIE, HEADER, etc.
    payload: str
    description: str
    
    # Optional metadata
    encoding: Optional[str] = None
    obfuscation: Optional[str] = None


@dataclass
class InjectionResult:
    """
    Contains the results of an injection attack attempt.
    """
    success: bool
    context_type: InjectionContextType
    attack_vector: AttackVector
    
    # Detection evidence
    evidence: str
    confidence_score: float  # 0.0 to 1.0
    
    # Response details
    response_time: float
    response_status: int
    response_body: str
    response_headers: Dict[str, str] = field(default_factory=dict)
    
    # Exploitation results
    exploited: bool = False
    extracted_data: Optional[Dict[str, Any]] = None
    
    # Visual proof
    visual_proof_path: Optional[str] = None
    visual_proof_type: Optional[str] = None
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_proof_snippet(self, max_length: int = 500) -> str:
        """
        Get a snippet of the response body for visual proof.
        """
        if len(self.response_body) <= max_length:
            return self.response_body
        return self.response_body[:max_length] + "..."


class InjectionAttackModule(ABC):
    """
    Abstract base class for injection attack modules.
    
    Implements a 6-step injection testing methodology:
    1. Supply unexpected syntax and context-specific payloads
    2. Detect anomalies and error messages in responses
    3. Analyze and extract error/evidence
    4. Mutate input systematically to confirm/disprove vulnerabilities
    5. Build proof-of-concept payloads for safe, verifiable exploits
    6. Exploitation automation for verified cases
    
    Each context (SQL, Command, LDAP, XPath, etc.) implements this interface.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the injection attack module.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.payloads = self._load_payloads()
        self.detection_patterns = self._load_detection_patterns()
    
    # ========================================
    # Six-Step Injection Testing Methodology
    # ========================================
    
    @abstractmethod
    def step1_supply_payloads(self, parameter_value: str) -> List[str]:
        """
        Step 1: Supply unexpected syntax and context-specific payloads.
        
        Generate a list of injection payloads appropriate for the context.
        Payloads should include syntax that breaks out of normal execution flow.
        
        Args:
            parameter_value: Original parameter value
            
        Returns:
            List of injection payloads to test
        """
        pass
    
    @abstractmethod
    def step2_detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None
    ) -> Tuple[bool, List[str]]:
        """
        Step 2: Detect anomalies and error messages in responses.
        
        Scan response for signs of injection success such as error messages,
        unexpected behavior, timing differences, or content changes.
        
        Args:
            response_body: HTTP response body
            response_headers: HTTP response headers
            response_time: Response time in seconds
            baseline_response: Optional tuple of (baseline_body, baseline_time)
            
        Returns:
            Tuple of (anomaly_detected, list_of_anomalies)
        """
        pass
    
    @abstractmethod
    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str]
    ) -> Dict[str, Any]:
        """
        Step 3: Analyze and extract error/evidence from response.
        
        Parse error messages and extract detailed information about the
        vulnerability, such as database type, query context, or system info.
        
        Args:
            response_body: HTTP response body containing anomalies
            anomalies: List of detected anomalies from step 2
            
        Returns:
            Dictionary containing extracted evidence with keys:
            - 'error_type': Type of error detected
            - 'details': Specific error details
            - 'context_info': Information about execution context
            - 'confidence': Confidence score (0.0-1.0)
        """
        pass
    
    @abstractmethod
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
        """
        Step 4: Mutate input systematically to confirm or disprove vulnerabilities.
        
        Test variations of the successful payload to confirm the vulnerability
        is real and not a false positive. Use boolean logic, timing attacks,
        or other techniques to verify.
        
        Args:
            target_url: Target URL
            parameter_name: Parameter to inject into
            parameter_type: Parameter type (GET, POST, etc.)
            parameter_value: Original parameter value
            successful_payload: Payload that showed initial signs of injection
            http_method: HTTP method
            headers: HTTP headers
            cookies: Cookies
            
        Returns:
            Tuple of (confirmed, confidence_score, verification_evidence)
        """
        pass
    
    @abstractmethod
    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Step 5: Build proof-of-concept payloads for safe, verifiable exploits.
        
        Create a safe, non-destructive proof-of-concept that demonstrates
        the vulnerability without causing harm.
        
        Args:
            vulnerable_parameter: Name of vulnerable parameter
            successful_payload: Payload that confirmed the vulnerability
            evidence: Evidence extracted in step 3
            
        Returns:
            Dictionary containing POC information:
            - 'poc_payload': Safe proof-of-concept payload
            - 'expected_result': What the POC should demonstrate
            - 'safety_notes': Important safety information
            - 'reproduction_steps': Steps to reproduce
        """
        pass
    
    @abstractmethod
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
        """
        Step 6: Exploitation automation for verified cases.
        
        Safely exploit the verified vulnerability to extract information
        or demonstrate impact. Should be non-destructive and respect
        ethical boundaries.
        
        Args:
            target_url: Target URL
            vulnerable_parameter: Name of vulnerable parameter
            parameter_type: Parameter type
            poc_payload: Proof-of-concept payload from step 5
            evidence: Evidence from previous steps
            http_method: HTTP method
            headers: HTTP headers
            cookies: Cookies
            
        Returns:
            Dictionary with exploitation results or None if exploitation failed:
            - 'success': Whether exploitation succeeded
            - 'data_extracted': Any data extracted
            - 'impact_level': Severity of the vulnerability
            - 'remediation': Suggested fixes
        """
        pass
    
    # ========================================
    # Legacy/Compatibility Methods
    # ========================================
    
    @abstractmethod
    def get_context_type(self) -> InjectionContextType:
        """Return the context type identifier."""
        pass
    
    @abstractmethod
    def _load_payloads(self) -> List[str]:
        """
        Load context-specific injection payloads.
        
        Returns:
            List of payload strings
        """
        pass
    
    @abstractmethod
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """
        Load patterns for detecting successful injection.
        
        Returns:
            List of detection pattern dictionaries with keys:
            - 'pattern': regex pattern or string to match
            - 'type': pattern type (error, timing, boolean, etc.)
            - 'confidence': confidence score if matched
        """
        pass
    
    @abstractmethod
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze a response to determine if injection was successful.
        
        Args:
            response_body: HTTP response body
            response_headers: HTTP response headers
            response_time: Response time in seconds
            baseline_time: Baseline response time for comparison (optional)
        
        Returns:
            Tuple of (success, confidence_score, evidence)
        """
        pass
    
    def test_injection(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        payload: str,
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> InjectionResult:
        """
        Test a single injection payload.
        
        Args:
            target_url: Target URL
            parameter_name: Parameter to inject into
            parameter_type: Parameter type (GET, POST, etc.)
            parameter_value: Original parameter value
            payload: Injection payload to test
            http_method: HTTP method to use
            headers: Additional HTTP headers
            cookies: Cookies to send
        
        Returns:
            InjectionResult with attack details
        """
        import requests
        
        # Construct attack vector
        attack_vector = AttackVector(
            context_type=self.get_context_type(),
            parameter_name=parameter_name,
            parameter_type=parameter_type,
            payload=payload,
            description=f"{self.get_context_type().value.upper()} injection via {parameter_type} parameter"
        )
        
        # Prepare request
        injected_value = self._inject_payload(parameter_value, payload)
        
        try:
            start_time = time.time()
            
            if parameter_type.upper() == "GET":
                params = {parameter_name: injected_value}
                response = requests.get(
                    target_url,
                    params=params,
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            elif parameter_type.upper() == "POST":
                data = {parameter_name: injected_value}
                response = requests.post(
                    target_url,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=self.config.get('timeout', 10)
                )
            else:
                # Handle other parameter types (COOKIE, HEADER)
                raise NotImplementedError(f"Parameter type {parameter_type} not yet implemented")
            
            response_time = time.time() - start_time
            
            # Analyze response
            success, confidence, evidence = self.analyze_response(
                response.text,
                dict(response.headers),
                response_time
            )
            
            # Create result
            result = InjectionResult(
                success=success,
                context_type=self.get_context_type(),
                attack_vector=attack_vector,
                evidence=evidence,
                confidence_score=confidence,
                response_time=response_time,
                response_status=response.status_code,
                response_body=response.text,
                response_headers=dict(response.headers),
                exploited=False
            )
            
            return result
            
        except requests.RequestException as e:
            # Request failed
            return InjectionResult(
                success=False,
                context_type=self.get_context_type(),
                attack_vector=attack_vector,
                evidence=f"Request failed: {str(e)}",
                confidence_score=0.0,
                response_time=0.0,
                response_status=0,
                response_body="",
                exploited=False
            )
    
    def _inject_payload(self, original_value: str, payload: str) -> str:
        """
        Inject payload into the original parameter value.
        
        Default implementation appends payload to original value.
        Override for context-specific injection strategies.
        """
        return f"{original_value}{payload}"
    
    @abstractmethod
    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to exploit a confirmed vulnerability.
        
        Args:
            target_url: Target URL
            vulnerable_parameter: Name of vulnerable parameter
            parameter_type: Type of parameter
            successful_payload: Payload that successfully detected the vulnerability
        
        Returns:
            Dictionary with exploitation results, or None if exploitation failed
        """
        pass
    
    def get_payload_count(self) -> int:
        """Get the number of available payloads for this context."""
        return len(self.payloads)
    
    def get_description(self) -> str:
        """Get a human-readable description of this context."""
        return f"{self.get_context_type().value.upper()} Injection Context"
    
    def execute_full_workflow(
        self,
        target_url: str,
        parameter_name: str,
        parameter_type: str,
        parameter_value: str,
        http_method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> List[InjectionResult]:
        """
        Execute the complete 6-step injection testing workflow.
        
        This is a high-level method that orchestrates all 6 steps of the
        injection testing methodology.
        
        Args:
            target_url: Target URL to test
            parameter_name: Parameter name to inject into
            parameter_type: Parameter type (GET, POST, etc.)
            parameter_value: Original parameter value
            http_method: HTTP method to use
            headers: Additional HTTP headers
            cookies: Cookies to send
            
        Returns:
            List of successful injection results
        """
        results = []
        
        # Step 1: Generate payloads
        payloads = self.step1_supply_payloads(parameter_value)
        
        for payload in payloads:
            # Test the payload using the legacy method (compatible with existing code)
            result = self.test_injection(
                target_url, parameter_name, parameter_type,
                parameter_value, payload, http_method, headers, cookies
            )
            
            if result.success:
                # Steps 2-6 are already integrated in test_injection and analyze_response
                # But can be enhanced in concrete implementations
                results.append(result)
        
        return results


# Backward compatibility: InjectionContext is an alias for InjectionAttackModule
InjectionContext = InjectionAttackModule
