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


class InjectionContext(ABC):
    """
    Abstract base class for injection attack contexts.
    
    Each context (SQL, LDAP, XPath, etc.) implements this interface to provide
    context-specific attack logic, payloads, and response analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the injection context.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.payloads = self._load_payloads()
        self.detection_patterns = self._load_detection_patterns()
    
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
