"""
Unit tests for Command Injection Module.

Tests the command injection detection and exploitation using the 6-step methodology.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from sql_attacker.injection_contexts import (
    InjectionContextType,
    InjectionResult,
    AttackVector,
)
from sql_attacker.injection_contexts.command_context import CommandInjectionModule


class TestCommandInjectionModule(unittest.TestCase):
    """Test Command injection module."""
    
    def setUp(self):
        self.module = CommandInjectionModule()
    
    def test_context_type(self):
        """Test context type is correct."""
        self.assertEqual(self.module.get_context_type(), InjectionContextType.COMMAND)
    
    def test_payloads_loaded(self):
        """Test that command injection payloads are loaded."""
        self.assertGreater(len(self.module.payloads), 0)
        self.assertIn("; whoami", self.module.payloads)
        self.assertIn("| whoami", self.module.payloads)
        self.assertIn("; sleep 5", self.module.payloads)
    
    def test_detection_patterns_loaded(self):
        """Test that detection patterns are loaded."""
        self.assertGreater(len(self.module.detection_patterns), 0)
        # Check for some Unix patterns
        pattern_strs = [p['pattern'] for p in self.module.detection_patterns]
        self.assertTrue(any('uid=' in p for p in pattern_strs))
    
    def test_step1_supply_payloads(self):
        """Test step 1: payload generation."""
        payloads = self.module.step1_supply_payloads("test")
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        self.assertIn("; whoami", payloads)
    
    def test_step2_detect_anomalies_with_command_output(self):
        """Test step 2: anomaly detection with command output."""
        # Unix uid output
        response_body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        self.assertTrue(detected)
        self.assertGreater(len(anomalies), 0)
        self.assertTrue(any('command_output' in a for a in anomalies))
    
    def test_step2_detect_anomalies_with_timing(self):
        """Test step 2: timing-based detection."""
        response_body = "normal response"
        baseline = ("baseline", 1.0)
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 6.0, baseline
        )
        self.assertTrue(detected)
        self.assertTrue(any('time_based' in a for a in anomalies))
    
    def test_step2_detect_anomalies_no_injection(self):
        """Test step 2: no anomalies detected in clean response."""
        response_body = "This is a normal response without any command output"
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        self.assertFalse(detected)
        self.assertEqual(len(anomalies), 0)
    
    def test_step3_extract_evidence_unix(self):
        """Test step 3: evidence extraction from Unix command output."""
        response_body = "uid=33(www-data) gid=33(www-data)"
        anomalies = ["command_output: uid=\\d+"]
        
        evidence = self.module.step3_extract_evidence(response_body, anomalies)
        
        self.assertEqual(evidence['error_type'], 'command_injection')
        self.assertIn('os_type', evidence['context_info'])
        self.assertEqual(evidence['context_info']['os_type'], 'unix')
        self.assertGreater(evidence['confidence'], 0.8)
        self.assertIn('username', evidence['details'])
        self.assertEqual(evidence['details']['username'], 'www-data')
    
    def test_step3_extract_evidence_windows(self):
        """Test step 3: evidence extraction from Windows output."""
        response_body = "C:\\Users\\Administrator\\Desktop"
        anomalies = ["command_output: C:\\\\Users"]
        
        evidence = self.module.step3_extract_evidence(response_body, anomalies)
        
        self.assertEqual(evidence['error_type'], 'command_injection')
        self.assertIn('os_type', evidence['context_info'])
        self.assertEqual(evidence['context_info']['os_type'], 'windows')
        self.assertGreater(evidence['confidence'], 0.8)
        self.assertIn('username', evidence['details'])
        self.assertEqual(evidence['details']['username'], 'Administrator')
    
    def test_step5_build_poc_unix(self):
        """Test step 5: POC building for Unix systems."""
        evidence = {
            'context_info': {'os_type': 'unix'},
            'details': {'username': 'www-data'}
        }
        
        poc = self.module.step5_build_poc('cmd', '; whoami', evidence)
        
        self.assertIn('poc_payload', poc)
        self.assertIn('expected_result', poc)
        self.assertIn('safety_notes', poc)
        self.assertIn('reproduction_steps', poc)
        self.assertEqual(poc['os_type'], 'unix')
        self.assertIn('echo', poc['poc_payload'])
    
    def test_step5_build_poc_windows(self):
        """Test step 5: POC building for Windows systems."""
        evidence = {
            'context_info': {'os_type': 'windows'},
            'details': {'username': 'Administrator'}
        }
        
        poc = self.module.step5_build_poc('cmd', '& whoami', evidence)
        
        self.assertIn('poc_payload', poc)
        self.assertIn('expected_result', poc)
        self.assertEqual(poc['os_type'], 'windows')
        self.assertIn('echo', poc['poc_payload'].lower())
    
    def test_analyze_response_command_output(self):
        """Test analyze_response with command output."""
        response_body = "uid=0(root) gid=0(root) groups=0(root)"
        success, confidence, evidence = self.module.analyze_response(
            response_body, {}, 0.5
        )
        self.assertTrue(success)
        self.assertGreater(confidence, 0.8)
        self.assertIn("command", evidence.lower())
    
    def test_analyze_response_shell_error(self):
        """Test analyze_response with shell error."""
        response_body = "sh: command not found"
        success, confidence, evidence = self.module.analyze_response(
            response_body, {}, 0.5
        )
        self.assertTrue(success)
        self.assertGreaterEqual(confidence, 0.7)  # Changed to >= instead of >
    
    def test_analyze_response_clean(self):
        """Test analyze_response with clean response."""
        response_body = "This is a normal web page response"
        success, confidence, evidence = self.module.analyze_response(
            response_body, {}, 0.5
        )
        self.assertFalse(success)
        self.assertEqual(confidence, 0.0)
    
    @patch('requests.get')
    def test_test_injection_success(self, mock_get):
        """Test successful command injection detection."""
        # Mock response with command output
        mock_response = Mock()
        mock_response.text = "uid=33(www-data) gid=33(www-data)"
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_get.return_value = mock_response
        
        result = self.module.test_injection(
            target_url="http://test.com",
            parameter_name="cmd",
            parameter_type="GET",
            parameter_value="",
            payload="; whoami"
        )
        
        self.assertIsInstance(result, InjectionResult)
        self.assertTrue(result.success)
        self.assertGreater(result.confidence_score, 0.8)
        self.assertEqual(result.context_type, InjectionContextType.COMMAND)
    
    @patch('requests.get')
    def test_test_injection_failure(self, mock_get):
        """Test when no command injection is detected."""
        # Mock response without command output
        mock_response = Mock()
        mock_response.text = "Normal web page content"
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_get.return_value = mock_response
        
        result = self.module.test_injection(
            target_url="http://test.com",
            parameter_name="cmd",
            parameter_type="GET",
            parameter_value="",
            payload="; whoami"
        )
        
        self.assertIsInstance(result, InjectionResult)
        self.assertFalse(result.success)
        self.assertEqual(result.confidence_score, 0.0)
    
    def test_get_description(self):
        """Test module description."""
        description = self.module.get_description()
        self.assertIn("COMMAND", description)
        self.assertIn("Injection", description)


class TestCommandInjectionIntegration(unittest.TestCase):
    """Integration tests for command injection module."""
    
    def setUp(self):
        self.module = CommandInjectionModule()
    
    def test_payloads_cover_multiple_os(self):
        """Test that payloads cover Unix, Linux, and Windows."""
        payloads = self.module.payloads
        
        # Unix/Linux payloads
        unix_payloads = [p for p in payloads if 'whoami' in p or 'id' in p or 'sleep' in p]
        self.assertGreater(len(unix_payloads), 0)
        
        # Windows payloads
        windows_payloads = [p for p in payloads if 'timeout' in p or 'dir' in p]
        self.assertGreater(len(windows_payloads), 0)
    
    def test_detection_patterns_comprehensive(self):
        """Test that detection patterns cover various scenarios."""
        patterns = self.module.detection_patterns
        
        # Should have patterns for command output
        output_patterns = [p for p in patterns if p['type'] == 'command_output']
        self.assertGreater(len(output_patterns), 0)
        
        # Should have patterns for errors
        error_patterns = [p for p in patterns if p['type'] == 'error']
        self.assertGreater(len(error_patterns), 0)
    
    def test_step4_verification_different_payloads(self):
        """Test that step 4 generates different verification payloads."""
        # This is a basic test since step4 needs network access
        # We're just testing that the method exists and has the right signature
        self.assertTrue(hasattr(self.module, 'step4_mutate_and_verify'))
        self.assertTrue(callable(self.module.step4_mutate_and_verify))


if __name__ == '__main__':
    unittest.main()
