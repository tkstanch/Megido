"""
HTTP Parameter Pollution (HPP) Detector

Generates URLs with duplicated or encoded parameters and observes
unwanted behaviors or actions to detect HPP vulnerabilities.
"""

import logging
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import requests
from enum import Enum

logger = logging.getLogger(__name__)


class HPPTechnique(Enum):
    """HTTP Parameter Pollution techniques"""
    DUPLICATE_PARAM = "duplicate_parameter"
    ENCODED_PARAM = "encoded_parameter"
    MIXED_CASE = "mixed_case"
    ARRAY_NOTATION = "array_notation"
    SEMICOLON_SEPARATOR = "semicolon_separator"
    AMPERSAND_ENCODED = "ampersand_encoded"


@dataclass
class HPPFinding:
    """Represents an HPP vulnerability finding"""
    technique: str
    severity: str
    url: str
    original_params: Dict[str, str]
    polluted_params: str
    response_code: int
    response_diff: Optional[str] = None
    behavior: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None

    def to_dict(self):
        return asdict(self)


class HTTPParameterPollutionDetector:
    """
    Detector for HTTP Parameter Pollution vulnerabilities
    """
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True, 
                 follow_redirects: bool = True):
        """
        Initialize HPP detector
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
            follow_redirects: Follow HTTP redirects
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.findings: List[HPPFinding] = []
        self.session = requests.Session()
    
    def scan_url(self, url: str, test_params: Optional[Dict[str, str]] = None) -> List[HPPFinding]:
        """
        Scan a URL for HPP vulnerabilities
        
        Args:
            url: Target URL
            test_params: Optional parameters to test (if None, uses existing URL params)
            
        Returns:
            List of findings
        """
        self.findings = []
        
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Get parameters
        if test_params:
            params = test_params
        else:
            params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            logger.warning(f"No parameters found in URL: {url}")
            return self.findings
        
        # Get baseline response
        try:
            baseline_response = self._make_request(base_url, params)
        except Exception as e:
            logger.error(f"Failed to get baseline response: {e}")
            return self.findings
        
        # Test each HPP technique
        for param_name, param_value in params.items():
            self._test_duplicate_parameter(base_url, params, param_name, param_value, baseline_response)
            self._test_encoded_parameter(base_url, params, param_name, param_value, baseline_response)
            self._test_mixed_case(base_url, params, param_name, param_value, baseline_response)
            self._test_array_notation(base_url, params, param_name, param_value, baseline_response)
            self._test_semicolon_separator(base_url, params, param_name, param_value, baseline_response)
            self._test_ampersand_encoded(base_url, params, param_name, param_value, baseline_response)
        
        logger.info(f"HPP scan complete: found {len(self.findings)} potential vulnerabilities")
        return self.findings
    
    def _make_request(self, url: str, params: Dict[str, str]) -> requests.Response:
        """Make HTTP request"""
        return self.session.get(
            url,
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=self.follow_redirects
        )
    
    def _make_request_raw(self, full_url: str) -> requests.Response:
        """Make HTTP request with raw URL (for testing pollution)"""
        return self.session.get(
            full_url,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=self.follow_redirects
        )
    
    def _test_duplicate_parameter(self, base_url: str, params: Dict[str, str],
                                  param_name: str, param_value: str,
                                  baseline: requests.Response):
        """Test duplicate parameter pollution"""
        # Create polluted URL with duplicate parameter
        test_params = params.copy()
        
        # Build URL with duplicate parameters manually
        param_list = []
        for k, v in test_params.items():
            if k == param_name:
                # Add parameter twice with different values
                param_list.append(f"{k}={urllib.parse.quote(param_value)}")
                param_list.append(f"{k}={urllib.parse.quote('polluted_' + param_value)}")
            else:
                param_list.append(f"{k}={urllib.parse.quote(v)}")
        
        polluted_url = f"{base_url}?{'&'.join(param_list)}"
        
        try:
            response = self._make_request_raw(polluted_url)
            
            # Check for differences
            if self._has_significant_difference(baseline, response):
                finding = HPPFinding(
                    technique=HPPTechnique.DUPLICATE_PARAM.value,
                    severity="MEDIUM",
                    url=base_url,
                    original_params=params,
                    polluted_params=polluted_url,
                    response_code=response.status_code,
                    response_diff=f"Baseline: {len(baseline.content)} bytes, "
                                 f"Polluted: {len(response.content)} bytes",
                    behavior="Parameter duplication changed response",
                    evidence={
                        'baseline_length': len(baseline.content),
                        'polluted_length': len(response.content),
                        'status_code_diff': baseline.status_code != response.status_code,
                    }
                )
                self.findings.append(finding)
                logger.warning(f"HPP duplicate parameter vulnerability found: {param_name}")
        
        except Exception as e:
            logger.debug(f"Error testing duplicate parameter: {e}")
    
    def _test_encoded_parameter(self, base_url: str, params: Dict[str, str],
                               param_name: str, param_value: str,
                               baseline: requests.Response):
        """Test encoded parameter pollution"""
        # Try different encodings
        encodings = [
            ('double_encode', urllib.parse.quote(urllib.parse.quote(param_value))),
            ('unicode_encode', param_value.encode('unicode_escape').decode()),
            ('hex_encode', ''.join(f'%{ord(c):02x}' for c in param_value)),
        ]
        
        for encoding_name, encoded_value in encodings:
            test_params = params.copy()
            test_params[param_name] = encoded_value
            
            try:
                param_list = [f"{k}={urllib.parse.quote(v)}" for k, v in test_params.items()]
                polluted_url = f"{base_url}?{'&'.join(param_list)}"
                
                response = self._make_request_raw(polluted_url)
                
                if self._has_significant_difference(baseline, response):
                    finding = HPPFinding(
                        technique=HPPTechnique.ENCODED_PARAM.value,
                        severity="LOW",
                        url=base_url,
                        original_params=params,
                        polluted_params=polluted_url,
                        response_code=response.status_code,
                        behavior=f"Encoded parameter ({encoding_name}) changed response",
                        evidence={
                            'encoding_type': encoding_name,
                            'encoded_value': encoded_value[:100],
                        }
                    )
                    self.findings.append(finding)
            
            except Exception as e:
                logger.debug(f"Error testing encoded parameter: {e}")
    
    def _test_mixed_case(self, base_url: str, params: Dict[str, str],
                        param_name: str, param_value: str,
                        baseline: requests.Response):
        """Test mixed case parameter names"""
        # Test uppercase, lowercase, and mixed case
        case_variants = [
            param_name.upper(),
            param_name.lower(),
            ''.join(c.upper() if i % 2 else c.lower() 
                   for i, c in enumerate(param_name)),
        ]
        
        for variant in case_variants:
            if variant == param_name:
                continue
            
            test_params = params.copy()
            # Remove original and add variant
            del test_params[param_name]
            test_params[variant] = param_value
            
            try:
                response = self._make_request(base_url, test_params)
                
                if self._has_significant_difference(baseline, response):
                    finding = HPPFinding(
                        technique=HPPTechnique.MIXED_CASE.value,
                        severity="LOW",
                        url=base_url,
                        original_params=params,
                        polluted_params=urllib.parse.urlencode(test_params),
                        response_code=response.status_code,
                        behavior="Case variation in parameter name changed response",
                        evidence={
                            'original_name': param_name,
                            'variant_name': variant,
                        }
                    )
                    self.findings.append(finding)
            
            except Exception as e:
                logger.debug(f"Error testing mixed case: {e}")
    
    def _test_array_notation(self, base_url: str, params: Dict[str, str],
                            param_name: str, param_value: str,
                            baseline: requests.Response):
        """Test array notation pollution"""
        # Test param[] notation
        test_params = params.copy()
        del test_params[param_name]
        
        # Build URL with array notation
        param_list = []
        for k, v in params.items():
            if k == param_name:
                param_list.append(f"{k}[]={urllib.parse.quote(param_value)}")
                param_list.append(f"{k}[]={urllib.parse.quote('polluted')}")
            else:
                param_list.append(f"{k}={urllib.parse.quote(v)}")
        
        polluted_url = f"{base_url}?{'&'.join(param_list)}"
        
        try:
            response = self._make_request_raw(polluted_url)
            
            if self._has_significant_difference(baseline, response):
                finding = HPPFinding(
                    technique=HPPTechnique.ARRAY_NOTATION.value,
                    severity="MEDIUM",
                    url=base_url,
                    original_params=params,
                    polluted_params=polluted_url,
                    response_code=response.status_code,
                    behavior="Array notation changed response behavior",
                    evidence={
                        'parameter': param_name,
                        'array_notation': f"{param_name}[]",
                    }
                )
                self.findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error testing array notation: {e}")
    
    def _test_semicolon_separator(self, base_url: str, params: Dict[str, str],
                                  param_name: str, param_value: str,
                                  baseline: requests.Response):
        """Test semicolon as parameter separator"""
        # Build URL with semicolon separator
        param_list = [f"{k}={urllib.parse.quote(v)}" for k, v in params.items()]
        polluted_url = f"{base_url}?{';'.join(param_list)}"
        
        try:
            response = self._make_request_raw(polluted_url)
            
            if self._has_significant_difference(baseline, response):
                finding = HPPFinding(
                    technique=HPPTechnique.SEMICOLON_SEPARATOR.value,
                    severity="LOW",
                    url=base_url,
                    original_params=params,
                    polluted_params=polluted_url,
                    response_code=response.status_code,
                    behavior="Semicolon separator changed response",
                )
                self.findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error testing semicolon separator: {e}")
    
    def _test_ampersand_encoded(self, base_url: str, params: Dict[str, str],
                               param_name: str, param_value: str,
                               baseline: requests.Response):
        """Test encoded ampersand in parameters"""
        # Encode ampersand as %26
        param_list = [f"{k}={urllib.parse.quote(v)}" for k, v in params.items()]
        polluted_url = f"{base_url}?{'%26'.join(param_list)}"
        
        try:
            response = self._make_request_raw(polluted_url)
            
            if self._has_significant_difference(baseline, response):
                finding = HPPFinding(
                    technique=HPPTechnique.AMPERSAND_ENCODED.value,
                    severity="LOW",
                    url=base_url,
                    original_params=params,
                    polluted_params=polluted_url,
                    response_code=response.status_code,
                    behavior="Encoded ampersand changed response",
                )
                self.findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error testing encoded ampersand: {e}")
    
    def _has_significant_difference(self, baseline: requests.Response, 
                                   test: requests.Response) -> bool:
        """Check if two responses are significantly different"""
        # Check status code
        if baseline.status_code != test.status_code:
            return True
        
        # Check content length difference (>10%)
        baseline_len = len(baseline.content)
        test_len = len(test.content)
        
        if baseline_len > 0:
            diff_percent = abs(baseline_len - test_len) / baseline_len
            if diff_percent > 0.1:  # 10% difference
                return True
        
        # Check for error messages in response
        error_keywords = [
            b'error', b'exception', b'warning', b'invalid',
            b'sql', b'database', b'query', b'syntax',
        ]
        
        test_content_lower = test.content.lower()
        baseline_content_lower = baseline.content.lower()
        
        for keyword in error_keywords:
            if keyword in test_content_lower and keyword not in baseline_content_lower:
                return True
        
        return False
    
    def get_report(self) -> Dict[str, Any]:
        """Generate a report of findings"""
        return {
            'total_findings': len(self.findings),
            'by_severity': self._count_by_severity(),
            'by_technique': self._count_by_technique(),
            'findings': [f.to_dict() for f in self.findings],
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
    
    def _count_by_technique(self) -> Dict[str, int]:
        """Count findings by technique"""
        counts = {}
        for finding in self.findings:
            counts[finding.technique] = counts.get(finding.technique, 0) + 1
        return counts
    
    def generate_test_urls(self, base_url: str, params: Dict[str, str]) -> Dict[str, List[str]]:
        """
        Generate test URLs for all HPP techniques
        
        Args:
            base_url: Base URL
            params: Parameters to test
            
        Returns:
            Dictionary mapping technique to list of test URLs
        """
        test_urls = {}
        
        for param_name, param_value in params.items():
            # Duplicate parameter
            param_list = []
            for k, v in params.items():
                if k == param_name:
                    param_list.append(f"{k}={urllib.parse.quote(param_value)}")
                    param_list.append(f"{k}={urllib.parse.quote('test2')}")
                else:
                    param_list.append(f"{k}={urllib.parse.quote(v)}")
            
            test_urls.setdefault('duplicate', []).append(
                f"{base_url}?{'&'.join(param_list)}"
            )
            
            # Array notation
            param_list = []
            for k, v in params.items():
                if k == param_name:
                    param_list.append(f"{k}[]={urllib.parse.quote(param_value)}")
                else:
                    param_list.append(f"{k}={urllib.parse.quote(v)}")
            
            test_urls.setdefault('array', []).append(
                f"{base_url}?{'&'.join(param_list)}"
            )
        
        return test_urls
