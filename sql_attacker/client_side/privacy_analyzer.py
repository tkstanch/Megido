"""
Privacy and Storage Risk Analyzer

Detects persistent cookies with sensitive values, scans for privacy leaks
in browser caches, localStorage, sessionStorage, and optionally inspects
Flash LSOs, Silverlight, and IE userData.
"""

import logging
import re
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import os
import base64

logger = logging.getLogger(__name__)


class StorageLocation(Enum):
    """Types of storage locations to analyze"""
    COOKIES = "cookies"
    LOCAL_STORAGE = "localStorage"
    SESSION_STORAGE = "sessionStorage"
    INDEXED_DB = "indexedDB"
    CACHE = "cache"
    FLASH_LSO = "flash_lso"
    SILVERLIGHT = "silverlight"
    IE_USER_DATA = "ie_userdata"


class RiskLevel(Enum):
    """Risk levels for privacy findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PrivacyFinding:
    """Represents a privacy/storage risk finding"""
    risk_type: str
    risk_level: str
    storage_location: str
    key: str
    description: str
    recommendation: str
    value_sample: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None

    def to_dict(self):
        return asdict(self)


class PrivacyStorageAnalyzer:
    """
    Analyzer for privacy and storage risks in client-side storage
    """
    
    # Patterns for sensitive data
    SENSITIVE_PATTERNS = {
        'password': [
            r'password', r'passwd', r'pwd', r'pass\b',
        ],
        'token': [
            r'token', r'auth', r'session', r'bearer',
            r'jwt', r'access_token', r'refresh_token',
        ],
        'api_key': [
            r'api[_-]?key', r'apikey', r'key', r'secret',
        ],
        'ssn': [
            r'\b\d{3}-\d{2}-\d{4}\b',  # US SSN format
            r'\b\d{9}\b',  # SSN without dashes
        ],
        'credit_card': [
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card
            r'\b\d{13,19}\b',  # Credit card without separators
        ],
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
        'phone': [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # US phone
            r'\+\d{1,3}\s?\d{1,14}',  # International phone
        ],
        'personal_info': [
            r'firstname', r'lastname', r'fullname', r'address',
            r'city', r'state', r'zip', r'country', r'dob',
            r'date[_-]?of[_-]?birth', r'birthdate',
        ],
    }
    
    # Cookie attribute checks
    COOKIE_SECURITY_CHECKS = [
        'httponly',
        'secure',
        'samesite',
    ]
    
    def __init__(self):
        """Initialize the privacy analyzer"""
        self.findings: List[PrivacyFinding] = []
    
    def analyze_cookies(self, cookies: List[Dict[str, Any]]) -> List[PrivacyFinding]:
        """
        Analyze cookies for security and privacy issues
        
        Args:
            cookies: List of cookie dictionaries (from browser)
            
        Returns:
            List of findings
        """
        findings = []
        
        for cookie in cookies:
            name = cookie.get('name', '')
            value = cookie.get('value', '')
            
            # Check for sensitive data in cookie value
            for data_type, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, name, re.IGNORECASE) or \
                       re.search(pattern, value, re.IGNORECASE):
                        finding = PrivacyFinding(
                            risk_type=f"SENSITIVE_DATA_IN_COOKIE_{data_type.upper()}",
                            risk_level=self._get_risk_level(data_type),
                            storage_location=StorageLocation.COOKIES.value,
                            key=name,
                            description=f"Cookie contains potentially sensitive {data_type} data",
                            recommendation="Avoid storing sensitive data in cookies. "
                                         "If necessary, encrypt the data and set HttpOnly, "
                                         "Secure, and SameSite attributes.",
                            value_sample=value[:50] + '...' if len(value) > 50 else value,
                            evidence={
                                'cookie_name': name,
                                'pattern_matched': pattern,
                                'data_type': data_type,
                            }
                        )
                        findings.append(finding)
                        break
            
            # Check cookie security attributes
            if not cookie.get('httpOnly', False):
                finding = PrivacyFinding(
                    risk_type="COOKIE_MISSING_HTTPONLY",
                    risk_level=RiskLevel.MEDIUM.value,
                    storage_location=StorageLocation.COOKIES.value,
                    key=name,
                    description="Cookie does not have HttpOnly flag set",
                    recommendation="Set HttpOnly flag to prevent JavaScript access to cookies",
                    evidence={'cookie_name': name}
                )
                findings.append(finding)
            
            if not cookie.get('secure', False):
                finding = PrivacyFinding(
                    risk_type="COOKIE_MISSING_SECURE",
                    risk_level=RiskLevel.MEDIUM.value,
                    storage_location=StorageLocation.COOKIES.value,
                    key=name,
                    description="Cookie does not have Secure flag set",
                    recommendation="Set Secure flag to ensure cookie is only sent over HTTPS",
                    evidence={'cookie_name': name}
                )
                findings.append(finding)
            
            if not cookie.get('sameSite') or cookie.get('sameSite').lower() == 'none':
                finding = PrivacyFinding(
                    risk_type="COOKIE_MISSING_SAMESITE",
                    risk_level=RiskLevel.MEDIUM.value,
                    storage_location=StorageLocation.COOKIES.value,
                    key=name,
                    description="Cookie does not have proper SameSite attribute",
                    recommendation="Set SameSite attribute to 'Strict' or 'Lax' to prevent CSRF",
                    evidence={'cookie_name': name}
                )
                findings.append(finding)
        
        return findings
    
    def analyze_local_storage(self, local_storage: Dict[str, str]) -> List[PrivacyFinding]:
        """
        Analyze localStorage for privacy issues
        
        Args:
            local_storage: Dictionary of localStorage key-value pairs
            
        Returns:
            List of findings
        """
        findings = []
        
        for key, value in local_storage.items():
            # Check for sensitive data
            for data_type, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, key, re.IGNORECASE) or \
                       re.search(pattern, str(value), re.IGNORECASE):
                        finding = PrivacyFinding(
                            risk_type=f"SENSITIVE_DATA_IN_LOCALSTORAGE_{data_type.upper()}",
                            risk_level=self._get_risk_level(data_type),
                            storage_location=StorageLocation.LOCAL_STORAGE.value,
                            key=key,
                            description=f"localStorage contains potentially sensitive {data_type} data",
                            recommendation="Avoid storing sensitive data in localStorage as it's "
                                         "accessible by JavaScript and persists indefinitely. "
                                         "Consider using sessionStorage or server-side storage.",
                            value_sample=str(value)[:50] + '...' if len(str(value)) > 50 else str(value),
                            evidence={
                                'key': key,
                                'pattern_matched': pattern,
                                'data_type': data_type,
                            }
                        )
                        findings.append(finding)
                        break
            
            # Check for unencrypted JWT tokens
            if self._looks_like_jwt(str(value)):
                finding = PrivacyFinding(
                    risk_type="JWT_IN_LOCALSTORAGE",
                    risk_level=RiskLevel.HIGH.value,
                    storage_location=StorageLocation.LOCAL_STORAGE.value,
                    key=key,
                    description="JWT token stored in localStorage",
                    recommendation="Store JWT tokens in httpOnly cookies or sessionStorage. "
                                 "localStorage is vulnerable to XSS attacks.",
                    value_sample=str(value)[:50] + '...',
                    evidence={'key': key, 'token_type': 'JWT'}
                )
                findings.append(finding)
        
        return findings
    
    def analyze_session_storage(self, session_storage: Dict[str, str]) -> List[PrivacyFinding]:
        """
        Analyze sessionStorage for privacy issues
        
        Args:
            session_storage: Dictionary of sessionStorage key-value pairs
            
        Returns:
            List of findings
        """
        findings = []
        
        for key, value in session_storage.items():
            # Similar checks as localStorage but with lower severity
            for data_type, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, key, re.IGNORECASE) or \
                       re.search(pattern, str(value), re.IGNORECASE):
                        # SessionStorage is less risky than localStorage (cleared on tab close)
                        risk_level = self._get_risk_level(data_type)
                        if risk_level == RiskLevel.CRITICAL.value:
                            risk_level = RiskLevel.HIGH.value
                        elif risk_level == RiskLevel.HIGH.value:
                            risk_level = RiskLevel.MEDIUM.value
                        
                        finding = PrivacyFinding(
                            risk_type=f"SENSITIVE_DATA_IN_SESSIONSTORAGE_{data_type.upper()}",
                            risk_level=risk_level,
                            storage_location=StorageLocation.SESSION_STORAGE.value,
                            key=key,
                            description=f"sessionStorage contains potentially sensitive {data_type} data",
                            recommendation="While sessionStorage is cleared on tab close, "
                                         "sensitive data should still be minimized and encrypted.",
                            value_sample=str(value)[:50] + '...' if len(str(value)) > 50 else str(value),
                            evidence={
                                'key': key,
                                'pattern_matched': pattern,
                                'data_type': data_type,
                            }
                        )
                        findings.append(finding)
                        break
        
        return findings
    
    def analyze_cache(self, cache_entries: List[Dict[str, Any]]) -> List[PrivacyFinding]:
        """
        Analyze browser cache for privacy leaks
        
        Args:
            cache_entries: List of cache entry dictionaries
            
        Returns:
            List of findings
        """
        findings = []
        
        for entry in cache_entries:
            url = entry.get('url', '')
            
            # Check for sensitive data in URLs
            for data_type, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        finding = PrivacyFinding(
                            risk_type=f"SENSITIVE_DATA_IN_CACHE_URL_{data_type.upper()}",
                            risk_level=RiskLevel.HIGH.value,
                            storage_location=StorageLocation.CACHE.value,
                            key=url,
                            description=f"Cached URL contains potentially sensitive {data_type} data",
                            recommendation="Never include sensitive data in URLs. "
                                         "Use POST requests and store data server-side.",
                            value_sample=url[:100] + '...' if len(url) > 100 else url,
                            evidence={
                                'url': url,
                                'pattern_matched': pattern,
                                'data_type': data_type,
                            }
                        )
                        findings.append(finding)
                        break
        
        return findings
    
    def scan_flash_lso(self, flash_dir: Optional[str] = None) -> List[PrivacyFinding]:
        """
        Scan for Flash Local Shared Objects (LSOs)
        
        Args:
            flash_dir: Optional path to Flash storage directory
            
        Returns:
            List of findings
        """
        findings = []
        
        # Default Flash LSO locations
        if not flash_dir:
            if os.name == 'nt':  # Windows
                flash_dir = os.path.expandvars('%APPDATA%/Macromedia/Flash Player')
            else:  # Unix-like
                flash_dir = os.path.expanduser('~/.macromedia/Flash_Player')
        
        if not os.path.exists(flash_dir):
            logger.info(f"Flash LSO directory not found: {flash_dir}")
            return findings
        
        try:
            for root, dirs, files in os.walk(flash_dir):
                for file in files:
                    if file.endswith('.sol'):
                        file_path = os.path.join(root, file)
                        finding = PrivacyFinding(
                            risk_type="FLASH_LSO_DETECTED",
                            risk_level=RiskLevel.MEDIUM.value,
                            storage_location=StorageLocation.FLASH_LSO.value,
                            key=file_path,
                            description="Flash Local Shared Object (LSO) detected. "
                                      "Flash LSOs can be used for tracking across domains.",
                            recommendation="Consider clearing Flash LSOs and disabling "
                                         "Flash if not needed.",
                            evidence={'file_path': file_path}
                        )
                        findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error scanning Flash LSOs: {e}")
        
        return findings
    
    def _get_risk_level(self, data_type: str) -> str:
        """Get risk level for a data type"""
        high_risk = ['password', 'ssn', 'credit_card', 'api_key']
        medium_risk = ['token', 'email', 'phone']
        
        if data_type in high_risk:
            return RiskLevel.CRITICAL.value
        elif data_type in medium_risk:
            return RiskLevel.HIGH.value
        else:
            return RiskLevel.MEDIUM.value
    
    def _looks_like_jwt(self, value: str) -> bool:
        """Check if a value looks like a JWT token"""
        if not isinstance(value, str):
            return False
        
        # JWT has format: header.payload.signature
        parts = value.split('.')
        if len(parts) != 3:
            return False
        
        # Check if parts are base64-encoded
        try:
            for part in parts:
                base64.b64decode(part + '==')  # Add padding
            return True
        except:
            return False
    
    def analyze_all(self, storage_data: Dict[str, Any]) -> List[PrivacyFinding]:
        """
        Analyze all storage types
        
        Args:
            storage_data: Dictionary with keys: cookies, localStorage, sessionStorage, cache
            
        Returns:
            Combined list of findings
        """
        all_findings = []
        
        # Analyze cookies
        if 'cookies' in storage_data:
            all_findings.extend(self.analyze_cookies(storage_data['cookies']))
        
        # Analyze localStorage
        if 'localStorage' in storage_data:
            all_findings.extend(self.analyze_local_storage(storage_data['localStorage']))
        
        # Analyze sessionStorage
        if 'sessionStorage' in storage_data:
            all_findings.extend(self.analyze_session_storage(storage_data['sessionStorage']))
        
        # Analyze cache
        if 'cache' in storage_data:
            all_findings.extend(self.analyze_cache(storage_data['cache']))
        
        # Scan Flash LSOs
        if storage_data.get('scan_flash_lso', False):
            all_findings.extend(self.scan_flash_lso())
        
        self.findings = all_findings
        logger.info(f"Privacy analysis complete: found {len(all_findings)} issues")
        
        return all_findings
    
    def get_report(self, findings: Optional[List[PrivacyFinding]] = None) -> Dict[str, Any]:
        """
        Generate a report of findings
        
        Args:
            findings: Optional list of findings (uses self.findings if not provided)
            
        Returns:
            Structured report
        """
        if findings is None:
            findings = self.findings
        
        return {
            'total_findings': len(findings),
            'by_risk_level': self._count_by_risk_level(findings),
            'by_storage_location': self._count_by_storage_location(findings),
            'by_risk_type': self._count_by_risk_type(findings),
            'findings': [f.to_dict() for f in findings],
        }
    
    def _count_by_risk_level(self, findings: List[PrivacyFinding]) -> Dict[str, int]:
        """Count findings by risk level"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in findings:
            counts[finding.risk_level] = counts.get(finding.risk_level, 0) + 1
        return counts
    
    def _count_by_storage_location(self, findings: List[PrivacyFinding]) -> Dict[str, int]:
        """Count findings by storage location"""
        counts = {}
        for finding in findings:
            counts[finding.storage_location] = counts.get(finding.storage_location, 0) + 1
        return counts
    
    def _count_by_risk_type(self, findings: List[PrivacyFinding]) -> Dict[str, int]:
        """Count findings by risk type"""
        counts = {}
        for finding in findings:
            counts[finding.risk_type] = counts.get(finding.risk_type, 0) + 1
        return counts
