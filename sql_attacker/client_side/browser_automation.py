"""
Browser Automation Worker for Client-Side SQL Injection Testing

Uses Playwright (with Selenium fallback) to inject SQLi payloads into HTML5 storage-backed forms,
scan for JavaScript/SQL errors, and monitor local storage for corruption or leakage.
"""

import logging
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class StorageType(Enum):
    """Types of browser storage to test"""
    LOCAL_STORAGE = "localStorage"
    SESSION_STORAGE = "sessionStorage"
    INDEXED_DB = "indexedDB"
    COOKIES = "cookies"
    WEB_SQL = "webSQL"


@dataclass
class BrowserFinding:
    """Represents a finding from browser automation testing"""
    finding_type: str
    severity: str
    url: str
    payload: str
    storage_type: Optional[str] = None
    error_message: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class BrowserAutomationWorker:
    """
    Browser automation worker for testing client-side SQL injection vulnerabilities
    """
    
    # SQL injection payloads for HTML5 storage
    HTML5_STORAGE_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "<script>alert('XSS')</script>",
        "admin'--",
        "1' UNION SELECT null--",
        "' OR 1=1--",
        "javascript:alert(1)",
        "' AND SLEEP(5)--",
    ]
    
    def __init__(self, use_playwright: bool = True, headless: bool = True, timeout: int = 30000):
        """
        Initialize browser automation worker
        
        Args:
            use_playwright: Use Playwright if True, else Selenium
            headless: Run browser in headless mode
            timeout: Timeout in milliseconds
        """
        self.use_playwright = use_playwright
        self.headless = headless
        self.timeout = timeout
        self.browser = None
        self.context = None
        self.page = None
        self.findings: List[BrowserFinding] = []
        
    def initialize_browser(self) -> bool:
        """Initialize the browser instance"""
        try:
            if self.use_playwright:
                return self._init_playwright()
            else:
                return self._init_selenium()
        except Exception as e:
            logger.error(f"Failed to initialize browser: {e}")
            return False
    
    def _init_playwright(self) -> bool:
        """Initialize Playwright browser"""
        try:
            from playwright.sync_api import sync_playwright
            
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(headless=self.headless)
            self.context = self.browser.new_context()
            self.page = self.context.new_page()
            self.page.set_default_timeout(self.timeout)
            
            # Set up console message listener
            self.page.on("console", self._handle_console_message)
            # Set up error listener
            self.page.on("pageerror", self._handle_page_error)
            
            logger.info("Playwright browser initialized successfully")
            return True
        except ImportError:
            logger.warning("Playwright not available, falling back to Selenium")
            self.use_playwright = False
            return self._init_selenium()
        except Exception as e:
            logger.error(f"Playwright initialization failed: {e}")
            return False
    
    def _init_selenium(self) -> bool:
        """Initialize Selenium browser"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service
            
            options = Options()
            if self.headless:
                options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            
            service = Service(ChromeDriverManager().install())
            self.browser = webdriver.Chrome(service=service, options=options)
            self.browser.set_page_load_timeout(self.timeout // 1000)
            
            logger.info("Selenium browser initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Selenium initialization failed: {e}")
            return False
    
    def _handle_console_message(self, msg):
        """Handle console messages from the page"""
        msg_text = str(msg.text).lower()
        
        # Check for SQL-related errors
        sql_keywords = ['sql', 'database', 'query', 'syntax error', 'sqlite', 'websql']
        if any(keyword in msg_text for keyword in sql_keywords):
            finding = BrowserFinding(
                finding_type="SQL_ERROR_IN_CONSOLE",
                severity="HIGH",
                url=self.page.url if self.page else "unknown",
                payload="",
                error_message=msg.text,
                evidence={"console_type": msg.type, "location": msg.location}
            )
            self.findings.append(finding)
            logger.warning(f"SQL error detected in console: {msg.text}")
    
    def _handle_page_error(self, error):
        """Handle page errors"""
        error_msg = str(error).lower()
        
        # Check for SQL-related errors
        if any(keyword in error_msg for keyword in ['sql', 'database', 'query']):
            finding = BrowserFinding(
                finding_type="SQL_ERROR_IN_PAGE",
                severity="HIGH",
                url=self.page.url if self.page else "unknown",
                payload="",
                error_message=str(error)
            )
            self.findings.append(finding)
            logger.warning(f"SQL error detected on page: {error}")
    
    def scan_form(self, url: str, form_selector: Optional[str] = None) -> List[BrowserFinding]:
        """
        Scan forms on a page for SQL injection vulnerabilities
        
        Args:
            url: Target URL
            form_selector: Optional CSS selector for specific form
            
        Returns:
            List of findings
        """
        self.findings = []
        
        if not self.initialize_browser():
            logger.error("Failed to initialize browser")
            return self.findings
        
        try:
            if self.use_playwright:
                return self._scan_form_playwright(url, form_selector)
            else:
                return self._scan_form_selenium(url, form_selector)
        finally:
            self.cleanup()
    
    def _scan_form_playwright(self, url: str, form_selector: Optional[str]) -> List[BrowserFinding]:
        """Scan forms using Playwright"""
        try:
            self.page.goto(url)
            
            # Find all forms or specific form
            if form_selector:
                forms = self.page.query_selector_all(form_selector)
            else:
                forms = self.page.query_selector_all('form')
            
            logger.info(f"Found {len(forms)} forms on {url}")
            
            for i, form in enumerate(forms):
                # Find all input fields in the form
                inputs = form.query_selector_all('input, textarea')
                
                for payload in self.HTML5_STORAGE_PAYLOADS:
                    # Fill inputs with payload
                    for input_elem in inputs:
                        try:
                            input_elem.fill(payload)
                        except:
                            pass
                    
                    # Check storage before submission
                    storage_before = self._get_storage_state()
                    
                    # Submit form (try both button and Enter key)
                    submit_button = form.query_selector('button[type="submit"], input[type="submit"]')
                    if submit_button:
                        submit_button.click()
                    else:
                        # Try pressing Enter on first input
                        if inputs:
                            inputs[0].press('Enter')
                    
                    # Wait a bit for processing
                    self.page.wait_for_timeout(1000)
                    
                    # Check storage after submission
                    storage_after = self._get_storage_state()
                    
                    # Detect storage corruption or leakage
                    self._check_storage_corruption(url, payload, storage_before, storage_after)
            
            return self.findings
            
        except Exception as e:
            logger.error(f"Error scanning forms with Playwright: {e}")
            return self.findings
    
    def _scan_form_selenium(self, url: str, form_selector: Optional[str]) -> List[BrowserFinding]:
        """Scan forms using Selenium"""
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.common.keys import Keys
            from selenium.common.exceptions import TimeoutException, NoSuchElementException
            
            self.browser.get(url)
            time.sleep(2)  # Wait for page load
            
            # Find forms
            if form_selector:
                forms = self.browser.find_elements(By.CSS_SELECTOR, form_selector)
            else:
                forms = self.browser.find_elements(By.TAG_NAME, 'form')
            
            logger.info(f"Found {len(forms)} forms on {url}")
            
            for form in forms:
                inputs = form.find_elements(By.CSS_SELECTOR, 'input, textarea')
                
                for payload in self.HTML5_STORAGE_PAYLOADS:
                    # Fill inputs
                    for input_elem in inputs:
                        try:
                            input_elem.clear()
                            input_elem.send_keys(payload)
                        except:
                            pass
                    
                    # Get storage state before
                    storage_before = self._get_storage_state_selenium()
                    
                    # Submit
                    try:
                        submit_btn = form.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                        submit_btn.click()
                    except NoSuchElementException:
                        if inputs:
                            inputs[0].send_keys(Keys.RETURN)
                    
                    time.sleep(1)
                    
                    # Get storage state after
                    storage_after = self._get_storage_state_selenium()
                    
                    # Check for corruption
                    self._check_storage_corruption(url, payload, storage_before, storage_after)
            
            return self.findings
            
        except Exception as e:
            logger.error(f"Error scanning forms with Selenium: {e}")
            return self.findings
    
    def _get_storage_state(self) -> Dict[str, Any]:
        """Get current storage state using Playwright"""
        try:
            storage = {
                'localStorage': self.page.evaluate('() => Object.assign({}, localStorage)'),
                'sessionStorage': self.page.evaluate('() => Object.assign({}, sessionStorage)'),
                'cookies': self.context.cookies(),
            }
            return storage
        except Exception as e:
            logger.error(f"Error getting storage state: {e}")
            return {}
    
    def _get_storage_state_selenium(self) -> Dict[str, Any]:
        """Get current storage state using Selenium"""
        try:
            local_storage = self.browser.execute_script('return Object.assign({}, localStorage);')
            session_storage = self.browser.execute_script('return Object.assign({}, sessionStorage);')
            cookies = self.browser.get_cookies()
            
            return {
                'localStorage': local_storage,
                'sessionStorage': session_storage,
                'cookies': cookies,
            }
        except Exception as e:
            logger.error(f"Error getting storage state: {e}")
            return {}
    
    def _check_storage_corruption(self, url: str, payload: str, 
                                   storage_before: Dict, storage_after: Dict):
        """Check for storage corruption or leakage"""
        try:
            # Check localStorage changes
            for storage_type in ['localStorage', 'sessionStorage']:
                before = storage_before.get(storage_type, {})
                after = storage_after.get(storage_type, {})
                
                # Check for payload in storage
                for key, value in after.items():
                    if payload in str(value) or payload in str(key):
                        finding = BrowserFinding(
                            finding_type="PAYLOAD_IN_STORAGE",
                            severity="MEDIUM",
                            url=url,
                            payload=payload,
                            storage_type=storage_type,
                            evidence={
                                'key': key,
                                'value': value,
                            }
                        )
                        self.findings.append(finding)
                        logger.warning(f"Payload found in {storage_type}: {key}={value}")
                
                # Check for corrupted/malformed data
                for key, value in after.items():
                    if key not in before:
                        # New key added
                        if self._is_corrupted_data(value):
                            finding = BrowserFinding(
                                finding_type="STORAGE_CORRUPTION",
                                severity="HIGH",
                                url=url,
                                payload=payload,
                                storage_type=storage_type,
                                evidence={
                                    'key': key,
                                    'corrupted_value': str(value)[:200],
                                }
                            )
                            self.findings.append(finding)
                            logger.warning(f"Storage corruption detected in {storage_type}: {key}")
        
        except Exception as e:
            logger.error(f"Error checking storage corruption: {e}")
    
    def _is_corrupted_data(self, value: Any) -> bool:
        """Check if data appears corrupted"""
        if not isinstance(value, str):
            return False
        
        # Check for SQL injection indicators (case-insensitive)
        sql_indicators = ['null', 'undefined', 'nan', 'syntax error', 'database']
        value_lower = value.lower()
        return any(indicator in value_lower for indicator in sql_indicators)
    
    def monitor_storage_changes(self, url: str, duration: int = 10) -> List[BrowserFinding]:
        """
        Monitor storage changes over time
        
        Args:
            url: Target URL
            duration: Monitoring duration in seconds
            
        Returns:
            List of findings
        """
        self.findings = []
        
        if not self.initialize_browser():
            return self.findings
        
        try:
            self.page.goto(url) if self.use_playwright else self.browser.get(url)
            
            # Get initial state
            initial_storage = self._get_storage_state() if self.use_playwright else self._get_storage_state_selenium()
            
            # Monitor for duration
            start_time = time.time()
            while time.time() - start_time < duration:
                time.sleep(1)
                
                current_storage = self._get_storage_state() if self.use_playwright else self._get_storage_state_selenium()
                
                # Check for unexpected changes
                self._detect_storage_leakage(url, initial_storage, current_storage)
            
            return self.findings
        
        finally:
            self.cleanup()
    
    def _detect_storage_leakage(self, url: str, initial: Dict, current: Dict):
        """Detect privacy leakage in storage"""
        # Check for sensitive data patterns
        sensitive_patterns = [
            r'password', r'token', r'api[_-]?key', r'secret',
            r'ssn', r'credit[_-]?card', r'cvv', r'pin',
        ]
        
        import re
        
        for storage_type in ['localStorage', 'sessionStorage']:
            initial_items = initial.get(storage_type, {})
            current_items = current.get(storage_type, {})
            
            for key, value in current_items.items():
                if key not in initial_items:
                    # New item - check for sensitive data
                    value_str = str(value).lower()
                    for pattern in sensitive_patterns:
                        if re.search(pattern, value_str):
                            finding = BrowserFinding(
                                finding_type="SENSITIVE_DATA_LEAKAGE",
                                severity="CRITICAL",
                                url=url,
                                payload="",
                                storage_type=storage_type,
                                evidence={
                                    'key': key,
                                    'pattern': pattern,
                                    'value_sample': value_str[:50],
                                }
                            )
                            self.findings.append(finding)
                            logger.critical(f"Sensitive data detected in {storage_type}: {key}")
    
    def cleanup(self):
        """Clean up browser resources"""
        try:
            if self.use_playwright:
                if self.page:
                    self.page.close()
                if self.context:
                    self.context.close()
                if self.browser:
                    self.browser.close()
                if hasattr(self, 'playwright'):
                    self.playwright.stop()
            else:
                if self.browser:
                    self.browser.quit()
            
            logger.info("Browser cleaned up successfully")
        except Exception as e:
            logger.error(f"Error cleaning up browser: {e}")
    
    def get_findings_report(self) -> Dict[str, Any]:
        """Get a structured report of findings"""
        return {
            'total_findings': len(self.findings),
            'by_severity': self._count_by_severity(),
            'by_type': self._count_by_type(),
            'findings': [f.to_dict() for f in self.findings],
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count findings by type"""
        counts = {}
        for finding in self.findings:
            counts[finding.finding_type] = counts.get(finding.finding_type, 0) + 1
        return counts
