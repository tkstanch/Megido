"""
Unit tests for JavaScript Static Scanner

Tests static analysis with sample JavaScript code.
"""

import unittest
import os
import tempfile
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_side.static_scanner import (
    JavaScriptStaticScanner,
    StaticFinding,
    VulnerabilityType
)


class TestJavaScriptStaticScanner(unittest.TestCase):
    """Test cases for JavaScriptStaticScanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = JavaScriptStaticScanner()
    
    def test_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(len(self.scanner.findings), 0)
    
    def test_unsafe_open_database_detection(self):
        """Test detection of unsafe openDatabase usage"""
        code = """
        var db = openDatabase('mydb', '1.0', 'Test DB', 2 * 1024 * 1024);
        var userInput = document.location.search;
        db.transaction(function(tx) {
            tx.executeSql('SELECT * FROM users WHERE id = ' + userInput);
        });
        """
        
        findings = self.scanner.scan_code(code, "test.js")
        
        # Should detect openDatabase with tainted input
        self.assertGreater(len(findings), 0)
        
        # Check for openDatabase finding
        open_db_findings = [f for f in findings if 'openDatabase' in f.vulnerability_type]
        self.assertGreater(len(open_db_findings), 0)
    
    def test_unsafe_local_storage_detection(self):
        """Test detection of unsafe localStorage usage"""
        code = """
        var userInput = window.location.hash;
        localStorage.setItem('user_data', 'value' + userInput);
        """
        
        findings = self.scanner.scan_code(code, "test.js")
        
        # Should detect localStorage with concatenation
        storage_findings = [f for f in findings if 'localStorage' in f.vulnerability_type.lower()]
        self.assertGreater(len(storage_findings), 0)
    
    def test_unsafe_indexed_db_detection(self):
        """Test detection of unsafe indexedDB usage"""
        code = """
        var request = indexedDB.open('MyDatabase', 1);
        var userInput = document.URL;
        objectStore.add({name: 'test' + userInput});
        """
        
        findings = self.scanner.scan_code(code, "test.js")
        
        # Should detect indexedDB operations
        self.assertGreater(len(findings), 0)
    
    def test_web_sql_injection_detection(self):
        """Test detection of Web SQL injection"""
        code = """
        var userInput = document.location.search;
        db.transaction(function(tx) {
            tx.executeSql('SELECT * FROM users WHERE name = "' + userInput + '"');
        });
        """
        
        findings = self.scanner.scan_code(code, "test.js")
        
        # Should detect SQL concatenation
        sql_findings = [f for f in findings if f.severity == "CRITICAL"]
        self.assertGreater(len(sql_findings), 0)
    
    def test_tainted_input_detection(self):
        """Test detection of tainted input sources"""
        code = """
        var input1 = document.location;
        var input2 = window.location.hash;
        var input3 = document.URL;
        var input4 = document.referrer;
        """
        
        findings = self.scanner.scan_code(code, "test.js")
        
        # Code has tainted input but not necessarily used unsafely
        # Findings depend on usage context
        self.assertIsInstance(findings, list)
    
    def test_sql_concatenation_with_tainted_input(self):
        """Test detection of SQL concatenation with tainted input"""
        code = """
        var id = document.location.search.split('=')[1];
        var query = 'SELECT * FROM users WHERE id = ' + id;
        """
        
        findings = self.scanner.scan_code(code, "test.js")
        
        # Should detect SQL concatenation with tainted input
        critical_findings = [f for f in findings if f.severity == "CRITICAL"]
        self.assertGreater(len(critical_findings), 0)
    
    def test_scan_file(self):
        """Test scanning a file"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write("""
            var db = openDatabase('test', '1.0', 'Test', 1024);
            var input = window.location.hash;
            """)
            temp_file = f.name
        
        try:
            findings = self.scanner.scan_file(temp_file)
            self.assertIsInstance(findings, list)
        finally:
            os.unlink(temp_file)
    
    def test_report_generation(self):
        """Test report generation"""
        # Add some findings
        self.scanner.findings = [
            StaticFinding(
                vulnerability_type="UNSAFE_OPEN_DATABASE",
                severity="HIGH",
                file_path="test.js",
                line_number=10,
                code_snippet="openDatabase(...)",
                description="Test description",
                recommendation="Test recommendation"
            ),
            StaticFinding(
                vulnerability_type="SQL_CONCATENATION",
                severity="CRITICAL",
                file_path="test.js",
                line_number=20,
                code_snippet="query = 'SELECT' + input",
                description="Test description",
                recommendation="Test recommendation"
            ),
        ]
        
        report = self.scanner.get_report()
        
        self.assertEqual(report['total_findings'], 2)
        self.assertEqual(report['by_severity']['CRITICAL'], 1)
        self.assertEqual(report['by_severity']['HIGH'], 1)
    
    def test_html_report_generation(self):
        """Test HTML report generation"""
        self.scanner.findings = [
            StaticFinding(
                vulnerability_type="TEST",
                severity="HIGH",
                file_path="test.js",
                line_number=1,
                code_snippet="test code",
                description="test",
                recommendation="test"
            ),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            output_file = f.name
        
        try:
            result = self.scanner.generate_html_report(output_file=output_file)
            self.assertTrue(os.path.exists(result))
            
            # Check HTML content
            with open(result, 'r') as f:
                content = f.read()
                self.assertIn('<html>', content)
                self.assertIn('TEST', content)
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_safe_code_no_findings(self):
        """Test that safe code produces no findings"""
        code = """
        // Safe code with no vulnerabilities
        function add(a, b) {
            return a + b;
        }
        console.log(add(1, 2));
        """
        
        findings = self.scanner.scan_code(code, "safe.js")
        
        # Should have no findings for safe code
        self.assertEqual(len(findings), 0)


class TestStaticFinding(unittest.TestCase):
    """Test cases for StaticFinding dataclass"""
    
    def test_finding_creation(self):
        """Test StaticFinding creation"""
        finding = StaticFinding(
            vulnerability_type="TEST",
            severity="HIGH",
            file_path="test.js",
            line_number=42,
            code_snippet="test code",
            description="test description",
            recommendation="test recommendation",
            confidence="HIGH"
        )
        
        self.assertEqual(finding.vulnerability_type, "TEST")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.line_number, 42)
        self.assertEqual(finding.confidence, "HIGH")
    
    def test_finding_to_dict(self):
        """Test conversion to dictionary"""
        finding = StaticFinding(
            vulnerability_type="TEST",
            severity="HIGH",
            file_path="test.js",
            line_number=1,
            code_snippet="code",
            description="desc",
            recommendation="rec"
        )
        
        result = finding.to_dict()
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result['vulnerability_type'], "TEST")
        self.assertEqual(result['severity'], "HIGH")


if __name__ == '__main__':
    unittest.main()
