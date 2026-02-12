"""
Unit tests for enhanced database fingerprinting module
"""

from django.test import TestCase
from sql_attacker.database_fingerprinting import (
    AdvancedDatabaseFingerprinter,
    DatabaseType,
    DatabaseFingerprint
)


class DatabaseFingerprintingTest(TestCase):
    """Test advanced database fingerprinting"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.fingerprinter = AdvancedDatabaseFingerprinter()
    
    def test_initialization(self):
        """Test that fingerprinter initializes correctly"""
        self.assertIsNotNone(self.fingerprinter)
        self.assertEqual(self.fingerprinter.fingerprints_cache, {})
        self.assertIsNone(self.fingerprinter.os_detected)
        self.assertIsNone(self.fingerprinter.architecture_detected)
    
    def test_detect_mysql_from_error(self):
        """Test detecting MySQL from error message"""
        error_text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        
        db_type, confidence = self.fingerprinter.detect_database_type(error_text)
        
        self.assertEqual(db_type, DatabaseType.MYSQL)
        self.assertGreater(confidence, 0.0)
    
    def test_detect_postgresql_from_error(self):
        """Test detecting PostgreSQL from error message"""
        error_text = "PostgreSQL ERROR: syntax error at or near"
        
        db_type, confidence = self.fingerprinter.detect_database_type(error_text)
        
        self.assertEqual(db_type, DatabaseType.POSTGRESQL)
        self.assertGreater(confidence, 0.0)
    
    def test_detect_mssql_from_error(self):
        """Test detecting SQL Server from error message"""
        error_text = "Microsoft SQL Server Native Client error"
        
        db_type, confidence = self.fingerprinter.detect_database_type(error_text)
        
        self.assertEqual(db_type, DatabaseType.MSSQL)
        self.assertGreater(confidence, 0.0)
    
    def test_detect_oracle_from_error(self):
        """Test detecting Oracle from error message"""
        error_text = "ORA-00933: SQL command not properly ended"
        
        db_type, confidence = self.fingerprinter.detect_database_type(error_text)
        
        self.assertEqual(db_type, DatabaseType.ORACLE)
        self.assertGreater(confidence, 0.0)
    
    def test_detect_sqlite_from_error(self):
        """Test detecting SQLite from error message"""
        error_text = "SQLite/JDBCDriver error"
        
        db_type, confidence = self.fingerprinter.detect_database_type(error_text)
        
        self.assertEqual(db_type, DatabaseType.SQLITE)
        self.assertGreater(confidence, 0.0)
    
    def test_detect_unknown_database(self):
        """Test detecting unknown database"""
        error_text = "Some random error without database signatures"
        
        db_type, confidence = self.fingerprinter.detect_database_type(error_text)
        
        self.assertEqual(db_type, DatabaseType.UNKNOWN)
        self.assertEqual(confidence, 0.0)
    
    def test_extract_mysql_version(self):
        """Test extracting MySQL version"""
        response_text = "MySQL server version for the right syntax to use near 'MySQL 5.7.30'"
        
        version = self.fingerprinter.extract_version(response_text, DatabaseType.MYSQL)
        
        self.assertIsNotNone(version)
        self.assertIn('5.7.30', version)
    
    def test_extract_postgresql_version(self):
        """Test extracting PostgreSQL version"""
        response_text = "PostgreSQL 13.2 on x86_64-pc-linux-gnu"
        
        version = self.fingerprinter.extract_version(response_text, DatabaseType.POSTGRESQL)
        
        self.assertIsNotNone(version)
        self.assertIn('13.2', version)
    
    def test_extract_mssql_version(self):
        """Test extracting SQL Server version"""
        response_text = "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5"
        
        version = self.fingerprinter.extract_version(response_text, DatabaseType.MSSQL)
        
        self.assertIsNotNone(version)
    
    def test_detect_edition_mysql(self):
        """Test detecting MySQL edition"""
        response_text = "MySQL 5.7.30-Enterprise"
        version = "5.7.30"
        
        edition = self.fingerprinter.detect_edition(response_text, version, DatabaseType.MYSQL)
        
        self.assertIsNotNone(edition)
        self.assertIn('Enterprise', edition)
    
    def test_detect_edition_mssql(self):
        """Test detecting SQL Server edition"""
        response_text = "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) Enterprise Edition"
        version = "2019"
        
        edition = self.fingerprinter.detect_edition(response_text, version, DatabaseType.MSSQL)
        
        self.assertIsNotNone(edition)
        self.assertIn('Enterprise', edition)
    
    def test_detect_linux_os(self):
        """Test detecting Linux OS"""
        version_info = "PostgreSQL 13.2 on x86_64-pc-linux-gnu"
        
        os_name = self.fingerprinter.detect_operating_system('', version_info)
        
        self.assertEqual(os_name, 'linux')
    
    def test_detect_windows_os(self):
        """Test detecting Windows OS"""
        version_info = "Microsoft SQL Server 2019 on Windows Server 2019"
        
        os_name = self.fingerprinter.detect_operating_system('', version_info)
        
        self.assertEqual(os_name, 'windows')
    
    def test_parse_version_details_mysql(self):
        """Test parsing MySQL version details"""
        version = "5.7.30"
        
        details = self.fingerprinter.parse_version_details(version, DatabaseType.MYSQL)
        
        self.assertEqual(details['major'], 5)
        self.assertEqual(details['minor'], 7)
        self.assertEqual(details['patch'], 30)
        self.assertEqual(details['full_string'], version)
    
    def test_parse_version_details_postgresql(self):
        """Test parsing PostgreSQL version details"""
        version = "PostgreSQL 13.2"
        
        details = self.fingerprinter.parse_version_details(version, DatabaseType.POSTGRESQL)
        
        self.assertEqual(details['major'], 13)
        self.assertEqual(details['minor'], 2)
    
    def test_check_known_vulnerabilities(self):
        """Test checking for known vulnerabilities"""
        # This is a simplified test - real implementation would have more comprehensive checks
        vulnerabilities = self.fingerprinter.check_known_vulnerabilities(
            DatabaseType.MYSQL,
            "5.5.45"
        )
        
        # Should return a list (empty or with vulnerabilities)
        self.assertIsInstance(vulnerabilities, list)
    
    def test_generate_attack_profile_mysql(self):
        """Test generating attack profile for MySQL"""
        fingerprint = DatabaseFingerprint(
            db_type=DatabaseType.MYSQL,
            version="5.7.30",
            version_detail=None,
            edition="Community",
            features=['json_support'],
            privileges=['file_priv'],
            configuration={},
            confidence=0.9
        )
        
        profile = self.fingerprinter.generate_attack_profile(fingerprint)
        
        self.assertIsInstance(profile, dict)
        self.assertIn('priority_techniques', profile)
        self.assertIn('payload_categories', profile)
        self.assertIn('estimated_success_rate', profile)
        self.assertGreater(profile['estimated_success_rate'], 0.0)
        self.assertLessEqual(profile['estimated_success_rate'], 1.0)
    
    def test_generate_attack_profile_postgresql(self):
        """Test generating attack profile for PostgreSQL"""
        fingerprint = DatabaseFingerprint(
            db_type=DatabaseType.POSTGRESQL,
            version="13.2",
            version_detail=None,
            edition=None,
            features=[],
            privileges=['superuser'],
            configuration={},
            confidence=0.85
        )
        
        profile = self.fingerprinter.generate_attack_profile(fingerprint)
        
        self.assertIn('priority_techniques', profile)
        self.assertIn('COPY TO PROGRAM', profile['priority_techniques'][0])
        self.assertGreater(profile['estimated_success_rate'], 0.5)
    
    def test_get_exploitation_hints_mysql(self):
        """Test getting exploitation hints for MySQL"""
        fingerprint = DatabaseFingerprint(
            db_type=DatabaseType.MYSQL,
            version="5.7.30",
            version_detail=None,
            edition=None,
            features=['json_support'],
            privileges=['file_priv'],
            configuration={},
            confidence=0.9
        )
        
        hints = self.fingerprinter.get_exploitation_hints(fingerprint)
        
        self.assertIsInstance(hints, dict)
        self.assertIn('recommended_techniques', hints)
        self.assertIn('dangerous_features', hints)
        self.assertIn('privilege_escalation_possible', hints)
        self.assertIn('FILE privilege', hints['dangerous_features'][0])
    
    def test_get_exploitation_hints_postgresql(self):
        """Test getting exploitation hints for PostgreSQL"""
        fingerprint = DatabaseFingerprint(
            db_type=DatabaseType.POSTGRESQL,
            version="13.2",
            version_detail=None,
            edition=None,
            features=[],
            privileges=['superuser'],
            configuration={},
            confidence=0.85
        )
        
        hints = self.fingerprinter.get_exploitation_hints(fingerprint)
        
        self.assertTrue(hints['privilege_escalation_possible'])
        self.assertIn('Superuser privileges', hints['dangerous_features'])
    
    def test_generate_targeted_payloads_mysql(self):
        """Test generating targeted payloads for MySQL"""
        fingerprint = DatabaseFingerprint(
            db_type=DatabaseType.MYSQL,
            version="5.7.30",
            version_detail=None,
            edition=None,
            features=[],
            privileges=['file_priv'],
            configuration={},
            confidence=0.9
        )
        
        payloads = self.fingerprinter.generate_targeted_payloads(fingerprint)
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
        # Should include LOAD_FILE payload due to file_priv
        self.assertTrue(any('LOAD_FILE' in p for p in payloads))
    
    def test_format_report(self):
        """Test formatting fingerprint report"""
        fingerprint = DatabaseFingerprint(
            db_type=DatabaseType.MYSQL,
            version="5.7.30",
            version_detail=None,
            edition="Community",
            features=['json_support'],
            privileges=['file_priv'],
            configuration={},
            confidence=0.9
        )
        
        report = self.fingerprinter.format_report(fingerprint)
        
        self.assertIsInstance(report, str)
        self.assertIn('DATABASE FINGERPRINT REPORT', report)
        self.assertIn('MYSQL', report)
        self.assertIn('5.7.30', report)
        self.assertIn('Community', report)
        self.assertIn('json_support', report)
        self.assertIn('file_priv', report)
    
    def test_fingerprint_comprehensive(self):
        """Test comprehensive fingerprinting"""
        response_text = "You have an error in your SQL syntax; MySQL server version 5.7.30"
        
        fingerprint = self.fingerprinter.fingerprint(response_text)
        
        self.assertIsInstance(fingerprint, DatabaseFingerprint)
        self.assertEqual(fingerprint.db_type, DatabaseType.MYSQL)
        self.assertGreater(fingerprint.confidence, 0.0)
