"""
Unit tests for advanced privilege escalation module
"""

from django.test import TestCase
from sql_attacker.privilege_escalation import (
    AdvancedPrivilegeEscalation,
    PrivilegeLevel,
    DangerousCapability,
    PrivilegeEscalationPath
)


class PrivilegeEscalationTest(TestCase):
    """Test advanced privilege escalation detection"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.priv_escalation = AdvancedPrivilegeEscalation()
    
    def test_initialization(self):
        """Test that privilege escalation detector initializes correctly"""
        self.assertIsNotNone(self.priv_escalation)
        self.assertEqual(self.priv_escalation.detected_privileges, {})
        self.assertEqual(self.priv_escalation.detected_capabilities, {})
        self.assertEqual(self.priv_escalation.escalation_paths, [])
    
    def test_privilege_queries_exist(self):
        """Test that privilege queries are defined for all databases"""
        expected_databases = ['mysql', 'postgresql', 'mssql', 'oracle', 'sqlite']
        
        for db in expected_databases:
            if db != 'sqlite':  # SQLite has limited privilege system
                self.assertIn(db, self.priv_escalation.PRIVILEGE_QUERIES)
                queries = self.priv_escalation.PRIVILEGE_QUERIES[db]
                self.assertIn('current_user', queries)
    
    def test_capability_tests_exist(self):
        """Test that capability tests are defined"""
        expected_databases = ['mysql', 'postgresql', 'mssql', 'oracle']
        
        for db in expected_databases:
            self.assertIn(db, self.priv_escalation.CAPABILITY_TESTS)
    
    def test_escalation_paths_exist(self):
        """Test that escalation paths are defined"""
        expected_databases = ['mysql', 'postgresql', 'mssql', 'oracle']
        
        for db in expected_databases:
            self.assertIn(db, self.priv_escalation.ESCALATION_PATHS)
            paths = self.priv_escalation.ESCALATION_PATHS[db]
            self.assertGreater(len(paths), 0)
    
    def test_find_escalation_paths_no_capabilities(self):
        """Test finding escalation paths with no capabilities"""
        privileges = {
            'user': 'testuser',
            'database': 'testdb',
            'privilege_level': PrivilegeLevel.USER,
            'specific_privileges': [],
            'is_admin': False,
            'is_dba': False,
        }
        
        capabilities = {
            DangerousCapability.FILE_READ: False,
            DangerousCapability.FILE_WRITE: False,
            DangerousCapability.COMMAND_EXECUTION: False,
        }
        
        paths = self.priv_escalation.find_escalation_paths(
            'mysql',
            privileges,
            capabilities
        )
        
        # Should still return paths but with lower exploitability
        self.assertIsInstance(paths, list)
    
    def test_find_escalation_paths_with_capabilities(self):
        """Test finding escalation paths with dangerous capabilities"""
        privileges = {
            'user': 'admin',
            'database': 'testdb',
            'privilege_level': PrivilegeLevel.ADMIN,
            'specific_privileges': ['FILE'],
            'is_admin': True,
            'is_dba': False,
        }
        
        capabilities = {
            DangerousCapability.FILE_READ: True,
            DangerousCapability.FILE_WRITE: True,
            DangerousCapability.COMMAND_EXECUTION: False,
        }
        
        paths = self.priv_escalation.find_escalation_paths(
            'mysql',
            privileges,
            capabilities
        )
        
        self.assertGreater(len(paths), 0)
        
        # Check that paths have correct structure
        for path in paths:
            self.assertIsInstance(path, PrivilegeEscalationPath)
            self.assertIsInstance(path.name, str)
            self.assertIsInstance(path.description, str)
            self.assertIsInstance(path.steps, list)
            self.assertIsInstance(path.payloads, list)
            self.assertIn(path.risk_level, ['low', 'medium', 'high', 'critical'])
            self.assertGreaterEqual(path.exploitability, 0.0)
            self.assertLessEqual(path.exploitability, 1.0)
    
    def test_generate_report(self):
        """Test report generation"""
        # Set up some dummy data
        self.priv_escalation.detected_privileges = {
            'user': 'testuser@localhost',
            'database': 'testdb',
            'privilege_level': PrivilegeLevel.USER,
            'specific_privileges': ['SELECT', 'INSERT'],
            'is_admin': False,
            'is_dba': False,
        }
        
        self.priv_escalation.detected_capabilities = {
            DangerousCapability.FILE_READ: True,
            DangerousCapability.FILE_WRITE: False,
        }
        
        report = self.priv_escalation.generate_report('mysql')
        
        # Check report content
        self.assertIsInstance(report, str)
        self.assertIn('PRIVILEGE ESCALATION ANALYSIS', report)
        self.assertIn('testuser@localhost', report)
        self.assertIn('testdb', report)
        self.assertIn('CURRENT PRIVILEGES', report)
    
    def test_generate_escalation_payloads_mysql(self):
        """Test payload generation for MySQL"""
        privileges = {'user': 'root@localhost'}
        payloads = self.priv_escalation._generate_escalation_payloads(
            'mysql',
            'FILE Privilege to System Access',
            privileges
        )
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_generate_escalation_payloads_postgresql(self):
        """Test payload generation for PostgreSQL"""
        privileges = {'user': 'postgres'}
        payloads = self.priv_escalation._generate_escalation_payloads(
            'postgresql',
            'COPY TO PROGRAM Command Execution',
            privileges
        )
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_generate_escalation_payloads_mssql(self):
        """Test payload generation for SQL Server"""
        privileges = {'user': 'sa'}
        payloads = self.priv_escalation._generate_escalation_payloads(
            'mssql',
            'xp_cmdshell Command Execution',
            privileges
        )
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_privilege_level_enum(self):
        """Test PrivilegeLevel enum"""
        self.assertEqual(PrivilegeLevel.NONE.value, 'none')
        self.assertEqual(PrivilegeLevel.USER.value, 'user')
        self.assertEqual(PrivilegeLevel.ADMIN.value, 'admin')
        self.assertEqual(PrivilegeLevel.DBA.value, 'dba')
        self.assertEqual(PrivilegeLevel.SYSTEM.value, 'system')
    
    def test_dangerous_capability_enum(self):
        """Test DangerousCapability enum"""
        self.assertEqual(DangerousCapability.FILE_READ.value, 'file_read')
        self.assertEqual(DangerousCapability.FILE_WRITE.value, 'file_write')
        self.assertEqual(DangerousCapability.COMMAND_EXECUTION.value, 'command_execution')
        self.assertEqual(DangerousCapability.NETWORK_ACCESS.value, 'network_access')


class PrivilegeEscalationPathTest(TestCase):
    """Test PrivilegeEscalationPath dataclass"""
    
    def test_escalation_path_creation(self):
        """Test creating an escalation path"""
        path = PrivilegeEscalationPath(
            name='Test Escalation',
            description='Test description',
            current_privilege=PrivilegeLevel.USER,
            target_privilege=PrivilegeLevel.ADMIN,
            capabilities_required=[DangerousCapability.FILE_WRITE],
            steps=['Step 1', 'Step 2'],
            risk_level='high',
            exploitability=0.8,
            payloads=['payload1', 'payload2']
        )
        
        self.assertEqual(path.name, 'Test Escalation')
        self.assertEqual(path.description, 'Test description')
        self.assertEqual(path.current_privilege, PrivilegeLevel.USER)
        self.assertEqual(path.target_privilege, PrivilegeLevel.ADMIN)
        self.assertEqual(len(path.capabilities_required), 1)
        self.assertEqual(len(path.steps), 2)
        self.assertEqual(path.risk_level, 'high')
        self.assertEqual(path.exploitability, 0.8)
        self.assertEqual(len(path.payloads), 2)
