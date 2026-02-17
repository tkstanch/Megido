"""
Unit tests for SQL Attacker Second-Order Examples Module

Tests all components including:
- Second-order injection payload generation
- Destructive query generation
- Numeric exploitation utilities
- Binary search algorithms
- Workflow generation
"""

from django.test import TestCase
from sql_attacker.sql_attacker_second_order_examples import (
    SecondOrderInjection,
    DestructiveQueries,
    NumericExploitation,
    ExploitationWorkflow,
    DBMSType,
)


class SecondOrderInjectionTest(TestCase):
    """Test SecondOrderInjection class functionality"""
    
    def test_scenarios_exist(self):
        """Test that second-order scenarios are defined"""
        self.assertGreater(len(SecondOrderInjection.SCENARIOS), 0)
        self.assertIn('user_registration', SecondOrderInjection.SCENARIOS)
        self.assertIn('password_change', SecondOrderInjection.SCENARIOS)
        self.assertIn('profile_update', SecondOrderInjection.SCENARIOS)
    
    def test_scenario_structure(self):
        """Test that scenarios have required fields"""
        for scenario_name, scenario in SecondOrderInjection.SCENARIOS.items():
            self.assertIn('description', scenario)
            self.assertIn('step_1_payload', scenario)
            self.assertIn('step_2_query', scenario)
            self.assertIn('impact', scenario)
    
    def test_get_second_order_payloads_mysql(self):
        """Test MySQL second-order payload generation"""
        payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MYSQL)
        
        self.assertIn('username_payloads', payloads)
        self.assertIn('email_payloads', payloads)
        self.assertIn('mysql_specific', payloads)
        
        # Check for specific MySQL payloads
        self.assertTrue(any("admin'--" in p for p in payloads['username_payloads']))
        self.assertTrue(any("UNION SELECT" in p for p in payloads['username_payloads']))
    
    def test_get_second_order_payloads_mssql(self):
        """Test MS-SQL second-order payload generation"""
        payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MSSQL)
        
        self.assertIn('mssql_specific', payloads)
        self.assertTrue(any('xp_cmdshell' in p for p in payloads['mssql_specific']))
    
    def test_get_second_order_payloads_postgresql(self):
        """Test PostgreSQL second-order payload generation"""
        payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.POSTGRESQL)
        
        self.assertIn('postgresql_specific', payloads)
        self.assertTrue(any('COPY' in p for p in payloads['postgresql_specific']))
    
    def test_generate_second_order_test_vectors(self):
        """Test test vector generation"""
        vectors = SecondOrderInjection.generate_second_order_test_vectors()
        
        self.assertGreater(len(vectors), 0)
        
        for vector in vectors:
            self.assertIn('name', vector)
            self.assertIn('initial_payload', vector)
            self.assertIn('storage_query', vector)
            self.assertIn('vulnerable_query', vector)
            self.assertIn('exploitation', vector)
            self.assertIn('severity', vector)
    
    def test_test_vector_severity_levels(self):
        """Test that test vectors have appropriate severity levels"""
        vectors = SecondOrderInjection.generate_second_order_test_vectors()
        
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for vector in vectors:
            self.assertIn(vector['severity'], valid_severities)


class DestructiveQueriesTest(TestCase):
    """Test DestructiveQueries class functionality"""
    
    def test_get_destructive_payloads_mysql(self):
        """Test MySQL destructive payload generation"""
        payloads = DestructiveQueries.get_destructive_payloads(DBMSType.MYSQL)
        
        self.assertIn('shutdown', payloads)
        self.assertIn('drop_database', payloads)
        self.assertIn('drop_tables', payloads)
        self.assertIn('user_manipulation', payloads)
        
        # Check payload structure
        for category in payloads.values():
            for item in category:
                self.assertIn('payload', item)
                self.assertIn('description', item)
                self.assertIn('privileges', item)
                self.assertIn('impact', item)
    
    def test_get_destructive_payloads_mssql(self):
        """Test MS-SQL destructive payload generation"""
        payloads = DestructiveQueries.get_destructive_payloads(DBMSType.MSSQL)
        
        self.assertIn('shutdown', payloads)
        self.assertIn('command_execution', payloads)
        
        # Check for xp_cmdshell usage
        cmd_exec = payloads['command_execution']
        self.assertTrue(any('xp_cmdshell' in item['payload'] for item in cmd_exec))
    
    def test_get_destructive_payloads_postgresql(self):
        """Test PostgreSQL destructive payload generation"""
        payloads = DestructiveQueries.get_destructive_payloads(DBMSType.POSTGRESQL)
        
        self.assertIn('shutdown', payloads)
        self.assertIn('command_execution', payloads)
        
        # Check for PostgreSQL-specific functions
        self.assertTrue(any('pg_terminate_backend' in item['payload'] 
                          for item in payloads['shutdown']))
    
    def test_get_destructive_payloads_oracle(self):
        """Test Oracle destructive payload generation"""
        payloads = DestructiveQueries.get_destructive_payloads(DBMSType.ORACLE)
        
        self.assertIn('shutdown', payloads)
        self.assertTrue(any('SHUTDOWN IMMEDIATE' in item['payload'] 
                          for item in payloads['shutdown']))
    
    def test_get_privilege_escalation_payloads_mysql(self):
        """Test MySQL privilege escalation payloads"""
        payloads = DestructiveQueries.get_privilege_escalation_payloads(DBMSType.MYSQL)
        
        self.assertGreater(len(payloads), 0)
        for payload in payloads:
            self.assertIn('technique', payload)
            self.assertIn('payload', payload)
            self.assertIn('description', payload)
            self.assertIn('prerequisites', payload)
    
    def test_get_privilege_escalation_payloads_mssql(self):
        """Test MS-SQL privilege escalation payloads"""
        payloads = DestructiveQueries.get_privilege_escalation_payloads(DBMSType.MSSQL)
        
        self.assertGreater(len(payloads), 0)
        # Check for sysadmin role escalation
        self.assertTrue(any('sysadmin' in p['payload'] for p in payloads))
    
    def test_destructive_payload_warnings(self):
        """Test that destructive payloads contain appropriate warnings"""
        for dbms in [DBMSType.MYSQL, DBMSType.MSSQL, DBMSType.POSTGRESQL]:
            payloads = DestructiveQueries.get_destructive_payloads(dbms)
            
            # At least one category should exist
            self.assertGreater(len(payloads), 0)
            
            # All payloads should have impact descriptions
            for category in payloads.values():
                for item in category:
                    self.assertIsNotNone(item['impact'])
                    self.assertGreater(len(item['impact']), 0)


class NumericExploitationTest(TestCase):
    """Test NumericExploitation class functionality"""
    
    def test_generate_ascii_extraction_payload_mysql(self):
        """Test MySQL ASCII extraction payload generation"""
        payload = NumericExploitation.generate_ascii_extraction_payload(
            DBMSType.MYSQL,
            'users',
            'username',
            1,
            'id=1'
        )
        
        self.assertIn('ASCII', payload)
        self.assertIn('SUBSTRING', payload)
        self.assertIn('users', payload)
        self.assertIn('username', payload)
        self.assertIn('id=1', payload)
        self.assertIn('{ASCII_VALUE}', payload)
    
    def test_generate_ascii_extraction_payload_postgresql(self):
        """Test PostgreSQL ASCII extraction payload generation"""
        payload = NumericExploitation.generate_ascii_extraction_payload(
            DBMSType.POSTGRESQL,
            'accounts',
            'password',
            5,
            'username=\'admin\''
        )
        
        self.assertIn('ASCII', payload)
        self.assertIn('SUBSTRING', payload)
        self.assertIn('accounts', payload)
        self.assertIn('password', payload)
    
    def test_generate_ascii_extraction_payload_mssql(self):
        """Test MS-SQL ASCII extraction payload generation"""
        payload = NumericExploitation.generate_ascii_extraction_payload(
            DBMSType.MSSQL,
            'users',
            'email',
            1,
            '1=1'
        )
        
        self.assertIn('ASCII', payload)
        self.assertIn('SUBSTRING', payload)
        self.assertIn('TOP 1', payload)  # MS-SQL specific
    
    def test_generate_ascii_extraction_payload_oracle(self):
        """Test Oracle ASCII extraction payload generation"""
        payload = NumericExploitation.generate_ascii_extraction_payload(
            DBMSType.ORACLE,
            'users',
            'username',
            1,
            'id=1'
        )
        
        self.assertIn('ASCII', payload)
        self.assertIn('SUBSTR', payload)  # Oracle uses SUBSTR
        self.assertIn('ROWNUM=1', payload)  # Oracle specific
    
    def test_generate_ascii_extraction_payload_sqlite(self):
        """Test SQLite ASCII extraction payload generation"""
        payload = NumericExploitation.generate_ascii_extraction_payload(
            DBMSType.SQLITE,
            'users',
            'username',
            1,
            'id=1'
        )
        
        self.assertIn('UNICODE', payload)  # SQLite uses UNICODE
        self.assertIn('SUBSTR', payload)
    
    def test_generate_length_extraction_payload_mysql(self):
        """Test MySQL length extraction payload generation"""
        payload = NumericExploitation.generate_length_extraction_payload(
            DBMSType.MYSQL,
            'users',
            'password',
            'id=1'
        )
        
        self.assertIn('LENGTH', payload)
        self.assertIn('users', payload)
        self.assertIn('password', payload)
        self.assertIn('{LENGTH_VALUE}', payload)
    
    def test_generate_length_extraction_payload_mssql(self):
        """Test MS-SQL length extraction payload generation"""
        payload = NumericExploitation.generate_length_extraction_payload(
            DBMSType.MSSQL,
            'users',
            'password',
            'id=1'
        )
        
        self.assertIn('LEN', payload)  # MS-SQL uses LEN
        self.assertIn('TOP 1', payload)
    
    def test_generate_comparison_payloads(self):
        """Test comparison payload generation"""
        payloads = NumericExploitation.generate_comparison_payloads(
            DBMSType.MYSQL,
            'users',
            'username',
            1,
            'id=1'
        )
        
        self.assertIn('greater_than', payloads)
        self.assertIn('less_than', payloads)
        self.assertIn('equals', payloads)
        self.assertIn('greater_equal', payloads)
        self.assertIn('less_equal', payloads)
        
        # Check that templates contain placeholders
        self.assertIn('{VALUE}', payloads['greater_than'])
        self.assertIn('{VALUE}', payloads['less_than'])
    
    def test_binary_search_ascii_success(self):
        """Test binary search ASCII with successful finding"""
        # Simulate finding character 'A' (ASCII 65)
        target_ascii = 65
        
        def test_func(val):
            return target_ascii > val
        
        result = NumericExploitation.binary_search_ascii(test_func, 32, 126)
        self.assertEqual(result, target_ascii)
    
    def test_binary_search_ascii_lowercase(self):
        """Test binary search for lowercase character"""
        # Simulate finding character 'z' (ASCII 122)
        target_ascii = 122
        
        def test_func(val):
            return target_ascii > val
        
        result = NumericExploitation.binary_search_ascii(test_func, 32, 126)
        self.assertEqual(result, target_ascii)
    
    def test_binary_search_ascii_space(self):
        """Test binary search for space character"""
        # Simulate finding space (ASCII 32)
        target_ascii = 32
        
        def test_func(val):
            return target_ascii > val
        
        result = NumericExploitation.binary_search_ascii(test_func, 32, 126)
        self.assertEqual(result, target_ascii)
    
    def test_binary_search_ascii_tilde(self):
        """Test binary search for tilde character"""
        # Simulate finding '~' (ASCII 126)
        target_ascii = 126
        
        def test_func(val):
            return target_ascii > val
        
        result = NumericExploitation.binary_search_ascii(test_func, 32, 126)
        self.assertEqual(result, target_ascii)
    
    def test_binary_search_ascii_exception(self):
        """Test binary search with exception handling"""
        def test_func(val):
            if val > 100:
                raise Exception("Test exception")
            return False
        
        result = NumericExploitation.binary_search_ascii(test_func, 32, 126)
        self.assertIsNone(result)
    
    def test_get_numeric_exploitation_examples(self):
        """Test numeric exploitation examples generation"""
        examples = NumericExploitation.get_numeric_exploitation_examples()
        
        self.assertGreater(len(examples), 0)
        
        for example in examples:
            self.assertIn('scenario', example)
            self.assertIn('vulnerable_code', example)
            self.assertIn('target_data', example)
            self.assertIn('step_1', example)
            self.assertIn('result', example)
    
    def test_numeric_exploitation_examples_steps(self):
        """Test that examples have proper step structure"""
        examples = NumericExploitation.get_numeric_exploitation_examples()
        
        for example in examples:
            # Each step should have description and payload
            self.assertIn('description', example['step_1'])
            self.assertIn('payload', example['step_1'])
            self.assertIn('explanation', example['step_1'])
    
    def test_generate_test_payload_list_mysql(self):
        """Test MySQL test payload list generation"""
        payloads = NumericExploitation.generate_test_payload_list(DBMSType.MYSQL)
        
        self.assertGreater(len(payloads), 0)
        
        # Check for basic injection tests
        self.assertIn('1 AND 1=1', payloads)
        self.assertIn('1 AND 1=2', payloads)
        
        # Check for ASCII extraction tests
        self.assertTrue(any('ASCII' in p and 'SUBSTRING' in p for p in payloads))
    
    def test_generate_test_payload_list_postgresql(self):
        """Test PostgreSQL test payload list generation"""
        payloads = NumericExploitation.generate_test_payload_list(DBMSType.POSTGRESQL)
        
        self.assertGreater(len(payloads), 0)
        # Check for PostgreSQL-specific payloads
        self.assertTrue(any('pg_tables' in p for p in payloads))
    
    def test_generate_test_payload_list_mssql(self):
        """Test MS-SQL test payload list generation"""
        payloads = NumericExploitation.generate_test_payload_list(DBMSType.MSSQL)
        
        self.assertGreater(len(payloads), 0)
        # Check for MS-SQL-specific payloads
        self.assertTrue(any('sys.tables' in p for p in payloads))


class ExploitationWorkflowTest(TestCase):
    """Test ExploitationWorkflow class functionality"""
    
    def test_get_second_order_workflow(self):
        """Test second-order workflow generation"""
        workflow = ExploitationWorkflow.get_second_order_workflow()
        
        self.assertIn('title', workflow)
        self.assertIn('overview', workflow)
        self.assertIn('steps', workflow)
        self.assertIn('best_practices', workflow)
        
        self.assertGreater(len(workflow['steps']), 0)
    
    def test_second_order_workflow_phases(self):
        """Test that workflow has required phases"""
        workflow = ExploitationWorkflow.get_second_order_workflow()
        
        phases = [step['phase'] for step in workflow['steps']]
        
        # Check for key phases
        self.assertTrue(any('Reconnaissance' in p for p in phases))
        self.assertTrue(any('Exploitation' in p for p in phases))
    
    def test_second_order_workflow_step_structure(self):
        """Test workflow step structure"""
        workflow = ExploitationWorkflow.get_second_order_workflow()
        
        for step in workflow['steps']:
            self.assertIn('phase', step)
            self.assertIn('actions', step)
            self.assertIsInstance(step['actions'], list)
    
    def test_get_numeric_extraction_workflow(self):
        """Test numeric extraction workflow generation"""
        workflow = ExploitationWorkflow.get_numeric_extraction_workflow()
        
        self.assertIn('title', workflow)
        self.assertIn('overview', workflow)
        self.assertIn('requirements', workflow)
        self.assertIn('steps', workflow)
        self.assertIn('efficiency_tips', workflow)
        self.assertIn('automation', workflow)
    
    def test_numeric_extraction_workflow_phases(self):
        """Test numeric extraction workflow phases"""
        workflow = ExploitationWorkflow.get_numeric_extraction_workflow()
        
        phases = [step['phase'] for step in workflow['steps']]
        
        # Check for key phases
        self.assertTrue(any('Identify' in p for p in phases))
        self.assertTrue(any('Extract Data Length' in p for p in phases))
        self.assertTrue(any('Character-by-Character' in p for p in phases))
    
    def test_numeric_extraction_workflow_automation(self):
        """Test that workflow includes automation guide"""
        workflow = ExploitationWorkflow.get_numeric_extraction_workflow()
        
        self.assertIn('automation', workflow)
        self.assertIn('code', workflow['automation'])
        # Check that pseudocode contains key functions
        self.assertIn('extract_string', workflow['automation']['code'])
        self.assertIn('binary_search', workflow['automation']['code'])
    
    def test_numeric_extraction_efficiency_tips(self):
        """Test that workflow includes efficiency tips"""
        workflow = ExploitationWorkflow.get_numeric_extraction_workflow()
        
        self.assertGreater(len(workflow['efficiency_tips']), 0)
        # Check for binary search recommendation
        self.assertTrue(any('binary search' in tip.lower() 
                          for tip in workflow['efficiency_tips']))


class IntegrationTest(TestCase):
    """Test integration and utility functions"""
    
    def test_dbms_type_enum(self):
        """Test DBMSType enum values"""
        self.assertEqual(DBMSType.MYSQL.value, "mysql")
        self.assertEqual(DBMSType.POSTGRESQL.value, "postgresql")
        self.assertEqual(DBMSType.MSSQL.value, "mssql")
        self.assertEqual(DBMSType.ORACLE.value, "oracle")
        self.assertEqual(DBMSType.SQLITE.value, "sqlite")
    
    def test_all_dbms_types_supported_in_numeric(self):
        """Test that numeric exploitation supports all DBMS types"""
        for dbms in [DBMSType.MYSQL, DBMSType.POSTGRESQL, 
                     DBMSType.MSSQL, DBMSType.ORACLE, DBMSType.SQLITE]:
            payload = NumericExploitation.generate_ascii_extraction_payload(
                dbms, 'test', 'col', 1, '1=1'
            )
            self.assertIsNotNone(payload)
            self.assertGreater(len(payload), 0)
    
    def test_all_dbms_types_supported_in_destructive(self):
        """Test that destructive queries support major DBMS types"""
        for dbms in [DBMSType.MYSQL, DBMSType.MSSQL, 
                     DBMSType.POSTGRESQL, DBMSType.ORACLE]:
            payloads = DestructiveQueries.get_destructive_payloads(dbms)
            self.assertGreater(len(payloads), 0)
    
    def test_second_order_payload_consistency(self):
        """Test that second-order payloads are consistent across DBMS"""
        mysql_payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MYSQL)
        mssql_payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MSSQL)
        
        # Common categories should exist in both
        for category in ['username_payloads', 'email_payloads']:
            self.assertIn(category, mysql_payloads)
            self.assertIn(category, mssql_payloads)


class PayloadQualityTest(TestCase):
    """Test payload quality and safety"""
    
    def test_no_actual_malicious_ips(self):
        """Ensure no real external IPs in payloads"""
        # Check destructive queries
        for dbms in [DBMSType.MYSQL, DBMSType.MSSQL, DBMSType.POSTGRESQL]:
            payloads = DestructiveQueries.get_destructive_payloads(dbms)
            
            for category in payloads.values():
                for item in category:
                    payload = item['payload']
                    # Check for placeholder domains
                    if 'attacker.com' in payload:
                        # This is acceptable - it's a placeholder
                        pass
                    # Ensure no real IPs like 192.168.x.x or public IPs
                    self.assertNotRegex(payload, r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
    def test_payloads_contain_sql_syntax(self):
        """Test that payloads contain valid SQL syntax elements"""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 
                       'CREATE', 'ALTER', 'UNION', 'WHERE', 'FROM']
        
        # Test second-order payloads
        payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MYSQL)
        all_payloads = []
        for category in payloads.values():
            all_payloads.extend(category)
        
        # At least some payloads should contain SQL keywords
        has_sql = any(any(keyword in p.upper() for keyword in sql_keywords) 
                     for p in all_payloads)
        self.assertTrue(has_sql)
    
    def test_comment_syntax_in_payloads(self):
        """Test that payloads use proper SQL comment syntax"""
        comment_patterns = ['--', '#', '/*', '*/']
        
        payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MYSQL)
        all_payloads = []
        for category in payloads.values():
            all_payloads.extend(category)
        
        # Many payloads should use comments for injection
        has_comments = any(any(pattern in p for pattern in comment_patterns) 
                          for p in all_payloads)
        self.assertTrue(has_comments)


if __name__ == '__main__':
    import unittest
    unittest.main()
