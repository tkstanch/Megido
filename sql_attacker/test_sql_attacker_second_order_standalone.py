#!/usr/bin/env python3
"""
Standalone test runner for SQL Attacker Second-Order Examples Module

This test script can run independently without Django installation,
making it easy to validate the module functionality.
"""

import sys
import unittest
from sql_attacker_second_order_examples import (
    SecondOrderInjection,
    DestructiveQueries,
    NumericExploitation,
    ExploitationWorkflow,
    DBMSType,
)


class TestSecondOrderInjection(unittest.TestCase):
    """Test SecondOrderInjection class functionality"""
    
    def test_scenarios_exist(self):
        """Test that second-order scenarios are defined"""
        self.assertGreater(len(SecondOrderInjection.SCENARIOS), 0)
        self.assertIn('user_registration', SecondOrderInjection.SCENARIOS)
    
    def test_get_second_order_payloads_mysql(self):
        """Test MySQL second-order payload generation"""
        payloads = SecondOrderInjection.get_second_order_payloads(DBMSType.MYSQL)
        self.assertIn('username_payloads', payloads)
        self.assertTrue(any("admin'--" in p for p in payloads['username_payloads']))
    
    def test_generate_test_vectors(self):
        """Test test vector generation"""
        vectors = SecondOrderInjection.generate_second_order_test_vectors()
        self.assertGreater(len(vectors), 0)
        self.assertIn('name', vectors[0])
        self.assertIn('severity', vectors[0])


class TestDestructiveQueries(unittest.TestCase):
    """Test DestructiveQueries class functionality"""
    
    def test_get_destructive_payloads_mysql(self):
        """Test MySQL destructive payload generation"""
        payloads = DestructiveQueries.get_destructive_payloads(DBMSType.MYSQL)
        self.assertIn('shutdown', payloads)
        self.assertGreater(len(payloads['shutdown']), 0)
    
    def test_get_destructive_payloads_mssql(self):
        """Test MS-SQL destructive payload generation"""
        payloads = DestructiveQueries.get_destructive_payloads(DBMSType.MSSQL)
        self.assertIn('command_execution', payloads)
    
    def test_get_privilege_escalation_payloads(self):
        """Test privilege escalation payload generation"""
        payloads = DestructiveQueries.get_privilege_escalation_payloads(DBMSType.MYSQL)
        self.assertGreater(len(payloads), 0)


class TestNumericExploitation(unittest.TestCase):
    """Test NumericExploitation class functionality"""
    
    def test_generate_ascii_extraction_payload_mysql(self):
        """Test MySQL ASCII extraction payload generation"""
        payload = NumericExploitation.generate_ascii_extraction_payload(
            DBMSType.MYSQL, 'users', 'username', 1, 'id=1'
        )
        self.assertIn('ASCII', payload)
        self.assertIn('SUBSTRING', payload)
    
    def test_generate_length_extraction_payload(self):
        """Test length extraction payload generation"""
        payload = NumericExploitation.generate_length_extraction_payload(
            DBMSType.MYSQL, 'users', 'password', 'id=1'
        )
        self.assertIn('LENGTH', payload)
    
    def test_binary_search_ascii(self):
        """Test binary search ASCII algorithm"""
        target = 65  # 'A'
        result = NumericExploitation.binary_search_ascii(
            lambda x: target > x, 32, 126
        )
        self.assertEqual(result, target)
    
    def test_generate_comparison_payloads(self):
        """Test comparison payload generation"""
        payloads = NumericExploitation.generate_comparison_payloads(
            DBMSType.MYSQL, 'users', 'username', 1
        )
        self.assertIn('greater_than', payloads)
        self.assertIn('less_than', payloads)
    
    def test_get_numeric_exploitation_examples(self):
        """Test numeric exploitation examples"""
        examples = NumericExploitation.get_numeric_exploitation_examples()
        self.assertGreater(len(examples), 0)
    
    def test_generate_test_payload_list(self):
        """Test test payload list generation"""
        payloads = NumericExploitation.generate_test_payload_list(DBMSType.MYSQL)
        self.assertGreater(len(payloads), 0)
        self.assertIn('1 AND 1=1', payloads)


class TestExploitationWorkflow(unittest.TestCase):
    """Test ExploitationWorkflow class functionality"""
    
    def test_get_second_order_workflow(self):
        """Test second-order workflow generation"""
        workflow = ExploitationWorkflow.get_second_order_workflow()
        self.assertIn('title', workflow)
        self.assertIn('steps', workflow)
        self.assertGreater(len(workflow['steps']), 0)
    
    def test_get_numeric_extraction_workflow(self):
        """Test numeric extraction workflow generation"""
        workflow = ExploitationWorkflow.get_numeric_extraction_workflow()
        self.assertIn('title', workflow)
        self.assertIn('automation', workflow)


class TestAllDBMSSupport(unittest.TestCase):
    """Test that all DBMS types are properly supported"""
    
    def test_numeric_exploitation_all_dbms(self):
        """Test numeric exploitation for all DBMS types"""
        for dbms in [DBMSType.MYSQL, DBMSType.POSTGRESQL, 
                     DBMSType.MSSQL, DBMSType.ORACLE, DBMSType.SQLITE]:
            payload = NumericExploitation.generate_ascii_extraction_payload(
                dbms, 'test', 'col', 1, '1=1'
            )
            self.assertIsNotNone(payload)
            self.assertGreater(len(payload), 0)
    
    def test_destructive_queries_major_dbms(self):
        """Test destructive queries for major DBMS types"""
        for dbms in [DBMSType.MYSQL, DBMSType.MSSQL, 
                     DBMSType.POSTGRESQL, DBMSType.ORACLE]:
            payloads = DestructiveQueries.get_destructive_payloads(dbms)
            self.assertGreater(len(payloads), 0)


class TestBinarySearchEdgeCases(unittest.TestCase):
    """Test binary search algorithm edge cases"""
    
    def test_binary_search_min_value(self):
        """Test binary search with minimum ASCII value"""
        target = 32  # Space
        result = NumericExploitation.binary_search_ascii(
            lambda x: target > x, 32, 126
        )
        self.assertEqual(result, target)
    
    def test_binary_search_max_value(self):
        """Test binary search with maximum ASCII value"""
        target = 126  # Tilde
        result = NumericExploitation.binary_search_ascii(
            lambda x: target > x, 32, 126
        )
        self.assertEqual(result, target)
    
    def test_binary_search_middle_value(self):
        """Test binary search with middle value"""
        target = 79  # 'O'
        result = NumericExploitation.binary_search_ascii(
            lambda x: target > x, 32, 126
        )
        self.assertEqual(result, target)
    
    def test_binary_search_with_exception(self):
        """Test binary search exception handling"""
        def failing_func(val):
            # Always fail - simulates network error or timeout
            raise ValueError("Test exception")
        
        result = NumericExploitation.binary_search_ascii(failing_func, 32, 126)
        self.assertIsNone(result)


def run_tests():
    """Run all tests and display results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSecondOrderInjection))
    suite.addTests(loader.loadTestsFromTestCase(TestDestructiveQueries))
    suite.addTests(loader.loadTestsFromTestCase(TestNumericExploitation))
    suite.addTests(loader.loadTestsFromTestCase(TestExploitationWorkflow))
    suite.addTests(loader.loadTestsFromTestCase(TestAllDBMSSupport))
    suite.addTests(loader.loadTestsFromTestCase(TestBinarySearchEdgeCases))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code based on results
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    print("=" * 80)
    print("SQL Attacker Second-Order Examples - Standalone Test Suite")
    print("=" * 80)
    print()
    
    exit_code = run_tests()
    
    print()
    print("=" * 80)
    if exit_code == 0:
        print("All tests passed!")
    else:
        print("Some tests failed. Please review the output above.")
    print("=" * 80)
    
    sys.exit(exit_code)
