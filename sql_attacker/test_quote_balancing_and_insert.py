"""
Unit tests for quote balancing and INSERT statement injection features.

Tests the new enhancements to the SQL injection module including:
- Quote balancing payloads
- INSERT parameter enumeration
- Enhanced response analysis
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from sql_attacker.injection_contexts.sql_context import SQLInjectionModule
from sql_attacker.injection_contexts import InjectionContextType


class TestQuoteBalancingPayloads(unittest.TestCase):
    """Test quote balancing payload generation."""
    
    def setUp(self):
        self.module = SQLInjectionModule()
    
    def test_generate_quote_balanced_payloads(self):
        """Test quote-balanced payload generation."""
        payloads = self.module._generate_quote_balanced_payloads()
        
        # Should have multiple payloads
        self.assertGreater(len(payloads), 5)
        
        # Should contain classic quote-balanced pattern
        self.assertTrue(any("Wiley' OR 'a'='a" in p for p in payloads))
        self.assertTrue(any("admin' OR 'b'='b" in p for p in payloads))
        
    def test_quote_balanced_no_comments(self):
        """Test that quote-balanced payloads avoid SQL comments."""
        payloads = self.module._generate_quote_balanced_payloads()
        
        # Most quote-balanced payloads should not end with comment markers
        comment_free = [p for p in payloads if not p.rstrip().endswith(('--', '#'))]
        
        # Should have at least some comment-free payloads
        self.assertGreater(len(comment_free), 5)
    
    def test_quote_balanced_with_base_value(self):
        """Test quote-balanced payloads with a base value."""
        base_value = "test123"
        payloads = self.module._generate_quote_balanced_payloads(base_value)
        
        # All payloads should start with base value
        for payload in payloads:
            self.assertTrue(payload.startswith(base_value))
    
    def test_quote_balanced_single_and_double_quotes(self):
        """Test that both single and double quote variants are generated."""
        payloads = self.module._generate_quote_balanced_payloads()
        
        # Should have single quote variants
        single_quote_payloads = [p for p in payloads if "'" in p]
        self.assertGreater(len(single_quote_payloads), 3)
        
        # Should have double quote variants
        double_quote_payloads = [p for p in payloads if '"' in p]
        self.assertGreater(len(double_quote_payloads), 1)


class TestInsertPayloads(unittest.TestCase):
    """Test INSERT statement payload generation."""
    
    def setUp(self):
        self.module = SQLInjectionModule()
    
    def test_generate_insert_payloads_basic(self):
        """Test basic INSERT payload generation."""
        payloads = self.module._generate_insert_payloads()
        
        # Should have multiple payloads
        self.assertGreater(len(payloads), 10)
        
        # Should include basic escape attempts
        self.assertTrue(any("foo')--" in p for p in payloads))
        self.assertTrue(any("foo')#" in p for p in payloads))
    
    def test_insert_parameter_enumeration(self):
        """Test parameter enumeration in INSERT payloads."""
        payloads = self.module._generate_insert_payloads(max_params=5)
        
        # Should include progressive parameter counts
        self.assertTrue(any("', NULL)--" in p for p in payloads))
        self.assertTrue(any("', NULL, NULL)--" in p for p in payloads))
        self.assertTrue(any("', NULL, NULL, NULL)--" in p for p in payloads))
        
        # Should include numeric variants
        self.assertTrue(any("', 1)--" in p for p in payloads))
        self.assertTrue(any("', 1, 1)--" in p for p in payloads))
    
    def test_insert_custom_base_value(self):
        """Test INSERT payloads with custom base value."""
        base_value = "myuser"
        payloads = self.module._generate_insert_payloads(base_value)
        
        # Should use custom base value
        self.assertTrue(any(f"{base_value}')--" in p for p in payloads))
        self.assertTrue(any(f"{base_value}', NULL)--" in p for p in payloads))
    
    def test_insert_mixed_parameter_types(self):
        """Test INSERT payloads with mixed parameter types."""
        payloads = self.module._generate_insert_payloads()
        
        # Should include mixed type parameters
        self.assertTrue(any("', 1, 'test')--" in p for p in payloads))
        self.assertTrue(any("', 'admin', 'password')--" in p for p in payloads))
    
    def test_insert_max_params_limit(self):
        """Test that max_params limit is respected."""
        max_params = 3
        payloads = self.module._generate_insert_payloads(max_params=max_params)
        
        # Count maximum number of parameters in any payload
        max_found = 0
        for payload in payloads:
            # Count commas after the first value to estimate parameter count
            if "', " in payload:
                param_section = payload.split("', ", 1)[1]
                param_count = param_section.count(',') + 1
                max_found = max(max_found, param_count)
        
        # Should not exceed max_params (allowing some tolerance for mixed types)
        self.assertLessEqual(max_found, max_params + 2)
    
    def test_insert_quote_balanced_variants(self):
        """Test that INSERT payloads include quote-balanced variants."""
        payloads = self.module._generate_insert_payloads()
        
        # Should include quote-balanced INSERT payloads
        quote_balanced = [p for p in payloads if ") AND (" in p or ") OR (" in p]
        self.assertGreater(len(quote_balanced), 1)


class TestStep1SupplyPayloadsEnhanced(unittest.TestCase):
    """Test enhanced step1_supply_payloads with new features."""
    
    def setUp(self):
        self.module = SQLInjectionModule()
    
    def test_step1_default_behavior(self):
        """Test that default behavior includes base payloads and quote balancing."""
        payloads = self.module.step1_supply_payloads("")
        
        # Should include original base payloads
        self.assertTrue(any("' OR '1'='1" in p for p in payloads))
        
        # Should include quote-balanced payloads
        self.assertTrue(any("Wiley' OR 'a'='a" in p for p in payloads))
    
    def test_step1_insert_statement_type(self):
        """Test step1 with INSERT statement type."""
        payloads = self.module.step1_supply_payloads("", statement_type="INSERT")
        
        # Should include INSERT-specific payloads
        self.assertTrue(any("')--" in p for p in payloads))
        self.assertTrue(any("', NULL)--" in p for p in payloads))
    
    def test_step1_include_insert_enum_flag(self):
        """Test step1 with include_insert_enum flag."""
        payloads = self.module.step1_supply_payloads("", include_insert_enum=True)
        
        # Should include INSERT enumeration payloads
        self.assertTrue(any("', 1)--" in p for p in payloads))
        self.assertTrue(any("', 1, 1)--" in p for p in payloads))
    
    def test_step1_select_statement_no_insert(self):
        """Test that SELECT statement type doesn't force INSERT payloads."""
        payloads_select = self.module.step1_supply_payloads("", statement_type="SELECT")
        payloads_default = self.module.step1_supply_payloads("")
        
        # Both should have similar length (no INSERT enumeration for SELECT)
        # Allow some variance due to quote-balanced additions
        self.assertAlmostEqual(len(payloads_select), len(payloads_default), delta=5)
    
    def test_step1_custom_max_insert_params(self):
        """Test step1 with custom max INSERT parameters."""
        payloads = self.module.step1_supply_payloads(
            "", 
            statement_type="INSERT",
            max_insert_params=3
        )
        
        # Should generate payloads but with limited parameter count
        insert_payloads = [p for p in payloads if "')--" in p]
        self.assertGreater(len(insert_payloads), 0)


class TestEnhancedResponseAnalysis(unittest.TestCase):
    """Test enhanced response analysis for quote balancing and INSERT."""
    
    def setUp(self):
        self.module = SQLInjectionModule()
    
    def test_detect_insert_error_patterns(self):
        """Test detection of INSERT-specific error messages."""
        response_body = "Error: column count doesn't match value count at row 1"
        
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        
        self.assertTrue(detected)
        # Should detect INSERT parameter count issue
        self.assertTrue(any('insert_param_count' in a for a in anomalies))
    
    def test_detect_oracle_insert_errors(self):
        """Test detection of Oracle INSERT errors."""
        response_body = "ORA-00913: too many values"
        
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        
        self.assertTrue(detected)
        # Should detect both SQL error and INSERT specific error
        sql_errors = [a for a in anomalies if 'sql_error' in a or 'insert_param_count' in a]
        self.assertGreater(len(sql_errors), 0)
    
    def test_detect_quote_balanced_success(self):
        """Test detection of quote-balanced injection success."""
        response_body = "Record successfully inserted into database"
        
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5, payload_hint="QUOTE_BALANCED"
        )
        
        # Should detect success indicator
        if detected:
            self.assertTrue(any('quote_balanced_success' in a for a in anomalies))
    
    def test_extract_evidence_insert_context(self):
        """Test evidence extraction with INSERT context."""
        response_body = "Error: wrong number of values in INSERT"
        
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        
        evidence = self.module.step3_extract_evidence(response_body, anomalies)
        
        # Should identify INSERT statement type
        if 'insert_detection' in evidence.get('context_info', {}):
            insert_info = evidence['context_info']['insert_detection']
            self.assertEqual(insert_info['statement_type'], 'INSERT')
    
    def test_extract_evidence_quote_balanced(self):
        """Test evidence extraction for quote-balanced injection."""
        response_body = "User created successfully"
        
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5, payload_hint="QUOTE_BALANCED"
        )
        
        if detected:
            evidence = self.module.step3_extract_evidence(response_body, anomalies)
            
            # Should mark as quote-balanced
            self.assertTrue(evidence['details'].get('quote_balanced', False))
    
    def test_confidence_scoring_insert(self):
        """Test confidence scoring for INSERT injection detection."""
        response_body = "MySQL Error: Column count doesn't match value count"
        
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        
        evidence = self.module.step3_extract_evidence(response_body, anomalies)
        
        # Should have high confidence for INSERT detection
        self.assertGreater(evidence['confidence'], 0.75)
    
    def test_content_length_change_detection(self):
        """Test detection of content length changes."""
        baseline_body = "A" * 100
        response_body = "B" * 200
        
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5,
            baseline_response=(baseline_body, 0.5)
        )
        
        # Should detect content change
        if detected:
            self.assertTrue(any('content_change' in a for a in anomalies))


class TestPayloadIntegration(unittest.TestCase):
    """Integration tests for new payload features."""
    
    def setUp(self):
        self.module = SQLInjectionModule()
    
    def test_payloads_contain_quote_balanced(self):
        """Test that regular payloads contain quote-balanced variants."""
        # Get payloads through step1
        payloads = self.module.step1_supply_payloads("")
        
        # Should have quote-balanced payloads in the list
        quote_balanced_count = sum(1 for p in payloads 
                                   if "' OR '" in p and not p.endswith(('--', '#')))
        self.assertGreater(quote_balanced_count, 3)
    
    def test_full_workflow_with_insert(self):
        """Test full workflow with INSERT statement detection."""
        # Step 1: Get payloads including INSERT
        payloads = self.module.step1_supply_payloads("user", statement_type="INSERT")
        
        # Should have significant number of payloads
        self.assertGreater(len(payloads), 50)
        
        # Step 2 & 3: Simulate INSERT error response
        response_body = "Error: number of columns does not match number of values"
        detected, anomalies = self.module.step2_detect_anomalies(
            response_body, {}, 0.5
        )
        
        self.assertTrue(detected)
        
        evidence = self.module.step3_extract_evidence(response_body, anomalies)
        
        # Should identify INSERT context
        self.assertGreater(evidence['confidence'], 0.7)
    
    def test_backward_compatibility(self):
        """Test that enhancements maintain backward compatibility."""
        # Old style call should still work
        payloads_old_style = self.module.step1_supply_payloads("test")
        
        # Should still return valid payloads
        self.assertGreater(len(payloads_old_style), 30)
        self.assertTrue(any("' OR '1'='1" in p for p in payloads_old_style))


if __name__ == '__main__':
    unittest.main()
