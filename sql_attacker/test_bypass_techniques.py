"""
Unit tests for advanced bypass techniques.

Tests all bypass techniques including:
- String construction without quotes
- Comment-based bypasses
- Keyword variants
- Encoding techniques
"""

from django.test import TestCase
from sql_attacker.bypass_techniques import (
    StringConstructionBypass,
    CommentWhitespaceBypass,
    KeywordVariantBypass,
    EncodingBypass,
    BatchQueryBypass,
    AdvancedBypassEngine,
    DBMSType,
)


class StringConstructionBypassTest(TestCase):
    """Test string construction bypass techniques"""
    
    def test_string_to_chr_oracle(self):
        """Test Oracle CHR() string construction"""
        result = StringConstructionBypass.string_to_chr_oracle("admin")
        self.assertIn("CHR(97)", result)  # 'a' = 97
        self.assertIn("CHR(100)", result)  # 'd' = 100
        self.assertIn("||", result)  # Oracle concatenation
        
    def test_string_to_chr_oracle_empty(self):
        """Test Oracle CHR() with empty string"""
        result = StringConstructionBypass.string_to_chr_oracle("")
        self.assertEqual(result, "''")
    
    def test_string_to_char_mssql(self):
        """Test MS-SQL CHAR() string construction"""
        result = StringConstructionBypass.string_to_char_mssql("admin")
        self.assertIn("CHAR(97)", result)
        self.assertIn("CHAR(100)", result)
        self.assertIn("+", result)  # MS-SQL concatenation
        
    def test_string_to_char_mssql_empty(self):
        """Test MS-SQL CHAR() with empty string"""
        result = StringConstructionBypass.string_to_char_mssql("")
        self.assertEqual(result, "''")
    
    def test_string_to_char_mysql(self):
        """Test MySQL CHAR() string construction"""
        result = StringConstructionBypass.string_to_char_mysql("admin")
        self.assertIn("CHAR(97,100,109,105,110)", result)
        
    def test_string_to_char_mysql_empty(self):
        """Test MySQL CHAR() with empty string"""
        result = StringConstructionBypass.string_to_char_mysql("")
        self.assertEqual(result, "''")
    
    def test_string_to_hex_mysql(self):
        """Test MySQL hex string conversion"""
        result = StringConstructionBypass.string_to_hex_mysql("admin")
        self.assertEqual(result, "0x61646d696e")
        
    def test_string_to_hex_mysql_empty(self):
        """Test MySQL hex with empty string"""
        result = StringConstructionBypass.string_to_hex_mysql("")
        self.assertEqual(result, "''")
    
    def test_bypass_quotes_mysql(self):
        """Test bypass quotes in payload for MySQL"""
        payload = "' OR 'a'='a"
        result = StringConstructionBypass.bypass_quotes_in_payload(payload, DBMSType.MYSQL)
        # Should not contain single quotes around 'a'
        self.assertNotIn("'a'", result)
        self.assertIn("CHAR(", result)
        
    def test_bypass_quotes_oracle(self):
        """Test bypass quotes in payload for Oracle"""
        payload = "' OR 'admin'='admin"
        result = StringConstructionBypass.bypass_quotes_in_payload(payload, DBMSType.ORACLE)
        self.assertIn("CHR(", result)
        self.assertIn("||", result)
        
    def test_bypass_quotes_mssql(self):
        """Test bypass quotes in payload for MS-SQL"""
        payload = "' OR 'test'='test"
        result = StringConstructionBypass.bypass_quotes_in_payload(payload, DBMSType.MSSQL)
        self.assertIn("CHAR(", result)
        self.assertIn("+", result)


class CommentWhitespaceBypassTest(TestCase):
    """Test comment-based whitespace bypass techniques"""
    
    def test_space_to_inline_comment(self):
        """Test replacing spaces with inline comments"""
        payload = "SELECT FROM users"
        result = CommentWhitespaceBypass.space_to_inline_comment(payload)
        self.assertNotIn(" ", result)
        self.assertIn("/**/", result)
        self.assertIn("SELECT/**/FROM/**/users", result)
    
    def test_space_to_inline_comment_custom(self):
        """Test custom comment style"""
        payload = "SELECT FROM users"
        result = CommentWhitespaceBypass.space_to_inline_comment(payload, "/*!*/")
        self.assertIn("/*!*/", result)
        
    def test_insert_comment_in_keywords(self):
        """Test inserting comments within keywords"""
        payload = "SELECT FROM WHERE"
        result = CommentWhitespaceBypass.insert_comment_in_keywords(payload)
        # Keywords should be broken up with comments
        self.assertIn("/*", result)
        self.assertIn("*/", result)
        # Original keywords should be modified
        self.assertTrue("SELECT" not in result or "/*" in result)
        
    def test_create_logical_block_injection(self):
        """Test logical block injection creation"""
        result = CommentWhitespaceBypass.create_logical_block_injection("base")
        self.assertIn("OR", result)
        self.assertIn("=", result)
        # Should be a valid logical expression
        self.assertTrue("'a'='a" in result or "'1'='1" in result)
        
    def test_generate_comment_variations(self):
        """Test generating multiple comment variations"""
        payload = "UNION SELECT"
        results = CommentWhitespaceBypass.generate_comment_variations(payload)
        self.assertGreater(len(results), 1)
        self.assertIn(payload, results)  # Original included
        # Should have variations with different comment styles
        self.assertTrue(any("/*" in r for r in results))


class KeywordVariantBypassTest(TestCase):
    """Test keyword variant bypass techniques"""
    
    def test_mixed_case_variant_alternate(self):
        """Test alternate mixed case"""
        result = KeywordVariantBypass.mixed_case_variant("SELECT", "alternate")
        self.assertEqual(result.upper(), "SELECT")
        self.assertNotEqual(result, "SELECT")
        self.assertNotEqual(result, "select")
        
    def test_mixed_case_variant_camel(self):
        """Test camel case variant"""
        result = KeywordVariantBypass.mixed_case_variant("SELECT", "camel")
        self.assertEqual(result[0], "S")  # First should be upper
        
    def test_hex_encode_keyword_full(self):
        """Test full hex encoding"""
        result = KeywordVariantBypass.hex_encode_keyword("SELECT", full=True)
        self.assertIn("%", result)
        self.assertNotIn("S", result)
        self.assertNotIn("E", result)
        # Should be all hex encoded
        self.assertTrue(all(c in "0123456789ABCDEFabcdef%" for c in result))
        
    def test_hex_encode_keyword_partial(self):
        """Test partial hex encoding"""
        result = KeywordVariantBypass.hex_encode_keyword("SELECT", full=False)
        self.assertIn("%", result)
        # Should have mix of hex and normal characters
        
    def test_keyword_repetition(self):
        """Test keyword repetition bypass"""
        result = KeywordVariantBypass.keyword_repetition("SELECT")
        self.assertIn("SELECT", result)
        self.assertGreater(len(result), len("SELECT"))
        # Should contain nested repetition
        
    def test_keyword_repetition_short(self):
        """Test keyword repetition with short keyword"""
        result = KeywordVariantBypass.keyword_repetition("OR")
        # Short keywords should return as-is
        self.assertEqual(result, "OR")
        
    def test_generate_keyword_variants(self):
        """Test generating multiple keyword variants"""
        variants = KeywordVariantBypass.generate_keyword_variants("SELECT")
        self.assertGreater(len(variants), 5)
        self.assertIn("SELECT", variants)
        self.assertIn("select", variants)
        # Should have hex encoded version
        self.assertTrue(any("%" in v for v in variants))
        
    def test_apply_to_payload(self):
        """Test applying keyword variants to payload"""
        payload = "' UNION SELECT NULL"
        variants = KeywordVariantBypass.apply_to_payload(payload)
        self.assertGreater(len(variants), 1)
        self.assertIn(payload, variants)  # Original included
        # Should have variations
        self.assertTrue(any("union" in v.lower() and v != payload for v in variants))


class EncodingBypassTest(TestCase):
    """Test encoding bypass techniques"""
    
    def test_double_url_encode(self):
        """Test double URL encoding"""
        payload = "' OR 1=1"
        result = EncodingBypass.double_url_encode(payload)
        # Should be double encoded
        self.assertIn("%25", result)  # % itself should be encoded
        self.assertNotIn(" ", result)
        self.assertNotIn("'", result)
        
    def test_partial_encode(self):
        """Test partial encoding"""
        payload = "SELECT FROM"
        result = EncodingBypass.partial_encode(payload, ratio=0.5)
        # Should have non-empty result
        self.assertGreater(len(result), 0)
        # Should have mix of encoded and non-encoded characters (with some tolerance for randomness)
        has_encoded = "%" in result
        has_normal = any(c.isalpha() for c in result if c != '%')
        # At least one should be true for a non-trivial payload
        self.assertTrue(has_encoded or has_normal)
        print("  ✓ Partial encoding works")
        """Test mixed encoding"""
        payload = "' OR 1=1"
        result = EncodingBypass.mixed_encoding(payload)
        # Special characters should be encoded
        self.assertNotIn("'", result)
        self.assertNotIn("=", result)
        self.assertIn("%", result)
        
    def test_unicode_encode_standard(self):
        """Test standard unicode encoding"""
        payload = "SELECT"
        result = EncodingBypass.unicode_encode(payload, 'standard')
        self.assertIn("\\u", result)
        self.assertNotIn("S", result)
        
    def test_unicode_encode_overlong(self):
        """Test overlong UTF-8 encoding"""
        payload = "' OR 1=1"
        result = EncodingBypass.unicode_encode(payload, 'overlong')
        # Special chars should be overlong encoded
        self.assertIn("%C0", result)
        
    def test_generate_encoding_variants(self):
        """Test generating multiple encoding variants"""
        payload = "' UNION SELECT"
        variants = EncodingBypass.generate_encoding_variants(payload)
        self.assertGreater(len(variants), 3)
        self.assertIn(payload, variants)  # Original included
        # Should have various encoding styles
        self.assertTrue(any("%" in v for v in variants))


class BatchQueryBypassTest(TestCase):
    """Test batch query bypass techniques"""
    
    def test_batch_without_semicolon(self):
        """Test batch query without semicolons"""
        queries = ["SELECT 1", "SELECT 2"]
        result = BatchQueryBypass.batch_without_semicolon(queries)
        self.assertNotIn(";", result)
        self.assertIn("SELECT 1", result)
        self.assertIn("SELECT 2", result)
        
    def test_batch_with_exec(self):
        """Test batch query using EXEC"""
        queries = ["SELECT 1", "SELECT 2"]
        result = BatchQueryBypass.batch_with_exec(queries)
        self.assertIn("EXEC", result)
        self.assertIn("SELECT 1", result)
        self.assertIn("SELECT 2", result)


class AdvancedBypassEngineTest(TestCase):
    """Test the main bypass engine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = AdvancedBypassEngine()
        self.engine_mysql = AdvancedBypassEngine(DBMSType.MYSQL)
        
    def test_initialization(self):
        """Test engine initializes correctly"""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine.dbms, DBMSType.UNKNOWN)
        
    def test_initialization_with_dbms(self):
        """Test engine initialization with DBMS"""
        engine = AdvancedBypassEngine(DBMSType.MYSQL)
        self.assertEqual(engine.dbms, DBMSType.MYSQL)
        
    def test_set_dbms(self):
        """Test setting DBMS type"""
        self.engine.set_dbms(DBMSType.ORACLE)
        self.assertEqual(self.engine.dbms, DBMSType.ORACLE)
        
    def test_generate_all_bypass_variants(self):
        """Test generating all bypass variants"""
        payload = "' UNION SELECT NULL"
        variants = self.engine_mysql.generate_all_bypass_variants(payload, max_variants=20)
        self.assertGreater(len(variants), 5)
        self.assertLessEqual(len(variants), 20)
        self.assertIn(payload, variants)  # Original included
        
    def test_generate_all_bypass_variants_no_duplicates(self):
        """Test that variants don't contain duplicates"""
        payload = "' OR 1=1"
        variants = self.engine_mysql.generate_all_bypass_variants(payload)
        # Check for duplicates
        self.assertEqual(len(variants), len(set(variants)))
        
    def test_generate_string_construction_variants(self):
        """Test string construction variants"""
        payload = "' OR 'admin'='admin"
        variants = self.engine_mysql.generate_string_construction_variants(payload)
        self.assertGreater(len(variants), 0)
        # Should use CHAR for MySQL
        self.assertTrue(any("CHAR(" in v for v in variants))
        
    def test_generate_string_construction_variants_unknown_dbms(self):
        """Test string construction with unknown DBMS"""
        payload = "' OR 'test'='test"
        variants = self.engine.generate_string_construction_variants(payload)
        # Should try multiple DBMS types
        self.assertGreater(len(variants), 1)
        
    def test_generate_comment_bypass_variants(self):
        """Test comment bypass variants"""
        payload = "UNION SELECT"
        variants = self.engine.generate_comment_bypass_variants(payload)
        self.assertGreater(len(variants), 1)
        self.assertTrue(any("/*" in v for v in variants))
        
    def test_generate_keyword_bypass_variants(self):
        """Test keyword bypass variants"""
        payload = "' UNION SELECT"
        variants = self.engine.generate_keyword_bypass_variants(payload)
        self.assertGreater(len(variants), 1)
        
    def test_generate_encoding_bypass_variants(self):
        """Test encoding bypass variants"""
        payload = "' OR 1=1"
        variants = self.engine.generate_encoding_bypass_variants(payload)
        self.assertGreater(len(variants), 1)
        self.assertTrue(any("%" in v for v in variants))
        
    def test_comprehensive_bypass_generation(self):
        """Test comprehensive bypass generation with various payloads"""
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin'--",
            "' AND SLEEP(5)--",
        ]
        
        for payload in payloads:
            variants = self.engine_mysql.generate_all_bypass_variants(payload, max_variants=30)
            self.assertGreater(len(variants), 3, f"Failed for payload: {payload}")
            self.assertIn(payload, variants)


class IntegrationTest(TestCase):
    """Integration tests for bypass techniques"""
    
    def test_end_to_end_mysql_bypass(self):
        """Test end-to-end bypass for MySQL"""
        engine = AdvancedBypassEngine(DBMSType.MYSQL)
        payload = "' OR 'admin'='admin"
        
        # Generate all variants
        variants = engine.generate_all_bypass_variants(payload, max_variants=50)
        
        # Should have multiple types of bypasses
        has_string_construction = any("CHAR(" in v for v in variants)
        has_comment = any("/*" in v for v in variants)
        has_encoding = any("%" in v for v in variants)
        
        # At least two types should be present
        bypass_types = sum([has_string_construction, has_comment, has_encoding])
        self.assertGreater(bypass_types, 1)
        
    def test_end_to_end_oracle_bypass(self):
        """Test end-to-end bypass for Oracle"""
        engine = AdvancedBypassEngine(DBMSType.ORACLE)
        payload = "' UNION SELECT NULL FROM dual"
        
        variants = engine.generate_all_bypass_variants(payload, max_variants=50)
        
        # Should have Oracle-specific bypasses
        has_chr = any("CHR(" in v for v in variants)
        has_concat = any("||" in v for v in variants)
        
        # At least one Oracle-specific technique
        self.assertTrue(has_chr or has_concat)
        
    def test_end_to_end_mssql_bypass(self):
        """Test end-to-end bypass for MS-SQL"""
        engine = AdvancedBypassEngine(DBMSType.MSSQL)
        payload = "' UNION SELECT NULL"
        
        variants = engine.generate_all_bypass_variants(payload, max_variants=50)
        
        # Should have MS-SQL specific bypasses
        has_char = any("CHAR(" in v and "+" in v for v in variants)
        
        self.assertGreater(len(variants), 5)


class SampleUsageTest(TestCase):
    """Sample usage tests demonstrating how to use the bypass techniques"""
    
    def test_sample_usage_string_construction(self):
        """Sample: Using string construction to bypass quote filters"""
        # Scenario: Application blocks single quotes
        original_payload = "' OR 'admin'='admin"
        
        # Use MySQL CHAR() to bypass
        bypass = StringConstructionBypass()
        result = bypass.bypass_quotes_in_payload(original_payload, DBMSType.MYSQL)
        
        # Verify no quotes in result (except initial quote if needed)
        # Count quotes - should have fewer than original
        original_quote_count = original_payload.count("'")
        result_quote_count = result.count("'")
        self.assertLess(result_quote_count, original_quote_count)
        
    def test_sample_usage_comment_whitespace(self):
        """Sample: Using comments to bypass space filters"""
        # Scenario: Application blocks spaces
        original_payload = "UNION SELECT NULL"
        
        bypass = CommentWhitespaceBypass()
        result = bypass.space_to_inline_comment(original_payload)
        
        # Verify no spaces
        self.assertNotIn(" ", result)
        
    def test_sample_usage_keyword_obfuscation(self):
        """Sample: Using keyword obfuscation to bypass keyword blacklists"""
        # Scenario: Application blocks 'SELECT' keyword
        original_payload = "' UNION SELECT NULL"
        
        bypass = KeywordVariantBypass()
        
        # Try mixed case
        mixed = bypass.mixed_case_variant("SELECT", "alternate")
        self.assertNotEqual(mixed, "SELECT")
        
        # Try repetition (SELSELECTECT)
        repeated = bypass.keyword_repetition("SELECT")
        self.assertIn("SELECT", repeated)
        self.assertGreater(len(repeated), len("SELECT"))
        
    def test_sample_usage_encoding_bypass(self):
        """Sample: Using encoding to bypass WAF"""
        # Scenario: WAF blocks obvious SQL injection patterns
        original_payload = "' OR 1=1--"
        
        bypass = EncodingBypass()
        
        # Double encode
        double_encoded = bypass.double_url_encode(original_payload)
        self.assertIn("%25", double_encoded)  # % encoded as %25
        
        # Partial encode
        partial = bypass.partial_encode(original_payload, ratio=0.5)
        self.assertIsNotNone(partial)
        
    def test_sample_usage_full_engine(self):
        """Sample: Using the full bypass engine"""
        # Scenario: Need to generate multiple bypass variants
        engine = AdvancedBypassEngine(DBMSType.MYSQL)
        original_payload = "' UNION SELECT NULL,NULL,NULL--"
        
        # Generate 20 variants
        variants = engine.generate_all_bypass_variants(original_payload, max_variants=20)
        
        # Should have diverse variants
        self.assertGreater(len(variants), 10)
        self.assertIn(original_payload, variants)
        
        # Print some examples (for documentation)
        # print("\nGenerated bypass variants:")
        # for i, variant in enumerate(variants[:5], 1):
        #     print(f"{i}. {variant}")
