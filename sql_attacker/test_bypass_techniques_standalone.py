#!/usr/bin/env python3
"""
Standalone test script for bypass techniques (no Django required).
This script validates the core functionality of bypass techniques.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.bypass_techniques import (
    StringConstructionBypass,
    CommentWhitespaceBypass,
    KeywordVariantBypass,
    EncodingBypass,
    BatchQueryBypass,
    AdvancedBypassEngine,
    DBMSType,
)


def test_string_construction():
    """Test string construction bypass techniques"""
    print("Testing String Construction Bypass...")
    
    # Test Oracle CHR()
    result = StringConstructionBypass.string_to_chr_oracle("admin")
    assert "CHR(97)" in result, "Oracle CHR conversion failed"
    assert "||" in result, "Oracle concatenation missing"
    print("  ✓ Oracle CHR() conversion works")
    
    # Test MS-SQL CHAR()
    result = StringConstructionBypass.string_to_char_mssql("admin")
    assert "CHAR(97)" in result, "MS-SQL CHAR conversion failed"
    assert "+" in result, "MS-SQL concatenation missing"
    print("  ✓ MS-SQL CHAR() conversion works")
    
    # Test MySQL CHAR()
    result = StringConstructionBypass.string_to_char_mysql("admin")
    assert "CHAR(97,100,109,105,110)" in result, "MySQL CHAR conversion failed"
    print("  ✓ MySQL CHAR() conversion works")
    
    # Test hex conversion
    result = StringConstructionBypass.string_to_hex_mysql("admin")
    assert result == "0x61646d696e", f"MySQL hex conversion failed: {result}"
    print("  ✓ MySQL hex conversion works")
    
    # Test payload bypass
    payload = "' OR 'a'='a"
    result = StringConstructionBypass.bypass_quotes_in_payload(payload, DBMSType.MYSQL)
    assert "'a'" not in result or result.count("'") < payload.count("'"), "Quote bypass failed"
    print("  ✓ Payload quote bypass works")
    
    print("✅ String Construction tests passed!\n")


def test_comment_whitespace():
    """Test comment-based whitespace bypass"""
    print("Testing Comment Whitespace Bypass...")
    
    # Test space to comment
    payload = "SELECT FROM users"
    result = CommentWhitespaceBypass.space_to_inline_comment(payload)
    assert " " not in result, "Spaces still present"
    assert "/**/" in result, "Comments not inserted"
    print("  ✓ Space to comment conversion works")
    
    # Test keyword breaking
    payload = "SELECT FROM WHERE"
    result = CommentWhitespaceBypass.insert_comment_in_keywords(payload)
    assert "/*" in result, "Comments not inserted in keywords"
    print("  ✓ Keyword comment insertion works")
    
    # Test logical block
    result = CommentWhitespaceBypass.create_logical_block_injection("base")
    assert "OR" in result, "Logical block missing OR"
    assert "=" in result, "Logical block missing equals"
    print("  ✓ Logical block injection works")
    
    # Test variations
    variations = CommentWhitespaceBypass.generate_comment_variations("UNION SELECT")
    assert len(variations) > 1, "Not enough variations generated"
    print(f"  ✓ Generated {len(variations)} comment variations")
    
    print("✅ Comment Whitespace tests passed!\n")


def test_keyword_variants():
    """Test keyword variant bypass"""
    print("Testing Keyword Variant Bypass...")
    
    # Test mixed case
    result = KeywordVariantBypass.mixed_case_variant("SELECT", "alternate")
    assert result.upper() == "SELECT", "Case transformation failed"
    assert result != "SELECT" and result != "select", "No case variation"
    print("  ✓ Mixed case variant works")
    
    # Test hex encoding
    result = KeywordVariantBypass.hex_encode_keyword("SELECT", full=True)
    assert "%" in result, "Hex encoding failed"
    assert "S" not in result, "Original characters still present"
    print("  ✓ Hex encoding works")
    
    # Test keyword repetition
    result = KeywordVariantBypass.keyword_repetition("SELECT")
    assert "SELECT" in result, "Original keyword missing"
    assert len(result) > len("SELECT"), "No repetition added"
    print("  ✓ Keyword repetition works")
    
    # Test variant generation
    variants = KeywordVariantBypass.generate_keyword_variants("SELECT")
    assert len(variants) > 5, f"Not enough variants: {len(variants)}"
    print(f"  ✓ Generated {len(variants)} keyword variants")
    
    # Test payload application
    payload = "' UNION SELECT NULL"
    variants = KeywordVariantBypass.apply_to_payload(payload)
    assert len(variants) > 1, "No payload variants generated"
    print(f"  ✓ Generated {len(variants)} payload variants")
    
    print("✅ Keyword Variant tests passed!\n")


def test_encoding_bypass():
    """Test encoding bypass techniques"""
    print("Testing Encoding Bypass...")
    
    # Test double URL encoding
    payload = "' OR 1=1"
    result = EncodingBypass.double_url_encode(payload)
    assert "%25" in result, "Double encoding failed (% not encoded)"
    assert "'" not in result, "Single quote not encoded"
    print("  ✓ Double URL encoding works")
    
    # Test partial encoding
    result = EncodingBypass.partial_encode(payload, ratio=0.5)
    assert len(result) > 0, "Partial encoding failed"
    print("  ✓ Partial encoding works")
    
    # Test mixed encoding
    result = EncodingBypass.mixed_encoding(payload)
    assert "'" not in result, "Special chars not encoded"
    assert "%" in result, "No encoding applied"
    print("  ✓ Mixed encoding works")
    
    # Test unicode encoding
    result = EncodingBypass.unicode_encode("SELECT", 'standard')
    assert "\\u" in result, "Unicode encoding failed"
    print("  ✓ Unicode encoding works")
    
    # Test encoding variants
    variants = EncodingBypass.generate_encoding_variants(payload)
    assert len(variants) > 3, f"Not enough encoding variants: {len(variants)}"
    print(f"  ✓ Generated {len(variants)} encoding variants")
    
    print("✅ Encoding Bypass tests passed!\n")


def test_batch_query():
    """Test batch query bypass"""
    print("Testing Batch Query Bypass...")
    
    queries = ["SELECT 1", "SELECT 2"]
    
    # Test without semicolon
    result = BatchQueryBypass.batch_without_semicolon(queries)
    assert ";" not in result, "Semicolon present"
    assert "SELECT 1" in result and "SELECT 2" in result, "Queries missing"
    print("  ✓ Batch without semicolon works")
    
    # Test with EXEC
    result = BatchQueryBypass.batch_with_exec(queries)
    assert "EXEC" in result, "EXEC wrapper missing"
    assert "SELECT 1" in result and "SELECT 2" in result, "Queries missing"
    print("  ✓ Batch with EXEC works")
    
    print("✅ Batch Query tests passed!\n")


def test_advanced_bypass_engine():
    """Test the main bypass engine"""
    print("Testing Advanced Bypass Engine...")
    
    # Test initialization
    engine = AdvancedBypassEngine()
    assert engine.dbms == DBMSType.UNKNOWN, "Default DBMS should be UNKNOWN"
    print("  ✓ Engine initialization works")
    
    # Test DBMS setting
    engine.set_dbms(DBMSType.MYSQL)
    assert engine.dbms == DBMSType.MYSQL, "DBMS setting failed"
    print("  ✓ DBMS setting works")
    
    # Test comprehensive bypass generation
    payload = "' UNION SELECT NULL"
    variants = engine.generate_all_bypass_variants(payload, max_variants=20)
    assert len(variants) > 5, f"Not enough variants: {len(variants)}"
    assert len(variants) <= 20, f"Too many variants: {len(variants)}"
    assert payload in variants, "Original payload missing"
    print(f"  ✓ Generated {len(variants)} comprehensive bypass variants")
    
    # Test no duplicates
    assert len(variants) == len(set(variants)), "Duplicate variants found"
    print("  ✓ No duplicate variants")
    
    # Test specific technique methods
    string_variants = engine.generate_string_construction_variants(payload)
    comment_variants = engine.generate_comment_bypass_variants(payload)
    keyword_variants = engine.generate_keyword_bypass_variants(payload)
    encoding_variants = engine.generate_encoding_bypass_variants(payload)
    
    print(f"  ✓ String construction: {len(string_variants)} variants")
    print(f"  ✓ Comment bypass: {len(comment_variants)} variants")
    print(f"  ✓ Keyword bypass: {len(keyword_variants)} variants")
    print(f"  ✓ Encoding bypass: {len(encoding_variants)} variants")
    
    print("✅ Advanced Bypass Engine tests passed!\n")


def test_integration_scenarios():
    """Test real-world integration scenarios"""
    print("Testing Integration Scenarios...")
    
    # Scenario 1: MySQL with quote blocking
    engine = AdvancedBypassEngine(DBMSType.MYSQL)
    payload = "' OR 'admin'='admin"
    variants = engine.generate_all_bypass_variants(payload, max_variants=30)
    
    has_char = any("CHAR(" in v for v in variants)
    has_comment = any("/*" in v for v in variants)
    has_encoding = any("%" in v for v in variants)
    
    assert has_char or has_comment or has_encoding, "No bypass techniques applied"
    print(f"  ✓ MySQL scenario: {len(variants)} variants with multiple techniques")
    
    # Scenario 2: Oracle
    engine = AdvancedBypassEngine(DBMSType.ORACLE)
    payload = "' UNION SELECT NULL FROM dual"
    variants = engine.generate_all_bypass_variants(payload, max_variants=30)
    
    has_chr = any("CHR(" in v for v in variants)
    has_concat = any("||" in v for v in variants)
    
    print(f"  ✓ Oracle scenario: {len(variants)} variants (CHR: {has_chr}, ||: {has_concat})")
    
    # Scenario 3: MS-SQL
    engine = AdvancedBypassEngine(DBMSType.MSSQL)
    payload = "' UNION SELECT NULL"
    variants = engine.generate_all_bypass_variants(payload, max_variants=30)
    
    print(f"  ✓ MS-SQL scenario: {len(variants)} variants")
    
    print("✅ Integration Scenario tests passed!\n")


def demonstrate_usage():
    """Demonstrate typical usage patterns"""
    print("=" * 60)
    print("USAGE DEMONSTRATION")
    print("=" * 60 + "\n")
    
    print("Example 1: Bypassing Quote Filters (MySQL)")
    print("-" * 50)
    original = "' OR 'admin'='admin"
    bypass = StringConstructionBypass.bypass_quotes_in_payload(original, DBMSType.MYSQL)
    print(f"Original: {original}")
    print(f"Bypass:   {bypass}\n")
    
    print("Example 2: Bypassing Space Filters")
    print("-" * 50)
    original = "UNION SELECT NULL"
    bypass = CommentWhitespaceBypass.space_to_inline_comment(original)
    print(f"Original: {original}")
    print(f"Bypass:   {bypass}\n")
    
    print("Example 3: Keyword Obfuscation")
    print("-" * 50)
    original = "SELECT"
    print(f"Original: {original}")
    print(f"Mixed case: {KeywordVariantBypass.mixed_case_variant(original, 'alternate')}")
    print(f"Repeated: {KeywordVariantBypass.keyword_repetition(original)}")
    print(f"Hex: {KeywordVariantBypass.hex_encode_keyword(original)}\n")
    
    print("Example 4: Comprehensive Bypass Generation")
    print("-" * 50)
    engine = AdvancedBypassEngine(DBMSType.MYSQL)
    original = "' UNION SELECT NULL--"
    variants = engine.generate_all_bypass_variants(original, max_variants=10)
    print(f"Original: {original}")
    print(f"Generated {len(variants)} variants:")
    for i, variant in enumerate(variants[:5], 1):
        print(f"  {i}. {variant}")
    print("  ...\n")


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("BYPASS TECHNIQUES STANDALONE TEST SUITE")
    print("=" * 60 + "\n")
    
    try:
        test_string_construction()
        test_comment_whitespace()
        test_keyword_variants()
        test_encoding_bypass()
        test_batch_query()
        test_advanced_bypass_engine()
        test_integration_scenarios()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60 + "\n")
        
        demonstrate_usage()
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}\n")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
