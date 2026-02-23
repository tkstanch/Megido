#!/usr/bin/env python3
"""
Test suite for OOB (Out-of-Band) SQL Injection Payload Generator
Tests payload generation for MS-SQL, Oracle, and MySQL
"""

import sys
import os

# Add parent directory to path for standalone execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sql_attacker.oob_payloads import (
    OOBPayloadGenerator,
    OOBTechnique,
    DatabaseType,
    OOBPayload
)


def test_initialization():
    """Test OOBPayloadGenerator initialization"""
    print("Testing initialization...")
    
    # Default initialization
    generator = OOBPayloadGenerator()
    assert generator.attacker_host == "attacker.com"
    assert generator.attacker_port == 80
    
    # Custom initialization
    generator = OOBPayloadGenerator("evil.com", 8080)
    assert generator.attacker_host == "evil.com"
    assert generator.attacker_port == 8080
    
    # Test set_attacker_host
    generator.set_attacker_host("newhost.com", 443)
    assert generator.attacker_host == "newhost.com"
    assert generator.attacker_port == 443
    
    print("✓ Initialization tests passed")


def test_mssql_payloads():
    """Test MS-SQL OOB payload generation"""
    print("\nTesting MS-SQL payload generation...")
    
    # Test domain for validation - not used for actual URL sanitization
    generator = OOBPayloadGenerator("attacker.com", 80)
    payloads = generator.generate_mssql_payloads()
    
    # Should generate multiple payloads
    assert len(payloads) >= 4, f"Expected at least 4 MS-SQL payloads, got {len(payloads)}"
    
    # Check payload types
    techniques = [p.technique for p in payloads]
    assert OOBTechnique.MSSQL_OPENROWSET_HTTP in techniques
    assert OOBTechnique.MSSQL_OPENROWSET_SMB in techniques
    
    # Verify payload structure
    for payload in payloads:
        assert isinstance(payload, OOBPayload)
        assert payload.payload is not None
        assert len(payload.payload) > 0
        assert payload.description is not None
        assert payload.listener_type in ['http', 'smb']
        assert payload.requires_privileges is True
        assert "attacker.com" in payload.payload
    
    # Test HTTP payload content
    http_payloads = [p for p in payloads if p.technique == OOBTechnique.MSSQL_OPENROWSET_HTTP]
    assert len(http_payloads) > 0
    assert any("OPENROWSET" in p.payload for p in http_payloads)
    assert any("http://" in p.payload for p in http_payloads)
    
    # Test SMB payload content
    smb_payloads = [p for p in payloads if p.technique == OOBTechnique.MSSQL_OPENROWSET_SMB]
    assert len(smb_payloads) > 0
    assert any("OPENROWSET" in p.payload for p in smb_payloads)
    assert any("\\\\" in p.payload for p in smb_payloads)
    
    # Test with custom data extraction
    custom_payloads = generator.generate_mssql_payloads("DB_NAME()")
    assert len(custom_payloads) >= 4
    assert any("DB_NAME()" in p.payload for p in custom_payloads)
    
    print("✓ MS-SQL payload tests passed")


def test_oracle_payloads():
    """Test Oracle OOB payload generation"""
    print("\nTesting Oracle payload generation...")
    
    # Test domain for validation - not used for actual URL sanitization
    generator = OOBPayloadGenerator("oracle-test.com", 80)
    payloads = generator.generate_oracle_payloads()
    
    # Should generate multiple payloads
    assert len(payloads) >= 5, f"Expected at least 5 Oracle payloads, got {len(payloads)}"
    
    # Check payload types
    techniques = [p.technique for p in payloads]
    assert OOBTechnique.ORACLE_UTL_HTTP in techniques
    assert OOBTechnique.ORACLE_UTL_INADDR in techniques
    assert OOBTechnique.ORACLE_DBMS_LDAP in techniques
    
    # Verify payload structure
    for payload in payloads:
        assert isinstance(payload, OOBPayload)
        assert payload.payload is not None
        assert len(payload.payload) > 0
        assert payload.description is not None
        assert payload.listener_type in ['http', 'dns', 'ldap']
        assert payload.requires_privileges is True
        assert "oracle-test.com" in payload.payload
    
    # Test UTL_HTTP payloads
    utl_http = [p for p in payloads if p.technique == OOBTechnique.ORACLE_UTL_HTTP]
    assert len(utl_http) > 0
    assert any("UTL_HTTP" in p.payload for p in utl_http)
    assert any("FROM dual" in p.payload for p in utl_http)
    
    # Test UTL_INADDR (DNS) payloads
    utl_inaddr = [p for p in payloads if p.technique == OOBTechnique.ORACLE_UTL_INADDR]
    assert len(utl_inaddr) > 0
    assert any("UTL_INADDR" in p.payload for p in utl_inaddr)
    assert any("get_host_address" in p.payload for p in utl_inaddr)
    
    # Test DBMS_LDAP payloads
    dbms_ldap = [p for p in payloads if p.technique == OOBTechnique.ORACLE_DBMS_LDAP]
    assert len(dbms_ldap) > 0
    assert any("DBMS_LDAP" in p.payload for p in dbms_ldap)
    assert any("INIT" in p.payload for p in dbms_ldap)
    
    # Test with custom data extraction
    custom_payloads = generator.generate_oracle_payloads("banner")
    assert len(custom_payloads) >= 5
    assert any("banner" in p.payload for p in custom_payloads)
    
    print("✓ Oracle payload tests passed")


def test_mysql_payloads():
    """Test MySQL OOB payload generation"""
    print("\nTesting MySQL payload generation...")
    
    # Test domain for validation - not used for actual URL sanitization
    generator = OOBPayloadGenerator("mysql-test.com", 445)
    payloads = generator.generate_mysql_payloads()
    
    # Should generate multiple payloads
    assert len(payloads) >= 3, f"Expected at least 3 MySQL payloads, got {len(payloads)}"
    
    # Check payload types
    techniques = [p.technique for p in payloads]
    assert OOBTechnique.MYSQL_LOAD_FILE_UNC in techniques
    assert OOBTechnique.MYSQL_INTO_OUTFILE_UNC in techniques
    
    # Verify payload structure
    for payload in payloads:
        assert isinstance(payload, OOBPayload)
        assert payload.payload is not None
        assert len(payload.payload) > 0
        assert payload.description is not None
        assert payload.listener_type == 'smb'
        assert payload.requires_privileges is True
        assert "mysql-test.com" in payload.payload
    
    # Test LOAD_FILE payloads
    load_file = [p for p in payloads if p.technique == OOBTechnique.MYSQL_LOAD_FILE_UNC]
    assert len(load_file) > 0
    assert any("LOAD_FILE" in p.payload for p in load_file)
    assert any("\\\\\\\\" in p.payload for p in load_file)  # UNC path with escaping
    
    # Test INTO OUTFILE payloads
    into_outfile = [p for p in payloads if p.technique == OOBTechnique.MYSQL_INTO_OUTFILE_UNC]
    assert len(into_outfile) > 0
    assert any("INTO OUTFILE" in p.payload for p in into_outfile)
    
    # Test with custom data extraction
    custom_payloads = generator.generate_mysql_payloads("DATABASE()")
    assert len(custom_payloads) >= 3
    assert any("DATABASE()" in p.payload for p in custom_payloads)
    
    print("✓ MySQL payload tests passed")


def test_generate_all_payloads():
    """Test generating all payloads at once"""
    print("\nTesting generate_all_payloads...")
    
    generator = OOBPayloadGenerator("all-test.com", 80)
    
    # Generate all payloads
    all_payloads = generator.generate_all_payloads()
    assert 'mssql' in all_payloads
    assert 'oracle' in all_payloads
    assert 'mysql' in all_payloads
    
    assert len(all_payloads['mssql']) >= 4
    assert len(all_payloads['oracle']) >= 5
    assert len(all_payloads['mysql']) >= 3
    
    # Generate for specific database
    mssql_only = generator.generate_all_payloads(db_type=DatabaseType.MSSQL)
    assert 'mssql' in mssql_only
    assert 'oracle' not in mssql_only
    assert 'mysql' not in mssql_only
    
    oracle_only = generator.generate_all_payloads(db_type=DatabaseType.ORACLE)
    assert 'oracle' in oracle_only
    assert 'mssql' not in oracle_only
    assert 'mysql' not in oracle_only
    
    mysql_only = generator.generate_all_payloads(db_type=DatabaseType.MYSQL)
    assert 'mysql' in mysql_only
    assert 'mssql' not in mysql_only
    assert 'oracle' not in mysql_only
    
    # Test with custom data extraction
    custom_all = generator.generate_all_payloads(data_to_exfiltrate="secret_column")
    for db_payloads in custom_all.values():
        # At least one payload should contain the custom extraction
        assert any("secret_column" in p.payload for p in db_payloads)
    
    print("✓ Generate all payloads tests passed")


def test_listener_setup_guide():
    """Test listener setup guide generation"""
    print("\nTesting listener setup guides...")
    
    generator = OOBPayloadGenerator()
    
    # Test all listener types
    http_guide = generator.get_listener_setup_guide('http')
    assert len(http_guide) > 0
    assert "HTTP" in http_guide or "http" in http_guide
    assert "nc -lvnp" in http_guide or "netcat" in http_guide.lower()
    
    smb_guide = generator.get_listener_setup_guide('smb')
    assert len(smb_guide) > 0
    assert "SMB" in smb_guide or "smb" in smb_guide
    assert "smbserver" in smb_guide or "Responder" in smb_guide
    
    dns_guide = generator.get_listener_setup_guide('dns')
    assert len(dns_guide) > 0
    assert "DNS" in dns_guide or "dns" in dns_guide
    assert "tcpdump" in dns_guide or "dnslog" in dns_guide
    
    ldap_guide = generator.get_listener_setup_guide('ldap')
    assert len(ldap_guide) > 0
    assert "LDAP" in ldap_guide or "ldap" in ldap_guide
    assert "389" in ldap_guide  # LDAP port
    
    # Test unknown listener type
    unknown_guide = generator.get_listener_setup_guide('unknown')
    assert "No setup guide available" in unknown_guide
    
    print("✓ Listener setup guide tests passed")


def test_format_payload_for_output():
    """Test payload formatting"""
    print("\nTesting payload formatting...")
    
    # Test domain for validation - not used for actual URL sanitization
    generator = OOBPayloadGenerator("format-test.com", 80)
    payloads = generator.generate_mssql_payloads()
    
    # Format a payload
    formatted = generator.format_payload_for_output(payloads[0])
    assert len(formatted) > 0
    assert "Technique:" in formatted
    assert "Description:" in formatted
    assert "Payload:" in formatted
    assert "Listener Setup:" in formatted
    assert "format-test.com" in formatted
    
    print("✓ Payload formatting tests passed")


def test_payload_injection_contexts():
    """Test payloads work in different injection contexts"""
    print("\nTesting payload injection contexts...")
    
    generator = OOBPayloadGenerator("context-test.com", 80)
    
    # Test that payloads start with injection escape characters
    mssql_payloads = generator.generate_mssql_payloads()
    # Most should start with ' or ; to break out of existing query
    assert any(p.payload.startswith("'") or p.payload.startswith(";") for p in mssql_payloads)
    
    oracle_payloads = generator.generate_oracle_payloads()
    assert any(p.payload.startswith("'") for p in oracle_payloads)
    
    mysql_payloads = generator.generate_mysql_payloads()
    assert any(p.payload.startswith("'") for p in mysql_payloads)
    
    print("✓ Payload injection context tests passed")


def test_special_characters_escaping():
    """Test that special characters are properly escaped in payloads"""
    print("\nTesting special character escaping...")
    
    generator = OOBPayloadGenerator("test.com", 80)
    
    # MySQL should have properly escaped backslashes for UNC paths
    mysql_payloads = generator.generate_mysql_payloads()
    for payload in mysql_payloads:
        if "LOAD_FILE" in payload.payload or "INTO OUTFILE" in payload.payload:
            # UNC paths should have multiple backslashes for proper escaping
            assert "\\\\" in payload.payload
    
    print("✓ Special character escaping tests passed")


def run_all_tests():
    """Run all test functions"""
    print("=" * 70)
    print("Running OOB Payload Generator Test Suite")
    print("=" * 70)
    
    try:
        test_initialization()
        test_mssql_payloads()
        test_oracle_payloads()
        test_mysql_payloads()
        test_generate_all_payloads()
        test_listener_setup_guide()
        test_format_payload_for_output()
        test_payload_injection_contexts()
        test_special_characters_escaping()
        
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED!")
        print("=" * 70)
        return True
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)


# ---------------------------------------------------------------------------
# unittest-based tests (run by pytest)
# ---------------------------------------------------------------------------

import unittest

from sql_attacker.oob_payloads import _validate_host, _validate_port


class TestOOBInputValidation(unittest.TestCase):
    """Tests for host/port input validation in OOBPayloadGenerator."""

    # ------------------------------------------------------------------
    # _validate_host
    # ------------------------------------------------------------------

    def test_validate_host_accepts_valid_hostname(self):
        self.assertEqual(_validate_host("attacker.com"), "attacker.com")

    def test_validate_host_strips_whitespace(self):
        self.assertEqual(_validate_host("  attacker.com  "), "attacker.com")

    def test_validate_host_rejects_empty_string(self):
        with self.assertRaises(ValueError):
            _validate_host("")

    def test_validate_host_rejects_whitespace_only(self):
        with self.assertRaises(ValueError):
            _validate_host("   ")

    def test_validate_host_rejects_non_string(self):
        with self.assertRaises(ValueError):
            _validate_host(None)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # _validate_port
    # ------------------------------------------------------------------

    def test_validate_port_accepts_valid_port(self):
        self.assertEqual(_validate_port(80), 80)
        self.assertEqual(_validate_port(443), 443)
        self.assertEqual(_validate_port(65535), 65535)
        self.assertEqual(_validate_port(1), 1)

    def test_validate_port_rejects_zero(self):
        with self.assertRaises(ValueError):
            _validate_port(0)

    def test_validate_port_rejects_negative(self):
        with self.assertRaises(ValueError):
            _validate_port(-1)

    def test_validate_port_rejects_too_high(self):
        with self.assertRaises(ValueError):
            _validate_port(65536)

    def test_validate_port_rejects_non_integer(self):
        with self.assertRaises(ValueError):
            _validate_port("80")  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # OOBPayloadGenerator constructor validation
    # ------------------------------------------------------------------

    def test_constructor_rejects_empty_host(self):
        with self.assertRaises(ValueError):
            OOBPayloadGenerator("", 80)

    def test_constructor_rejects_bad_port(self):
        with self.assertRaises(ValueError):
            OOBPayloadGenerator("attacker.com", 0)

    def test_set_attacker_host_rejects_empty_host(self):
        gen = OOBPayloadGenerator("attacker.com", 80)
        with self.assertRaises(ValueError):
            gen.set_attacker_host("", 80)

    def test_set_attacker_host_rejects_bad_port(self):
        gen = OOBPayloadGenerator("attacker.com", 80)
        with self.assertRaises(ValueError):
            gen.set_attacker_host("attacker.com", 99999)

    def test_set_attacker_host_updates_correctly(self):
        gen = OOBPayloadGenerator("old.com", 80)
        gen.set_attacker_host("new.com", 443)
        self.assertEqual(gen.attacker_host, "new.com")
        self.assertEqual(gen.attacker_port, 443)
        self.assertEqual(gen.attacker_ip, "new.com")
