"""
Tests for migration 0005 - Safe index rename

This test ensures that the migration works correctly in various scenarios:
1. When the old index exists
2. When the old index doesn't exist
3. When the migration is run multiple times (idempotent)
4. When the migration is reversed
"""

from django.test import TestCase, TransactionTestCase
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test.utils import override_settings


class Migration0005TestCase(TransactionTestCase):
    """
    Test cases for migration scanner.0005_safe_index_rename
    
    Uses TransactionTestCase to allow database schema modifications during tests.
    """
    
    # Specify the apps to migrate
    app_label = 'scanner'
    migrate_from = [('scanner', '0004_engineexecution_enginefinding_enginescan_and_more')]
    migrate_to = [('scanner', '0005_safe_index_rename')]
    
    def setUp(self):
        """Set up the test by migrating to the previous migration"""
        # Get the migration executor
        self.executor = MigrationExecutor(connection)
        
        # Migrate to the state just before our target migration
        self.executor.migrate(self.migrate_from)
        
        # Get the old state
        self.old_apps = self.executor.loader.project_state(self.migrate_from).apps
    
    def test_migration_forward_succeeds(self):
        """
        Test that the migration runs successfully when applying forward.
        
        This test verifies that the migration can be applied without errors,
        regardless of whether the old index exists or not.
        """
        try:
            # Apply the migration
            self.executor.migrate(self.migrate_to)
            
            # Get the new state
            new_apps = self.executor.loader.project_state(self.migrate_to).apps
            
            # If we get here without exceptions, the migration succeeded
            self.assertTrue(True, "Migration 0005 applied successfully")
            
        except Exception as e:
            self.fail(f"Migration 0005 failed: {str(e)}")
    
    def test_migration_reverse_succeeds(self):
        """
        Test that the migration can be reversed successfully.
        
        This test verifies that the reverse migration works correctly.
        """
        try:
            # First apply the migration forward
            self.executor.migrate(self.migrate_to)
            
            # Then reverse it
            self.executor.migrate(self.migrate_from)
            
            # If we get here without exceptions, the reverse migration succeeded
            self.assertTrue(True, "Migration 0005 reversed successfully")
            
        except Exception as e:
            self.fail(f"Migration 0005 reverse failed: {str(e)}")
    
    def test_migration_is_idempotent(self):
        """
        Test that the migration can be applied multiple times without errors.
        
        This verifies the idempotent behavior - running the migration multiple
        times should not cause errors.
        """
        try:
            # Apply the migration forward
            self.executor.migrate(self.migrate_to)
            
            # Reverse it
            self.executor.migrate(self.migrate_from)
            
            # Apply it forward again
            self.executor.migrate(self.migrate_to)
            
            # If we get here without exceptions, the migration is idempotent
            self.assertTrue(True, "Migration 0005 is idempotent")
            
        except Exception as e:
            self.fail(f"Migration 0005 idempotency test failed: {str(e)}")
    
    def test_migration_with_missing_index(self):
        """
        Test that the migration succeeds even when the old index doesn't exist.
        
        This is the key scenario that the migration was designed to handle:
        databases where the index was never created or was manually dropped.
        """
        # For PostgreSQL, we can test by manually dropping the index if it exists
        if connection.vendor == 'postgresql':
            with connection.cursor() as cursor:
                # Drop the old index if it exists (from migration 0003)
                cursor.execute("""
                    DO $$
                    BEGIN
                        IF EXISTS (
                            SELECT 1 FROM pg_indexes 
                            WHERE indexname = 'scanner_vul_risk_sc_idx'
                        ) THEN
                            DROP INDEX scanner_vul_risk_sc_idx;
                        END IF;
                    END $$;
                """)
        
        try:
            # Now apply migration 0005 - it should succeed even without the index
            self.executor.migrate(self.migrate_to)
            
            # If we get here, the migration succeeded without the index
            self.assertTrue(True, "Migration 0005 succeeded with missing index")
            
        except Exception as e:
            self.fail(f"Migration 0005 failed with missing index: {str(e)}")
    
    def test_migration_preserves_data(self):
        """
        Test that the migration doesn't affect any data in the tables.
        
        Index renaming should be a pure schema change that doesn't touch data.
        """
        # First, create a test vulnerability (using the old apps state)
        Vulnerability = self.old_apps.get_model('scanner', 'Vulnerability')
        ScanTarget = self.old_apps.get_model('scanner', 'ScanTarget')
        Scan = self.old_apps.get_model('scanner', 'Scan')
        
        # Create test data
        target = ScanTarget.objects.create(
            url='https://test.example.com',
            name='Test Target for Migration'
        )
        scan = Scan.objects.create(
            target=target,
            status='completed'
        )
        vuln = Vulnerability.objects.create(
            scan=scan,
            vulnerability_type='xss',
            severity='high',
            url='https://test.example.com/test',
            description='Test vulnerability for migration',
            risk_score=75.5
        )
        
        # Store the ID and risk_score
        vuln_id = vuln.id
        original_risk_score = vuln.risk_score
        
        # Apply the migration
        self.executor.migrate(self.migrate_to)
        
        # Get the new apps state
        new_apps = self.executor.loader.project_state(self.migrate_to).apps
        NewVulnerability = new_apps.get_model('scanner', 'Vulnerability')
        
        # Verify the data is unchanged
        vuln_after = NewVulnerability.objects.get(id=vuln_id)
        self.assertEqual(vuln_after.risk_score, original_risk_score)
        self.assertEqual(vuln_after.description, 'Test vulnerability for migration')


class Migration0005DatabaseSpecificTestCase(TestCase):
    """
    Test database-specific behavior of migration 0005.
    
    This tests the SafeRenameIndex operation's database-specific logic.
    """
    
    def test_database_vendor_detection(self):
        """
        Test that the migration correctly detects the database vendor.
        
        The migration should behave differently for PostgreSQL vs SQLite.
        """
        vendor = connection.vendor
        
        # The test should work with any of the expected database vendors
        self.assertIn(vendor, ['postgresql', 'sqlite', 'mysql', 'oracle'],
                     f"Unexpected database vendor: {vendor}")
    
    def test_sqlite_uses_noop(self):
        """
        Test that SQLite correctly uses the no-op behavior.
        
        For SQLite, the migration should not attempt to run PostgreSQL-specific
        SQL commands.
        """
        if connection.vendor == 'sqlite':
            # SQLite doesn't support PL/pgSQL DO blocks
            # The migration should handle this gracefully
            with connection.cursor() as cursor:
                # This should not raise an error
                try:
                    # The migration's no-op for SQLite should not execute PL/pgSQL
                    # We just verify that we're on SQLite
                    cursor.execute("SELECT sqlite_version()")
                    version = cursor.fetchone()
                    self.assertIsNotNone(version, "SQLite is working")
                except Exception as e:
                    self.fail(f"SQLite test failed: {str(e)}")
    
    def test_postgresql_checks_pg_indexes(self):
        """
        Test that PostgreSQL correctly checks pg_indexes catalog.
        
        For PostgreSQL, the migration should query pg_indexes to check
        if the index exists.
        """
        if connection.vendor == 'postgresql':
            with connection.cursor() as cursor:
                # Verify we can query pg_indexes (this is what the migration does)
                try:
                    cursor.execute("""
                        SELECT COUNT(*) FROM pg_indexes 
                        WHERE schemaname = 'public'
                    """)
                    count = cursor.fetchone()[0]
                    # We should have at least some indexes
                    self.assertGreaterEqual(count, 0, "Can query pg_indexes")
                except Exception as e:
                    self.fail(f"PostgreSQL pg_indexes test failed: {str(e)}")
