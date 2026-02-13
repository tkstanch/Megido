# Manually created migration for safe index rename
# 
# RATIONALE FOR THIS MIGRATION:
# -----------------------------
# This migration addresses a common issue in Django migrations where RenameIndex
# operations fail if the index doesn't exist in the database. This can happen when:
# - Developers have different database states (e.g., fresh database vs. migrated)
# - Migrations were applied out of order or some were skipped
# - Database was manually modified
# - Different environments (dev/staging/prod) have diverged
#
# BEST PRACTICE:
# Never rewrite existing migrations in shared/production codebases. Instead, create
# new migrations that are robust and handle edge cases gracefully.
#
# IMPLEMENTATION:
# This migration uses a custom RunSQL operation with database-specific SQL:
# - PostgreSQL: Uses PL/pgSQL DO block to check if index exists before renaming
# - SQLite: Uses a no-op statement (SQLite handles indexes differently)
# This makes the migration idempotent and safe to run in any environment.
#
# MAINTAINER NOTE:
# If you need to rename other indexes in the future, follow this same pattern:
# 1. Check if the old index exists
# 2. Check if the new index doesn't exist yet
# 3. Only perform the rename if both conditions are true

from django.db import migrations


class SafeRenameIndex(migrations.RunSQL):
    """
    Custom migration operation that safely renames an index with database-specific logic.
    
    - PostgreSQL: Uses PL/pgSQL DO block to conditionally rename the index
    - SQLite: No-op (SQLite handles indexes differently)
    """
    
    def __init__(self):
        # PostgreSQL SQL for forward migration
        postgresql_forward = """
            DO $$
            BEGIN
                -- Check if old index exists and new index doesn't exist
                IF EXISTS (
                    SELECT 1 FROM pg_indexes 
                    WHERE indexname = 'scanner_vul_risk_sc_idx'
                ) AND NOT EXISTS (
                    SELECT 1 FROM pg_indexes 
                    WHERE indexname = 'scanner_vul_risk_score_idx'
                ) THEN
                    -- Rename the index
                    ALTER INDEX scanner_vul_risk_sc_idx 
                    RENAME TO scanner_vul_risk_score_idx;
                END IF;
            END $$;
        """
        
        # PostgreSQL SQL for reverse migration
        postgresql_reverse = """
            DO $$
            BEGIN
                -- Check if new index exists and old index doesn't exist
                IF EXISTS (
                    SELECT 1 FROM pg_indexes 
                    WHERE indexname = 'scanner_vul_risk_score_idx'
                ) AND NOT EXISTS (
                    SELECT 1 FROM pg_indexes 
                    WHERE indexname = 'scanner_vul_risk_sc_idx'
                ) THEN
                    -- Rename back to old name
                    ALTER INDEX scanner_vul_risk_score_idx 
                    RENAME TO scanner_vul_risk_sc_idx;
                END IF;
            END $$;
        """
        
        # SQLite no-op (SQLite doesn't support DO blocks and handles indexes differently)
        sqlite_noop = "SELECT 1;"
        
        super().__init__(
            sql=postgresql_forward,
            reverse_sql=postgresql_reverse,
        )
    
    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        """Execute the forward migration with database-specific logic."""
        if schema_editor.connection.vendor == 'postgresql':
            # PostgreSQL: Run the conditional PL/pgSQL block
            super().database_forwards(app_label, schema_editor, from_state, to_state)
        elif schema_editor.connection.vendor == 'sqlite':
            # SQLite: No-op (SQLite doesn't need explicit index renaming)
            pass
        # Other databases: Also no-op for safety
    
    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        """Execute the reverse migration with database-specific logic."""
        if schema_editor.connection.vendor == 'postgresql':
            # PostgreSQL: Run the conditional PL/pgSQL block
            super().database_backwards(app_label, schema_editor, from_state, to_state)
        elif schema_editor.connection.vendor == 'sqlite':
            # SQLite: No-op
            pass
        # Other databases: Also no-op for safety


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_engineexecution_enginefinding_enginescan_and_more'),
    ]

    operations = [
        # Use custom SafeRenameIndex operation that handles different databases
        SafeRenameIndex(),
    ]
