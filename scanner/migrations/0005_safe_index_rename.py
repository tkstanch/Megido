# Generated migration for safe index rename
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
# This migration uses a custom operation with database-specific logic:
# - PostgreSQL: Uses PL/pgSQL to check if index exists before renaming
# - SQLite: Silently succeeds (SQLite handles indexes differently)
# This makes the migration idempotent and safe to run in any environment.
#
# MAINTAINER NOTE:
# If you need to rename other indexes in the future, follow this same pattern:
# 1. Check if the old index exists
# 2. Check if the new index doesn't exist yet
# 3. Only perform the rename if both conditions are true

from django.db import migrations


def rename_index_safely(apps, schema_editor):
    """
    Safely rename an index, checking if it exists first.
    This prevents errors when the index doesn't exist.
    
    Handles both PostgreSQL and SQLite:
    - PostgreSQL: Checks pg_indexes and renames if found
    - SQLite: No-op (SQLite doesn't use explicit index names the same way)
    """
    # Check database backend
    if schema_editor.connection.vendor == 'postgresql':
        # PostgreSQL: Use PL/pgSQL to conditionally rename
        with schema_editor.connection.cursor() as cursor:
            cursor.execute("""
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
            """)
    elif schema_editor.connection.vendor == 'sqlite':
        # SQLite: No-op - SQLite handles index names differently
        # Django manages SQLite indexes automatically, so this is safe to skip
        pass
    # Other databases: Also no-op for safety
    # If you need to support other databases, add handling here


def reverse_rename_index_safely(apps, schema_editor):
    """
    Reverse the index rename operation safely.
    """
    if schema_editor.connection.vendor == 'postgresql':
        # PostgreSQL: Rename back to original name
        with schema_editor.connection.cursor() as cursor:
            cursor.execute("""
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
            """)
    elif schema_editor.connection.vendor == 'sqlite':
        # SQLite: No-op
        pass


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_engineexecution_enginefinding_enginescan_and_more'),
    ]

    operations = [
        # Use RunPython to execute custom Python code that handles different databases
        migrations.RunPython(
            code=rename_index_safely,
            reverse_code=reverse_rename_index_safely,
        ),
    ]
