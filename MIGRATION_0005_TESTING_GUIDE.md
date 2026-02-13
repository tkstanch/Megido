# Migration 0005 Testing Guide

## Overview
This document describes how to test migration `scanner.0005_safe_index_rename` to verify it works correctly in different scenarios.

## What This Migration Does
- **Purpose**: Safely renames the index `scanner_vul_risk_sc_idx` to `scanner_vul_risk_score_idx`
- **Key Feature**: Uses conditional PL/pgSQL logic to check if the index exists before attempting to rename it
- **Database Support**: Works with both PostgreSQL and SQLite

## Testing Scenarios

### Scenario 1: Fresh Database Migration
Tests that the migration works on a fresh database where the index may or may not exist.

```bash
# Remove existing database
rm -f db.sqlite3

# Run migrations
USE_SQLITE=true python manage.py migrate scanner
```

**Expected Result**: Migration completes successfully without errors.

### Scenario 2: Idempotency Test
Tests that the migration can be run multiple times without errors.

```bash
# Run migration multiple times
USE_SQLITE=true python manage.py migrate scanner
USE_SQLITE=true python manage.py migrate scanner
```

**Expected Result**: No errors, even when run multiple times.

### Scenario 3: Reverse Migration Test
Tests that the migration can be reversed successfully.

```bash
# Migrate to 0005
USE_SQLITE=true python manage.py migrate scanner 0005

# Reverse to 0004
USE_SQLITE=true python manage.py migrate scanner 0004

# Forward to 0005 again
USE_SQLITE=true python manage.py migrate scanner 0005
```

**Expected Result**: All migrations (forward and reverse) complete successfully.

### Scenario 4: Missing Index Test
Tests that the migration works even when the old index doesn't exist.

For PostgreSQL:
```bash
# Drop the old index manually, then run migration
psql -d megido_db -c "DROP INDEX IF EXISTS scanner_vul_risk_sc_idx;"
python manage.py migrate scanner 0005
```

For SQLite (index handling is automatic):
```bash
USE_SQLITE=true python manage.py migrate scanner 0005
```

**Expected Result**: Migration completes successfully even if index is missing.

## Automated Test Suite

A comprehensive test suite is available in `scanner/tests_migration_0005.py`. To run it:

```bash
# Run all migration tests
USE_SQLITE=true python manage.py test scanner.tests_migration_0005
```

The test suite includes:
- `test_migration_forward_succeeds` - Tests forward migration
- `test_migration_reverse_succeeds` - Tests reverse migration
- `test_migration_is_idempotent` - Tests multiple applications
- `test_migration_with_missing_index` - Tests with missing index
- `test_migration_preserves_data` - Tests data integrity
- `test_database_vendor_detection` - Tests database detection
- `test_sqlite_uses_noop` - Tests SQLite no-op behavior
- `test_postgresql_checks_pg_indexes` - Tests PostgreSQL index checking

## Manual Verification Script

A quick verification script is available:

```bash
cd /home/runner/work/Megido/Megido
rm -f db.sqlite3
USE_SQLITE=true python -c "
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
django.setup()

from django.db import connection
from django.db.migrations.executor import MigrationExecutor

# Run all tests
tests = [
    ('Fresh database', [('scanner', '0005_safe_index_rename')]),
    ('Idempotency', [('scanner', '0005_safe_index_rename')]),
    ('Reverse', [('scanner', '0004_engineexecution_enginefinding_enginescan_and_more')]),
    ('Forward again', [('scanner', '0005_safe_index_rename')]),
]

for test_name, target in tests:
    print(f'Testing: {test_name}...')
    executor = MigrationExecutor(connection)
    try:
        executor.migrate(target)
        print(f'  ✓ {test_name} PASSED')
    except Exception as e:
        print(f'  ✗ {test_name} FAILED: {e}')

print('\nAll tests completed!')
"
```

## PostgreSQL-Specific Testing

For PostgreSQL environments, additional testing can verify the PL/pgSQL logic:

```sql
-- Check if old index exists
SELECT * FROM pg_indexes WHERE indexname = 'scanner_vul_risk_sc_idx';

-- Check if new index exists
SELECT * FROM pg_indexes WHERE indexname = 'scanner_vul_risk_score_idx';

-- Manually test the conditional logic
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'scanner_vul_risk_sc_idx'
    ) THEN
        RAISE NOTICE 'Old index exists';
    ELSE
        RAISE NOTICE 'Old index does not exist';
    END IF;
END $$;
```

## Troubleshooting

### Error: "relation 'scanner_vul_risk_sc_idx' does not exist"
**Cause**: Using older migration code that doesn't check for index existence.
**Solution**: Ensure you're using the updated migration 0005 that includes conditional logic.

### Error: "near 'DO': syntax error" (SQLite)
**Cause**: Migration is trying to execute PostgreSQL-specific PL/pgSQL on SQLite.
**Solution**: Ensure the migration's `SafeRenameIndex` class correctly detects SQLite and uses no-op behavior.

## Success Criteria

The migration is working correctly if:
1. ✓ It completes without errors on a fresh database
2. ✓ It can be run multiple times without errors
3. ✓ It can be reversed and re-applied
4. ✓ It works even when the old index doesn't exist
5. ✓ It preserves all data in the vulnerability table
6. ✓ It works on both PostgreSQL and SQLite

## Related Files

- Migration file: `scanner/migrations/0005_safe_index_rename.py`
- Test file: `scanner/tests_migration_0005.py`
- Model file: `scanner/models.py`
- Migration 0003 (creates index): `scanner/migrations/0003_add_advanced_features.py`
