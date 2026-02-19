# Migration to safely add visual evidence fields to SQLInjectionResult.
#
# Migration 0007 was converted to a no-op for the database (state_operations only)
# to handle databases that are in a partial schema state. This migration performs
# the actual database changes using conditional logic so that it is idempotent and
# safe to run regardless of which columns already exist.
#
# This handles the two known error states:
#   - DuplicateColumn: column "injection_context" already exists
#   - ProgrammingError: column "screenshots" does not exist

from django.db import migrations

TABLE = 'sql_attacker_sqlinjectionresult'

# Columns to add: (column_name, postgresql_type, sqlite_type)
COLUMNS = [
    ('all_injection_points',    'jsonb',          'text'),
    ('evidence_timeline',       'jsonb',          'text'),
    ('extracted_sensitive_data','jsonb',          'text'),
    ('gif_evidence',            'varchar(100)',   'varchar(100)'),
    ('injection_context',       "varchar(50) NOT NULL DEFAULT 'sql'",
                                "varchar(50) NOT NULL DEFAULT 'sql'"),
    ('proof_of_impact',         'text',           'text'),
    ('screenshots',             'jsonb',          'text'),
    ('successful_payloads',     'jsonb',          'text'),
    ('verified',                'boolean NOT NULL DEFAULT false',
                                'integer NOT NULL DEFAULT 0'),
    ('video_evidence',          'varchar(100)',   'varchar(100)'),
    ('visual_proof_path',       'varchar(512)',   'varchar(512)'),
    ('visual_proof_size',       'integer',        'integer'),
    ('visual_proof_type',       'varchar(20)',    'varchar(20)'),
]

# Indexes to create: (index_name, columns)
# sql_attacke_injecti_915905_idx: single-column index on injection_context (db_index=True)
# sql_attacke_injecti_88412f_idx: composite index declared in AddIndex of migration 0007
INDEXES = [
    ('sql_attacke_injecti_915905_idx', '(injection_context)'),
    ('sql_attacke_injecti_88412f_idx', '(injection_context, detected_at)'),
]


def add_columns_and_indexes(apps, schema_editor):
    connection = schema_editor.connection
    vendor = connection.vendor

    with connection.cursor() as cursor:
        if vendor == 'postgresql':
            # Build a single DO $$ block with IF NOT EXISTS checks for all columns
            checks = '\n'.join(
                f"""
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = '{TABLE}' AND column_name = '{col}'
    ) THEN
        ALTER TABLE {TABLE} ADD COLUMN {col} {pg_type};
    END IF;"""
                for col, pg_type, _ in COLUMNS
            )
            cursor.execute(f"DO $$\nBEGIN{checks}\nEND $$;")

            # Create indexes conditionally (PostgreSQL supports CREATE INDEX IF NOT EXISTS)
            for idx_name, idx_cols in INDEXES:
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS {idx_name} ON {TABLE} {idx_cols};"
                )

        elif vendor == 'sqlite':
            # SQLite: use PRAGMA table_info to check existing columns
            cursor.execute(f"PRAGMA table_info({TABLE})")
            existing = {row[1] for row in cursor.fetchall()}

            for col, _, sqlite_type in COLUMNS:
                if col not in existing:
                    cursor.execute(
                        f"ALTER TABLE {TABLE} ADD COLUMN {col} {sqlite_type};"
                    )

            # SQLite: check existing indexes via sqlite_master
            for idx_name, idx_cols in INDEXES:
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name=%s",
                    [idx_name],
                )
                if not cursor.fetchone():
                    cursor.execute(
                        f"CREATE INDEX {idx_name} ON {TABLE} {idx_cols};"
                    )


class Migration(migrations.Migration):

    dependencies = [
        ('sql_attacker', '0007_add_visual_evidence_fields'),
    ]

    operations = [
        migrations.RunPython(
            add_columns_and_indexes,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
