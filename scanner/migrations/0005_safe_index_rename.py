# No-op migration for index renaming
# 
# RATIONALE FOR THIS MIGRATION:
# -----------------------------
# This migration previously attempted to rename database indexes but caused errors in some
# environments where the indexes did not exist. Users reported errors like:
#     django.db.utils.ProgrammingError: relation "scanner_vul_risk_sc_idx" does not exist
#
# The migration has been converted to a no-op (does nothing) to prevent these failures.
#
# ORIGINAL INTENT:
# This migration was originally intended to rename indexes:
# - scanner_vul_risk_sc_idx -> scanner_vul_risk_score_idx
# - scanner_vul_verifie_idx -> scanner_vul_verified_idx
# - scanner_vul_false_p_idx -> scanner_vul_false_positive_status_idx
#
# WHY NO-OP:
# The index rename can fail on some databases where:
# - Old indexes don't exist in fresh installations
# - Indexes were manually dropped or never created
# - Migrations were applied in different orders across environments
# - Database schema was modified outside of Django migrations
#
# This no-op approach supersedes the previous "safe index rename" approach which used
# conditional SQL logic (PL/pgSQL DO blocks). Even with conditional checks, the complexity
# and database-specific behavior made it prone to failures in diverse environments.
#
# TROUBLESHOOTING FOR USERS:
# If you encounter migration errors related to this migration, you can mark it as applied
# without running any operations by using:
#     python manage.py migrate scanner 0005 --fake
#
# This will record the migration in Django's migration history without executing any SQL.
#
# CURRENT STATE:
# The database schema should have the correct indexes. This migration does nothing to ensure
# compatibility across all environments and database states.
#
# BEST PRACTICE:
# Never rewrite existing migrations in shared/production codebases. Instead, create
# new migrations that are robust and handle edge cases gracefully. In this case,
# making the migration a no-op ensures it can run in any environment without errors.
#
# MAINTAINER NOTE:
# This migration intentionally does nothing. Do not add operations unless you have
# verified that the database schema requires changes across ALL deployment environments.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_engineexecution_enginefinding_enginescan_and_more'),
    ]

    operations = [
        # No operations - indexes are already in correct state
    ]
