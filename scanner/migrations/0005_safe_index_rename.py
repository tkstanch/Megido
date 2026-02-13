# No-op migration for index renaming
# 
# RATIONALE FOR THIS MIGRATION:
# -----------------------------
# This migration was originally intended to rename indexes, but those indexes either
# do not exist in the database or have already been renamed. The target indexes are
# already present with their new names.
#
# Specifically, the following index renames were originally planned but are no longer needed:
# - scanner_vul_risk_sc_idx -> scanner_vul_risk_score_idx
# - scanner_vul_verifie_idx -> scanner_vul_verified_idx
# - scanner_vul_false_p_idx -> scanner_vul_false_positive_status_idx
#
# CURRENT STATE:
# The database schema already has the correct indexes, so this migration does nothing.
# This prevents errors when running migrations where:
# - Old indexes don't exist
# - New indexes already exist
# - Database was manually modified or migrations applied in different order
#
# BEST PRACTICE:
# Never rewrite existing migrations in shared/production codebases. Instead, create
# new migrations that are robust and handle edge cases gracefully. In this case,
# making the migration a no-op ensures it can run in any environment without errors.
#
# MAINTAINER NOTE:
# This migration intentionally does nothing. Do not add operations unless you have
# verified that the database schema requires changes.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_engineexecution_enginefinding_enginescan_and_more'),
    ]

    operations = [
        # No operations - indexes are already in correct state
    ]
