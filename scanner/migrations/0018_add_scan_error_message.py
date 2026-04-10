"""
Migration 0018: Add error_message field to Scan model.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0017_add_program_scope'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='error_message',
            field=models.TextField(blank=True, null=True),
        ),
    ]
