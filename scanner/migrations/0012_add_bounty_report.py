"""
Migration to add bounty_report TextField to the Vulnerability model.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0011_add_new_vulnerability_types'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnerability',
            name='bounty_report',
            field=models.TextField(
                blank=True,
                null=True,
                help_text='Auto-generated bug bounty submission report (Markdown format)',
            ),
        ),
    ]
