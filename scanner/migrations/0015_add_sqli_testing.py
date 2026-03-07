from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Add enable_sqli_testing flag to Scan model.

    New field on Scan model:
        - enable_sqli_testing (BooleanField, default=False)
    """

    dependencies = [
        ('scanner', '0014_add_bounty_vulnerability_types'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='enable_sqli_testing',
            field=models.BooleanField(
                default=False,
                help_text='Whether SQL Injection tests via the SQL Attacker engine are enabled for this scan',
            ),
        ),
    ]
