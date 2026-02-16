# Generated migration for enhanced verification fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0007_exploitmedia'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnerability',
            name='successful_payloads',
            field=models.JSONField(blank=True, default=list, help_text='List of payloads that successfully exploited the vulnerability'),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='repeater_data',
            field=models.JSONField(blank=True, default=list, help_text='Copy-paste ready HTTP requests for manual verification in repeater app'),
        ),
    ]
