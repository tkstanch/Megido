# Generated migration for proof reporting system

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0008_add_payload_and_repeater_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnerability',
            name='http_traffic',
            field=models.JSONField(blank=True, default=dict, help_text='Captured HTTP request/response traffic during exploitation'),
        ),
    ]
