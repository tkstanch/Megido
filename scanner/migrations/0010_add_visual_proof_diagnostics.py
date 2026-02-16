# Migration for visual proof diagnostics and warnings system

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0009_add_http_traffic_field'),
    ]

    operations = [
        # Add warnings field to Scan model
        migrations.AddField(
            model_name='scan',
            name='warnings',
            field=models.JSONField(
                blank=True,
                default=list,
                help_text='List of warnings generated during the scan (e.g., missing dependencies, configuration issues)'
            ),
        ),
        # Add visual_proof_status field to Vulnerability model
        migrations.AddField(
            model_name='vulnerability',
            name='visual_proof_status',
            field=models.CharField(
                choices=[
                    ('captured', 'Successfully Captured'),
                    ('disabled', 'Disabled by Configuration'),
                    ('failed', 'Capture Failed'),
                    ('not_supported', 'Not Supported for This Vulnerability Type'),
                    ('missing_dependencies', 'Missing Required Dependencies'),
                    ('not_attempted', 'Not Attempted'),
                ],
                default='not_attempted',
                help_text='Status of visual proof capture attempt',
                max_length=50,
            ),
        ),
    ]
