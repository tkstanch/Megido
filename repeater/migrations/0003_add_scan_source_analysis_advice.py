import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('repeater', '0002_add_repeater_tab_and_update_request'),
        ('scanner', '0015_add_sqli_testing'),
    ]

    operations = [
        migrations.AddField(
            model_name='repeaterrequest',
            name='scan',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='repeater_requests',
                to='scanner.scan',
            ),
        ),
        migrations.AddField(
            model_name='repeaterrequest',
            name='source',
            field=models.CharField(
                choices=[
                    ('manual', 'Manual'),
                    ('scanner', 'Scanner'),
                    ('interceptor', 'Interceptor'),
                    ('exploit', 'Exploit'),
                ],
                default='manual',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='repeaterrequest',
            name='analysis_advice',
            field=models.TextField(blank=True, null=True),
        ),
    ]
