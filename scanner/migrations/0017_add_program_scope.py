"""
Migration 0017: Add ProgramScope model and FK fields to Scan and HeatMapScan.
"""

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0016_add_heatmap_models'),
    ]

    operations = [
        # 1. Create ProgramScope table
        migrations.CreateModel(
            name='ProgramScope',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, help_text='Name of the bug bounty program or engagement')),
                ('in_scope_domains', models.JSONField(
                    default=list, blank=True,
                    help_text='Domains/URLs allowed to be scanned (supports wildcards like *.example.com)',
                )),
                ('out_of_scope_domains', models.JSONField(
                    default=list, blank=True,
                    help_text='Domains/URLs that must NOT be scanned',
                )),
                ('allowed_vulnerability_types', models.JSONField(
                    default=list, blank=True,
                    help_text='Vulnerability types allowed to test; empty means all allowed',
                )),
                ('disallowed_vulnerability_types', models.JSONField(
                    default=list, blank=True,
                    help_text='Vulnerability types explicitly prohibited',
                )),
                ('max_requests_per_second', models.FloatField(
                    null=True, blank=True,
                    help_text='Rate limit: maximum requests per second (optional)',
                )),
                ('testing_window_start', models.TimeField(
                    null=True, blank=True,
                    help_text='Start of allowed testing window (optional)',
                )),
                ('testing_window_end', models.TimeField(
                    null=True, blank=True,
                    help_text='End of allowed testing window (optional)',
                )),
                ('notes', models.TextField(
                    blank=True, default='',
                    help_text='Free-form program rules or special instructions',
                )),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),

        # 2. Add FK from Scan to ProgramScope
        migrations.AddField(
            model_name='scan',
            name='program_scope',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='scans',
                to='scanner.programscope',
            ),
        ),

        # 3. Add FK from HeatMapScan to ProgramScope
        migrations.AddField(
            model_name='heatmapscan',
            name='program_scope',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='heat_map_scans',
                to='scanner.programscope',
            ),
        ),
    ]
