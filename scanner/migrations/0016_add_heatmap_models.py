from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    """
    Add HeatMapScan and HeatMapHotspot models for the heat map analyzer feature.
    """

    dependencies = [
        ('scanner', '0015_add_sqli_testing'),
    ]

    operations = [
        migrations.CreateModel(
            name='HeatMapScan',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_url', models.URLField(max_length=2048)),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                    ],
                    default='pending',
                    max_length=20,
                )),
                ('started_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('total_hotspots', models.IntegerField(default=0)),
                ('summary', models.JSONField(blank=True, default=dict)),
                ('risk_scores', models.JSONField(blank=True, default=dict)),
                ('error_message', models.TextField(blank=True, null=True)),
            ],
            options={
                'ordering': ['-started_at'],
            },
        ),
        migrations.CreateModel(
            name='HeatMapHotspot',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('heat_map_scan', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='hotspots',
                    to='scanner.HeatMapScan',
                )),
                ('category', models.CharField(max_length=100)),
                ('category_label', models.CharField(blank=True, max_length=255, null=True)),
                ('url', models.URLField(max_length=2048)),
                ('parameter', models.CharField(blank=True, max_length=255, null=True)),
                ('risk_score', models.IntegerField(default=5)),
                ('priority', models.CharField(
                    choices=[
                        ('Critical', 'Critical'),
                        ('High', 'High'),
                        ('Medium', 'Medium'),
                        ('Low', 'Low'),
                    ],
                    default='Medium',
                    max_length=20,
                )),
                ('vulnerabilities', models.JSONField(blank=True, default=list)),
                ('payloads', models.JSONField(blank=True, default=list)),
                ('description', models.TextField(blank=True, null=True)),
                ('evidence', models.TextField(blank=True, null=True)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-risk_score', 'priority'],
            },
        ),
        migrations.AddIndex(
            model_name='heatmaphotspot',
            index=models.Index(fields=['priority'], name='scanner_hm_priority_idx'),
        ),
        migrations.AddIndex(
            model_name='heatmaphotspot',
            index=models.Index(fields=['risk_score'], name='scanner_hm_risk_idx'),
        ),
    ]
