# Generated migration for advanced vulnerability scanner features

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_vulnerability_exploit_attempted_at_and_more'),
    ]

    operations = [
        # Risk scoring fields
        migrations.AddField(
            model_name='vulnerability',
            name='risk_score',
            field=models.FloatField(default=0.0, help_text='Composite risk score (0-100)'),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='risk_level',
            field=models.CharField(default='medium', help_text='Risk level: critical, high, medium, low', max_length=20),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='confidence_score',
            field=models.FloatField(default=0.5, help_text='Confidence in finding (0.0-1.0)'),
        ),
        
        # Verification and proof of impact
        migrations.AddField(
            model_name='vulnerability',
            name='verified',
            field=models.BooleanField(default=False, help_text='Verified through successful exploitation'),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='proof_of_impact',
            field=models.TextField(blank=True, help_text='Evidence of real-world impact', null=True),
        ),
        
        # False positive management
        migrations.AddField(
            model_name='vulnerability',
            name='false_positive_status',
            field=models.CharField(
                choices=[
                    ('unknown', 'Unknown'),
                    ('confirmed', 'Confirmed Vulnerability'),
                    ('false_positive', 'False Positive'),
                    ('accepted_risk', 'Accepted Risk'),
                ],
                default='unknown',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='false_positive_reason',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='reviewed_by',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='reviewed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        
        # Compliance mapping
        migrations.AddField(
            model_name='vulnerability',
            name='compliance_violations',
            field=models.JSONField(blank=True, default=dict, help_text='Mapping to compliance frameworks (GDPR, PCI-DSS, OWASP, etc.)'),
        ),
        
        # Remediation
        migrations.AddField(
            model_name='vulnerability',
            name='remediation_priority',
            field=models.IntegerField(default=3, help_text='Priority 1-5 (1=highest)'),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='remediation_effort',
            field=models.CharField(
                choices=[
                    ('low', 'Low'),
                    ('medium', 'Medium'),
                    ('high', 'High'),
                ],
                default='medium',
                max_length=20,
            ),
        ),
        
        # Add indexes for performance
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['risk_score'], name='scanner_vul_risk_sc_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['verified'], name='scanner_vul_verifie_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['false_positive_status'], name='scanner_vul_false_p_idx'),
        ),
    ]
