# Generated migration for advanced detection fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sql_attacker', '0003_remove_redundant_discovered_params'),
    ]

    operations = [
        migrations.AddField(
            model_name='sqlinjectionresult',
            name='confidence_score',
            field=models.FloatField(default=0.7, help_text='Confidence score (0.0-1.0) for detection accuracy'),
        ),
        migrations.AddField(
            model_name='sqlinjectionresult',
            name='risk_score',
            field=models.IntegerField(default=50, help_text='Risk score (0-100) indicating severity and exploitability'),
        ),
        migrations.AddField(
            model_name='sqlinjectionresult',
            name='impact_analysis',
            field=models.JSONField(blank=True, null=True, help_text='Detailed impact demonstration results'),
        ),
        migrations.AddField(
            model_name='sqlinjectionresult',
            name='proof_of_concept',
            field=models.JSONField(blank=True, null=True, help_text='Proof-of-concept queries and findings'),
        ),
    ]
