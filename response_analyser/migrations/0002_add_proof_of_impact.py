# Generated migration for adding proof_of_impact field

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('response_analyser', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnerability',
            name='proof_of_impact',
            field=models.TextField(blank=True, null=True, help_text='Proof of Concept or evidence of impact for this vulnerability'),
        ),
    ]
