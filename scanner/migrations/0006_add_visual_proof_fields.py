# Generated migration to add visual proof fields to Vulnerability model
# This adds screenshot/GIF capture capability for successful exploitations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0005_safe_index_rename'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnerability',
            name='visual_proof_path',
            field=models.CharField(
                blank=True,
                help_text='Path to screenshot or GIF showing exploitation impact',
                max_length=512,
                null=True
            ),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='visual_proof_type',
            field=models.CharField(
                blank=True,
                choices=[
                    ('screenshot', 'Screenshot'),
                    ('gif', 'Animated GIF'),
                    ('video', 'Video')
                ],
                help_text='Type of visual proof',
                max_length=20,
                null=True
            ),
        ),
        migrations.AddField(
            model_name='vulnerability',
            name='visual_proof_size',
            field=models.IntegerField(
                blank=True,
                help_text='File size in bytes',
                null=True
            ),
        ),
    ]
