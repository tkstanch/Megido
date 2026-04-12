from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0018_add_scan_error_message'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='task_id',
            field=models.CharField(blank=True, db_index=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='scan',
            name='status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('completed', 'Completed'),
                    ('failed', 'Failed'),
                    ('cancelled', 'Cancelled'),
                ],
                default='pending',
                max_length=20,
            ),
        ),
    ]
