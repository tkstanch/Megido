from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sql_attacker', '0013_add_bug_report_bounty_and_stage_fields'),
    ]

    operations = [
        migrations.AlterField(
            model_name='sqlinjectiontask',
            name='status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('awaiting_confirmation', 'Awaiting Confirmation'),
                    ('completed', 'Completed'),
                    ('failed', 'Failed'),
                    ('cancelled', 'Cancelled'),
                ],
                default='pending',
                max_length=21,
                help_text='Current execution status of this task',
            ),
        ),
    ]
