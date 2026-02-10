# Generated migration for stealth enhancements and interactive mode

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sql_attacker', '0004_add_advanced_detection_fields'),
    ]

    operations = [
        # Enhanced stealth configuration
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='max_requests_per_minute',
            field=models.IntegerField(default=20, help_text='Maximum requests per minute (rate limiting)'),
        ),
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='enable_jitter',
            field=models.BooleanField(default=True, help_text='Add random jitter to timing delays'),
        ),
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='randomize_headers',
            field=models.BooleanField(default=True, help_text='Randomize HTTP headers (Referer, Accept-Language, etc.)'),
        ),
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='max_retries',
            field=models.IntegerField(default=3, help_text='Maximum retry attempts for failed requests'),
        ),
        
        # Interactive mode configuration
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='require_confirmation',
            field=models.BooleanField(default=False, help_text='Require manual confirmation after parameter discovery'),
        ),
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='awaiting_confirmation',
            field=models.BooleanField(default=False, help_text='Task is waiting for confirmation to proceed'),
        ),
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='selected_params',
            field=models.JSONField(blank=True, null=True, help_text='Manually selected parameters to test'),
        ),
        
        # Update status choices to include awaiting_confirmation
        migrations.AlterField(
            model_name='sqlinjectiontask',
            name='status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('awaiting_confirmation', 'Awaiting Confirmation'),
                    ('completed', 'Completed'),
                    ('failed', 'Failed')
                ],
                db_index=True,
                default='pending',
                max_length=20
            ),
        ),
    ]
