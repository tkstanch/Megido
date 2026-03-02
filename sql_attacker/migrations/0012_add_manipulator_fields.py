from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sql_attacker', '0011_add_celery_and_oob_fields'),
    ]

    operations = [
        # SQLInjectionTask – Manipulator integration fields
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='use_manipulator',
            field=models.BooleanField(
                default=False,
                help_text='Use Manipulator app tricks and encodings to enhance SQL injection payloads',
            ),
        ),
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='manipulator_encodings',
            field=models.JSONField(
                blank=True,
                null=True,
                help_text='Selected encoding techniques from Manipulator app',
            ),
        ),
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='manipulator_trick_ids',
            field=models.JSONField(
                blank=True,
                null=True,
                help_text='Selected manipulation trick IDs from Manipulator app',
            ),
        ),
        # SQLInjectionResult – Manipulator tracking fields
        migrations.AddField(
            model_name='sqlinjectionresult',
            name='manipulator_tricks_used',
            field=models.JSONField(
                blank=True,
                null=True,
                help_text='Manipulation tricks applied from Manipulator app',
            ),
        ),
        migrations.AddField(
            model_name='sqlinjectionresult',
            name='manipulator_encodings_used',
            field=models.JSONField(
                blank=True,
                null=True,
                help_text='Encoding techniques applied from Manipulator app',
            ),
        ),
    ]
