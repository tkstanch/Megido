from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('interceptor', '0004_rename_interceptor_timesta_idx_interceptor_timesta_505c0a_idx_and_more'),
    ]

    operations = [
        # Remove old index on 'method'
        migrations.RemoveIndex(
            model_name='interceptedrequest',
            name='interceptor_method_43698d_idx',
        ),

        # Rename simple fields to original_* names
        migrations.RenameField(
            model_name='interceptedrequest',
            old_name='method',
            new_name='original_method',
        ),
        migrations.RenameField(
            model_name='interceptedrequest',
            old_name='url',
            new_name='original_url',
        ),
        migrations.RenameField(
            model_name='interceptedrequest',
            old_name='headers',
            new_name='original_headers',
        ),
        migrations.RenameField(
            model_name='interceptedrequest',
            old_name='body',
            new_name='original_body',
        ),

        # Add status field
        migrations.AddField(
            model_name='interceptedrequest',
            name='status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pending'),
                    ('modified', 'Modified'),
                    ('forwarded', 'Forwarded'),
                    ('dropped', 'Dropped'),
                ],
                default='pending',
                max_length=20,
            ),
        ),

        # Add modified_* fields
        migrations.AddField(
            model_name='interceptedrequest',
            name='modified_method',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='modified_url',
            field=models.URLField(blank=True, max_length=2000, null=True),
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='modified_headers',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='modified_body',
            field=models.TextField(blank=True, null=True),
        ),

        # Add indexes for renamed and new fields
        migrations.AddIndex(
            model_name='interceptedrequest',
            index=models.Index(fields=['original_method'], name='interceptor_orig_method_idx'),
        ),
        migrations.AddIndex(
            model_name='interceptedrequest',
            index=models.Index(fields=['status'], name='interceptor_status_idx'),
        ),
    ]
