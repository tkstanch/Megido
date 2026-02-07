# Generated migration for new interceptor models

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('interceptor', '0002_interceptorsettings'),
    ]

    operations = [
        # Remove old InterceptedRequest fields and recreate with new schema
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='proxy_request',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='status',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='original_url',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='original_method',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='original_headers',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='original_body',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='modified_url',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='modified_method',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='modified_headers',
        ),
        migrations.RemoveField(
            model_name='interceptedrequest',
            name='modified_body',
        ),
        
        # Add new fields to InterceptedRequest
        migrations.AddField(
            model_name='interceptedrequest',
            name='url',
            field=models.URLField(max_length=2000, default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='method',
            field=models.CharField(max_length=10, default='GET'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='headers',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='body',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='interceptedrequest',
            name='source_app',
            field=models.CharField(blank=True, max_length=50, default=''),
        ),
        
        # Add indexes
        migrations.AddIndex(
            model_name='interceptedrequest',
            index=models.Index(fields=['-timestamp'], name='interceptor_timesta_idx'),
        ),
        migrations.AddIndex(
            model_name='interceptedrequest',
            index=models.Index(fields=['source_app'], name='interceptor_sourcea_idx'),
        ),
        migrations.AddIndex(
            model_name='interceptedrequest',
            index=models.Index(fields=['method'], name='interceptor_method_idx'),
        ),
        
        # Create InterceptedResponse model
        migrations.CreateModel(
            name='InterceptedResponse',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status_code', models.IntegerField()),
                ('headers', models.JSONField()),
                ('body', models.TextField()),
                ('response_time', models.FloatField()),
                ('request', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='response', to='interceptor.interceptedrequest')),
            ],
        ),
        migrations.AddIndex(
            model_name='interceptedresponse',
            index=models.Index(fields=['status_code'], name='interceptor_statusc_idx'),
        ),
        
        # Create PayloadRule model
        migrations.CreateModel(
            name='PayloadRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('target_url_pattern', models.CharField(help_text='Regex pattern to match URLs', max_length=500)),
                ('injection_type', models.CharField(choices=[('header', 'HTTP Header'), ('body', 'Request Body'), ('param', 'URL Parameter'), ('cookie', 'Cookie')], max_length=20)),
                ('injection_point', models.CharField(help_text='Header name, parameter name, etc.', max_length=100)),
                ('payload_content', models.TextField()),
                ('active', models.BooleanField(default=True)),
                ('target_apps', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='payloadrule',
            index=models.Index(fields=['active'], name='interceptor_active_idx'),
        ),
    ]
