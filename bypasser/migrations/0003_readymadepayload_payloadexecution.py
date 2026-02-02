# Generated migration for ReadyMadePayload and PayloadExecution models

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('bypasser', '0002_custombypasstechnique_customtechniqueexecution'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReadyMadePayload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Unique payload identifier', max_length=255, unique=True)),
                ('payload', models.TextField(help_text='The actual payload')),
                ('description', models.TextField(help_text='What this payload does')),
                ('category', models.CharField(choices=[('xss', 'XSS'), ('sqli', 'SQL Injection'), ('command_injection', 'Command Injection'), ('path_traversal', 'Path Traversal'), ('xxe', 'XXE'), ('ssti', 'SSTI'), ('ssrf', 'SSRF'), ('ldap', 'LDAP Injection'), ('nosql', 'NoSQL Injection'), ('general', 'General')], help_text='Attack type category', max_length=50)),
                ('bypass_target', models.CharField(choices=[('waf', 'WAF'), ('ips', 'IPS'), ('ids', 'IDS'), ('firewall', 'Firewall'), ('filter', 'Input Filter'), ('all', 'All')], help_text='What security control this bypasses', max_length=50)),
                ('risk_level', models.CharField(choices=[('info', 'Informational'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='medium', help_text='Risk level of using this payload', max_length=20)),
                ('times_used', models.IntegerField(default=0, help_text='Number of times payload has been used')),
                ('times_successful', models.IntegerField(default=0, help_text='Number of successful uses')),
                ('success_rate', models.FloatField(default=0.0, help_text='Success rate percentage')),
                ('is_active', models.BooleanField(default=True, help_text='Whether payload is active')),
                ('is_built_in', models.BooleanField(default=True, help_text='Is this a built-in payload')),
                ('tags', models.CharField(blank=True, help_text='Comma-separated tags', max_length=500, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['-times_successful', 'category', 'name'],
            },
        ),
        migrations.CreateModel(
            name='PayloadExecution',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transformations_applied', models.TextField(blank=True, help_text='Comma-separated list of transformations', null=True)),
                ('original_payload', models.TextField(help_text='Original payload from library')),
                ('transformed_payload', models.TextField(help_text='Payload after transformations')),
                ('success', models.BooleanField(default=False, help_text='Whether the payload worked')),
                ('http_status_code', models.IntegerField(blank=True, null=True)),
                ('response_time', models.FloatField(blank=True, help_text='Response time in seconds', null=True)),
                ('response_length', models.IntegerField(blank=True, null=True)),
                ('bypass_confirmed', models.BooleanField(default=False, help_text='Bypass definitively confirmed')),
                ('reflection_found', models.BooleanField(default=False, help_text='Payload reflected in response')),
                ('waf_triggered', models.BooleanField(default=False, help_text='WAF/filter was triggered')),
                ('error_message', models.TextField(blank=True, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('executed_at', models.DateTimeField(auto_now_add=True)),
                ('payload', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='executions', to='bypasser.readymadepayload')),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='payload_executions', to='bypasser.bypassersession')),
            ],
            options={
                'ordering': ['-executed_at'],
            },
        ),
        migrations.AddIndex(
            model_name='readymadepayload',
            index=models.Index(fields=['category', 'is_active'], name='bypasser_re_categor_8a7e3a_idx'),
        ),
        migrations.AddIndex(
            model_name='readymadepayload',
            index=models.Index(fields=['bypass_target', 'is_active'], name='bypasser_re_bypass__c5e6e0_idx'),
        ),
        migrations.AddIndex(
            model_name='readymadepayload',
            index=models.Index(fields=['risk_level'], name='bypasser_re_risk_le_f8b9c1_idx'),
        ),
        migrations.AddIndex(
            model_name='payloadexecution',
            index=models.Index(fields=['session', 'success'], name='bypasser_pa_session_a1b2c3_idx'),
        ),
        migrations.AddIndex(
            model_name='payloadexecution',
            index=models.Index(fields=['payload', 'success'], name='bypasser_pa_payload_d4e5f6_idx'),
        ),
    ]
