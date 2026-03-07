import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sql_attacker', '0012_add_manipulator_fields'),
    ]

    operations = [
        # SQLInjectionTask – current_stage field for real-time Celery progress
        migrations.AddField(
            model_name='sqlinjectiontask',
            name='current_stage',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Current pipeline stage name for real-time progress reporting',
                max_length=50,
            ),
        ),

        # BugReport model
        migrations.CreateModel(
            name='BugReport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('result', models.ForeignKey(
                    help_text='The injection finding this bug report tracks',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='bug_reports',
                    to='sql_attacker.sqlinjectionresult',
                )),
                ('bug_id', models.CharField(
                    db_index=True,
                    help_text='Auto-generated unique identifier (e.g. SQLI-2026-001)',
                    max_length=30,
                    unique=True,
                )),
                ('title', models.CharField(
                    help_text='Auto-generated descriptive bug title',
                    max_length=255,
                )),
                ('status', models.CharField(
                    choices=[
                        ('new', 'New'),
                        ('confirmed', 'Confirmed'),
                        ('false_positive', 'False Positive'),
                        ('duplicate', 'Duplicate'),
                        ('wont_fix', "Won't Fix"),
                        ('in_progress', 'In Progress'),
                        ('resolved', 'Resolved'),
                        ('verified', 'Verified'),
                    ],
                    db_index=True,
                    default='new',
                    max_length=20,
                )),
                ('priority', models.CharField(
                    choices=[
                        ('P1_critical', 'P1 \u2013 Critical'),
                        ('P2_high', 'P2 \u2013 High'),
                        ('P3_medium', 'P3 \u2013 Medium'),
                        ('P4_low', 'P4 \u2013 Low'),
                        ('P5_info', 'P5 \u2013 Informational'),
                    ],
                    db_index=True,
                    default='P3_medium',
                    max_length=15,
                )),
                ('assignee', models.CharField(blank=True, default='', max_length=100)),
                ('triage_notes', models.TextField(blank=True, default='')),
                ('false_positive_reason', models.TextField(
                    blank=True,
                    default='',
                    help_text='Justification when status=false_positive',
                )),
                ('false_positive_indicators', models.JSONField(
                    blank=True,
                    help_text='Automated FP detection signals from FalsePositiveReducer',
                    null=True,
                )),
                ('verified_by', models.CharField(blank=True, default='', max_length=100)),
                ('verified_at', models.DateTimeField(blank=True, null=True)),
                ('resolution', models.TextField(blank=True, default='')),
                ('bounty_status', models.CharField(
                    choices=[
                        ('not_submitted', 'Not Submitted'),
                        ('submitted', 'Submitted'),
                        ('accepted', 'Accepted'),
                        ('rejected', 'Rejected'),
                        ('paid', 'Paid'),
                    ],
                    db_index=True,
                    default='not_submitted',
                    max_length=15,
                )),
                ('bounty_amount', models.DecimalField(
                    blank=True,
                    decimal_places=2,
                    help_text='Bounty amount awarded (USD)',
                    max_digits=10,
                    null=True,
                )),
                ('bounty_platform', models.CharField(
                    blank=True,
                    default='',
                    help_text='e.g. HackerOne, Bugcrowd, Intigriti',
                    max_length=50,
                )),
                ('bounty_submission_url', models.URLField(blank=True, default='', max_length=1024)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Bug Report',
                'verbose_name_plural': 'Bug Reports',
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(fields=['status', 'priority'], name='sql_bug_status_priority_idx'),
                    models.Index(fields=['bounty_status', 'created_at'], name='sql_bug_bounty_status_idx'),
                ],
            },
        ),

        # BountyImpactReport model
        migrations.CreateModel(
            name='BountyImpactReport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bug_report', models.OneToOneField(
                    help_text='The BugReport this impact report supplements',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='impact_report',
                    to='sql_attacker.bugreport',
                )),
                ('cvss_score', models.FloatField(
                    default=0.0,
                    help_text='Auto-calculated CVSS v3.1 base score',
                )),
                ('cvss_vector', models.CharField(
                    blank=True,
                    default='',
                    help_text='CVSS v3.1 vector string',
                    max_length=100,
                )),
                ('cwe_id', models.CharField(
                    blank=True,
                    default='CWE-89',
                    help_text='CWE identifier (e.g. CWE-89 for SQL Injection)',
                    max_length=20,
                )),
                ('impact_summary', models.TextField(blank=True, default='')),
                ('technical_details', models.TextField(blank=True, default='')),
                ('reproduction_steps', models.TextField(blank=True, default='')),
                ('business_impact', models.TextField(blank=True, default='')),
                ('remediation', models.TextField(blank=True, default='')),
                ('ready_to_submit_report', models.TextField(
                    blank=True,
                    default='',
                    help_text='Complete formatted bounty submission text',
                )),
                ('estimated_bounty_range', models.CharField(
                    blank=True,
                    default='',
                    help_text='e.g. $500-$2000',
                    max_length=50,
                )),
                ('submission_platform_template', models.CharField(
                    choices=[
                        ('hackerone', 'HackerOne'),
                        ('bugcrowd', 'Bugcrowd'),
                        ('intigriti', 'Intigriti'),
                        ('custom', 'Custom / Other'),
                    ],
                    default='hackerone',
                    max_length=20,
                )),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Bounty Impact Report',
                'verbose_name_plural': 'Bounty Impact Reports',
            },
        ),
    ]
