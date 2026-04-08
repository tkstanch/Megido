# Generated migration for the recon app.

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ReconProject',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
                ('user', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='recon_projects',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'verbose_name': 'Recon Project',
                'verbose_name_plural': 'Recon Projects',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='ScopeTarget',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target', models.CharField(max_length=500)),
                ('target_type', models.CharField(
                    choices=[
                        ('domain', 'Domain'),
                        ('subdomain', 'Subdomain'),
                        ('ip', 'IP Address'),
                        ('ip_range', 'IP Range'),
                        ('wildcard', 'Wildcard'),
                    ],
                    max_length=20,
                )),
                ('is_in_scope', models.BooleanField(default=True)),
                ('notes', models.TextField(blank=True)),
                ('added_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='targets',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Scope Target',
                'verbose_name_plural': 'Scope Targets',
            },
        ),
        migrations.AlterUniqueTogether(
            name='scopetarget',
            unique_together={('project', 'target')},
        ),
        migrations.CreateModel(
            name='WhoisResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=500)),
                ('raw_data', models.TextField(blank=True)),
                ('registrar', models.CharField(blank=True, max_length=200)),
                ('registrant_name', models.CharField(blank=True, max_length=200)),
                ('registrant_email', models.CharField(blank=True, max_length=200)),
                ('registrant_org', models.CharField(blank=True, max_length=200)),
                ('registrant_phone', models.CharField(blank=True, max_length=50)),
                ('registrant_address', models.TextField(blank=True)),
                ('creation_date', models.CharField(blank=True, max_length=100)),
                ('expiration_date', models.CharField(blank=True, max_length=100)),
                ('name_servers', models.TextField(blank=True)),
                ('status', models.TextField(blank=True)),
                ('queried_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='whois_results',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'WHOIS Result',
                'verbose_name_plural': 'WHOIS Results',
                'ordering': ['-queried_at'],
            },
        ),
        migrations.CreateModel(
            name='IPDiscovery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(blank=True, max_length=500)),
                ('ip_address', models.GenericIPAddressField()),
                ('reverse_domains', models.TextField(blank=True)),
                ('asn_number', models.CharField(blank=True, max_length=20)),
                ('asn_org', models.CharField(blank=True, max_length=200)),
                ('asn_country', models.CharField(blank=True, max_length=10)),
                ('ip_range', models.CharField(blank=True, max_length=100)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='ip_discoveries',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'IP Discovery',
                'verbose_name_plural': 'IP Discoveries',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.CreateModel(
            name='CertificateDiscovery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=500)),
                ('issuer', models.CharField(blank=True, max_length=500)),
                ('subject', models.CharField(blank=True, max_length=500)),
                ('not_before', models.CharField(blank=True, max_length=100)),
                ('not_after', models.CharField(blank=True, max_length=100)),
                ('san_domains', models.TextField(blank=True)),
                ('source', models.CharField(default='crt.sh', max_length=50)),
                ('cert_id', models.CharField(blank=True, max_length=100)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='certificates',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Certificate Discovery',
                'verbose_name_plural': 'Certificate Discoveries',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.CreateModel(
            name='SubdomainResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subdomain', models.CharField(max_length=500)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('status_code', models.IntegerField(blank=True, null=True)),
                ('is_alive', models.BooleanField(default=False)),
                ('source', models.CharField(blank=True, max_length=100)),
                ('title', models.CharField(blank=True, max_length=500)),
                ('technologies', models.TextField(blank=True)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('last_checked', models.DateTimeField(blank=True, null=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='subdomains',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Subdomain Result',
                'verbose_name_plural': 'Subdomain Results',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.AlterUniqueTogether(
            name='subdomainresult',
            unique_together={('project', 'subdomain')},
        ),
        migrations.CreateModel(
            name='ServicePort',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=500)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('port', models.IntegerField()),
                ('protocol', models.CharField(default='tcp', max_length=10)),
                ('service_name', models.CharField(blank=True, max_length=100)),
                ('service_version', models.CharField(blank=True, max_length=200)),
                ('banner', models.TextField(blank=True)),
                ('is_open', models.BooleanField(default=True)),
                ('source', models.CharField(default='nmap', max_length=50)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='services',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Service Port',
                'verbose_name_plural': 'Service Ports',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.AlterUniqueTogether(
            name='serviceport',
            unique_together={('project', 'host', 'port', 'protocol')},
        ),
        migrations.CreateModel(
            name='DirectoryFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_url', models.URLField(max_length=2000)),
                ('path', models.CharField(max_length=500)),
                ('full_url', models.URLField(blank=True, max_length=2000)),
                ('status_code', models.IntegerField()),
                ('content_length', models.IntegerField(blank=True, null=True)),
                ('content_type', models.CharField(blank=True, max_length=200)),
                ('redirect_url', models.URLField(blank=True, max_length=2000)),
                ('is_interesting', models.BooleanField(default=False)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='directories',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Directory Finding',
                'verbose_name_plural': 'Directory Findings',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.CreateModel(
            name='BucketFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bucket_name', models.CharField(max_length=500)),
                ('bucket_url', models.URLField(blank=True, max_length=2000)),
                ('provider', models.CharField(default='aws', max_length=50)),
                ('is_public', models.BooleanField(blank=True, null=True)),
                ('is_listable', models.BooleanField(default=False)),
                ('is_writable', models.BooleanField(default=False)),
                ('keywords', models.TextField(blank=True)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='buckets',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Bucket Finding',
                'verbose_name_plural': 'Bucket Findings',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.AlterUniqueTogether(
            name='bucketfinding',
            unique_together={('project', 'bucket_name', 'provider')},
        ),
        migrations.CreateModel(
            name='GitHubFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('finding_type', models.CharField(
                    choices=[
                        ('repo', 'Repository'),
                        ('secret', 'Secret'),
                        ('contributor', 'Contributor'),
                        ('leak', 'Data Leak'),
                        ('issue', 'Issue'),
                        ('commit', 'Commit'),
                    ],
                    max_length=20,
                )),
                ('repository', models.CharField(blank=True, max_length=500)),
                ('file_path', models.CharField(blank=True, max_length=500)),
                ('content', models.TextField(blank=True)),
                ('url', models.URLField(blank=True, max_length=2000)),
                ('severity', models.CharField(
                    choices=[
                        ('critical', 'Critical'),
                        ('high', 'High'),
                        ('medium', 'Medium'),
                        ('low', 'Low'),
                        ('info', 'Info'),
                    ],
                    default='info',
                    max_length=20,
                )),
                ('is_verified', models.BooleanField(default=False)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='github_findings',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'GitHub Finding',
                'verbose_name_plural': 'GitHub Findings',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.CreateModel(
            name='TechFingerprint',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_url', models.URLField(max_length=2000)),
                ('technology', models.CharField(max_length=200)),
                ('version', models.CharField(blank=True, max_length=100)),
                ('category', models.CharField(blank=True, max_length=100)),
                ('evidence', models.TextField(blank=True)),
                ('cve_count', models.IntegerField(default=0)),
                ('confidence', models.IntegerField(default=100)),
                ('discovered_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='tech_fingerprints',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Tech Fingerprint',
                'verbose_name_plural': 'Tech Fingerprints',
                'ordering': ['-discovered_at'],
            },
        ),
        migrations.CreateModel(
            name='ReconTask',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('task_type', models.CharField(
                    choices=[
                        ('whois', 'WHOIS Lookup'),
                        ('subdomain_enum', 'Subdomain Enumeration'),
                        ('port_scan', 'Port Scan'),
                        ('directory_brute', 'Directory Brute-Force'),
                        ('bucket_discovery', 'Bucket Discovery'),
                        ('github_recon', 'GitHub Recon'),
                        ('fingerprinting', 'Fingerprinting'),
                        ('full_recon', 'Full Recon'),
                        ('ip_discovery', 'IP Discovery'),
                        ('cert_parsing', 'Certificate Parsing'),
                    ],
                    max_length=30,
                )),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                        ('cancelled', 'Cancelled'),
                    ],
                    default='pending',
                    max_length=20,
                )),
                ('target', models.CharField(blank=True, max_length=500)),
                ('celery_task_id', models.CharField(blank=True, max_length=200)),
                ('progress', models.IntegerField(default=0)),
                ('result_summary', models.TextField(blank=True)),
                ('error_message', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='tasks',
                    to='recon.reconproject',
                )),
            ],
            options={
                'verbose_name': 'Recon Task',
                'verbose_name_plural': 'Recon Tasks',
                'ordering': ['-created_at'],
            },
        ),
    ]
