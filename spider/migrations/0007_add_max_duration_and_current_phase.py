from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('spider', '0006_add_scan_profile_and_max_crawl_urls'),
    ]

    operations = [
        migrations.AddField(
            model_name='spidertarget',
            name='max_duration',
            field=models.IntegerField(
                default=3600,
                help_text='Maximum session duration in seconds before graceful abort (0 = no limit)',
            ),
        ),
        migrations.AddField(
            model_name='spidersession',
            name='current_phase',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Current phase being executed (e.g. crawling, dirbuster, completed)',
                max_length=50,
            ),
        ),
    ]
