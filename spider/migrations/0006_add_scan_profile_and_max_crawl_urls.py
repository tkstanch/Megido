from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('spider', '0005_add_adaptive_stealth_and_max_parameter_tests'),
    ]

    operations = [
        migrations.AddField(
            model_name='spidertarget',
            name='scan_profile',
            field=models.CharField(
                choices=[
                    ('quick', 'Quick'),
                    ('standard', 'Standard'),
                    ('aggressive', 'Aggressive'),
                    ('custom', 'Custom'),
                ],
                default='custom',
                help_text='Scan preset: quick (crawl only), standard (all phases + stealth), aggressive (all phases, no stealth), custom (manual)',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='spidertarget',
            name='max_crawl_urls',
            field=models.IntegerField(default=500, help_text='Maximum number of URLs to crawl'),
        ),
    ]
