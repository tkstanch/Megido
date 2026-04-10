from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('recon', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='whoisresult',
            name='warning',
            field=models.TextField(blank=True),
        ),
    ]
