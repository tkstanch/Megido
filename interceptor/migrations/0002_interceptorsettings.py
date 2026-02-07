# Generated migration for InterceptorSettings

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('interceptor', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='InterceptorSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_enabled', models.BooleanField(default=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Interceptor Settings',
                'verbose_name_plural': 'Interceptor Settings',
            },
        ),
    ]
