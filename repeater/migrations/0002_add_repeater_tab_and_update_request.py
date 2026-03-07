# Generated migration for RepeaterTab model and RepeaterRequest updates

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('repeater', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='RepeaterTab',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(default='New Tab', max_length=255)),
                ('order', models.IntegerField(default=0)),
                ('follow_redirects', models.BooleanField(default=True)),
                ('max_redirects', models.IntegerField(default=10)),
                ('timeout', models.FloatField(default=30.0)),
                ('verify_ssl', models.BooleanField(default=False)),
                ('auto_content_length', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['order', 'created_at'],
            },
        ),
        migrations.AddField(
            model_name='repeaterrequest',
            name='tab',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='requests',
                to='repeater.repeatertab',
            ),
        ),
        migrations.AddField(
            model_name='repeaterrequest',
            name='tab_history_index',
            field=models.IntegerField(default=0),
        ),
    ]
