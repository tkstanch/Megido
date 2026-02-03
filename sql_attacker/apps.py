from django.apps import AppConfig


class SqlAttackerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sql_attacker'
    verbose_name = 'SQL Injection Attacker'
