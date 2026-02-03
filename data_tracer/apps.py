from django.apps import AppConfig


class DataTracerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'data_tracer'
    verbose_name = 'Data Tracer - Network Scanner'
