"""
App configuration for the Recon module.
"""
from django.apps import AppConfig


class ReconConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'recon'
    verbose_name = 'Recon - Web Hacking Reconnaissance'
