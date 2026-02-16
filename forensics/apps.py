"""
Django app configuration for the Forensics app.

This app provides a digital forensics dashboard for analyzing forensic images,
smartphone backups, system backups, and log files.
"""
from django.apps import AppConfig


class ForensicsConfig(AppConfig):
    """
    Configuration class for the Forensics application.
    
    This app handles:
    1. File upload and storage
    2. Basic file analysis (hash, size, type)
    3. Sample data/hex extraction
    4. Device/file metadata extraction (when available)
    5. Web dashboard for uploading and reviewing results
    
    Future extensions could include:
    - Integration with PyTSK3 for disk image analysis
    - YARA rule scanning
    - Timeline analysis
    - Artifact extraction (browser history, registry, etc.)
    - Memory dump analysis
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'forensics'
    verbose_name = 'Digital Forensics Dashboard'
