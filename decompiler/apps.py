"""
Django app configuration for the Decompiler app.

This app is designed to capture and analyze user data from browser extensions
by decompiling and analyzing modern browser extension technologies such as:
- Java applets
- Flash (SWF files)
- Silverlight (XAP packages)

The app provides tools for intercepting, decompiling, analyzing, and manipulating
browser extension traffic and bytecode.
"""
from django.apps import AppConfig


class DecompilerConfig(AppConfig):
    """
    Configuration class for the Decompiler application.
    
    This app handles the complete workflow of browser extension analysis:
    1. Downloading and capturing extension packages
    2. Decompiling bytecode to source code
    3. Analyzing decompiled source
    4. Recompiling and executing code
    5. Manipulating extension components via JavaScript
    6. Defeating obfuscation techniques
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'decompiler'
    verbose_name = 'Browser Extension Decompiler'
