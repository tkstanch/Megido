# Test settings that override migrations to skip problematic ones
from megido_security.settings import *
import os

os.environ['USE_SQLITE'] = 'true'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable problematic migrations
MIGRATION_MODULES = {
    'scanner': None,
    'sql_attacker': None,
}

# Also disable apps with cross-dependencies
for app in ['repeater', 'proxy', 'collaborator', 'interceptor', 'discover']:
    if app not in MIGRATION_MODULES:
        MIGRATION_MODULES[app] = None
