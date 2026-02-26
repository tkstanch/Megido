"""
Minimal test settings for running discover app tests in isolation.
Uses SQLite and only includes the apps required by the discover tests.
"""
from megido_security.settings import *  # noqa: F401, F403

# Override database to use SQLite
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Minimal installed apps for discover tests
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'discover',
]

# Remove middleware that depends on apps not in INSTALLED_APPS
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Use an empty URL conf to avoid loading all app URLs
ROOT_URLCONF = 'megido_security.test_urls'

# Disable ASGI/channels for tests
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    }
}

# Silence logging during tests
import logging
logging.disable(logging.CRITICAL)

