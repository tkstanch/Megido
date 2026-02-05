"""
Django settings for megido_security project.
"""
import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-development-key-change-in-production'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'app_manager',
    'browser',
    'proxy',
    'interceptor',
    'repeater',
    'scanner',
    'spider',
    'mapper',
    'bypasser',
    'collaborator',
    'decompiler',
    'malware_analyser',
    'response_analyser',
    'sql_attacker',
    'data_tracer',
    'discover',
    'manipulator',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'app_manager.middleware.AppEnabledMiddleware',
]

ROOT_URLCONF = 'megido_security.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'megido_security.wsgi.application'


# Database
# https://docs.djangoproject.com/en/6.0/ref/settings/#databases

# PostgreSQL Database Configuration
# For production, use environment variables to override these defaults
# See MIGRATING_TO_POSTGRESQL.md and CONFIGURATION.md for setup instructions
#
# Note: Default values below are for development/testing purposes.
# Override with environment variables in production for security.

# Use SQLite for testing when PostgreSQL is not available
import os
if os.environ.get('USE_SQLITE', 'false').lower() == 'true' or not os.environ.get('DB_NAME'):
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('DB_NAME', 'radical'),
            'USER': os.environ.get('DB_USER', 'tkstanch'),
            'PASSWORD': os.environ.get('DB_PASSWORD', 'radicalglitch@1998####$'),
            'HOST': os.environ.get('DB_HOST', 'localhost'),
            'PORT': os.environ.get('DB_PORT', '5432'),
        }
    }

# Legacy SQLite configuration (commented out after PostgreSQL migration)
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/

STATIC_URL = 'static/'

# Media files (User uploads)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# https://docs.djangoproject.com/en/6.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# OSINT API Keys for Discover app
# Set these to enable Shodan and Hunter.io integrations
SHODAN_API_KEY = None  # Get from https://account.shodan.io/
HUNTER_IO_KEY = None   # Get from https://hunter.io/api

# ClamAV Configuration (can be overridden via environment variables)
CLAMAV_HOST = 'clamav'  # Use 'localhost' if running ClamAV locally
CLAMAV_PORT = 3310
CLAMAV_TIMEOUT = 60

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'app_manager': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}