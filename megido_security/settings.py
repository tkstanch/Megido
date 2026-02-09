"""
Django settings for megido_security project.
"""
import os
from pathlib import Path

# Suppress SSL warnings during testing (configured for security testing tool)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-development-key-change-in-production'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', '*']

INSTALLED_APPS = [
    'daphne',  # Must be first for Channels ASGI support
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'channels',
    'rest_framework',
    'rest_framework.authtoken',
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

# ASGI application for Channels (WebSocket support)
ASGI_APPLICATION = 'megido_security.asgi.application'


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
if os.environ.get('USE_SQLITE', 'false').lower() == 'true':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    # PostgreSQL configuration - requires environment variables
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('DB_NAME', 'megido_db'),
            'USER': os.environ.get('DB_USER', 'megido_user'),
            'PASSWORD': os.environ.get('DB_PASSWORD'),  # No default - must be set via environment
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

# Wayback Machine Configuration
ENABLE_WAYBACK_MACHINE = os.environ.get('ENABLE_WAYBACK_MACHINE', 'true').lower() == 'true'
WAYBACK_MACHINE_TIMEOUT = int(os.environ.get('WAYBACK_MACHINE_TIMEOUT', '10'))
WAYBACK_MACHINE_MAX_RETRIES = int(os.environ.get('WAYBACK_MACHINE_MAX_RETRIES', '2'))

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

# ============================================================================
# Network and HTTP Settings for Local Testing
# ============================================================================
# WARNING: These settings are for LOCAL TESTING ONLY
# Never deploy to production with these permissive settings

# Disable SSL verification for testing (this is a security testing tool)
REQUESTS_VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() == 'true'

# Allow connections to any external host for testing
REQUESTS_ALLOW_REDIRECTS = True

# Timeout settings for external requests (in seconds)
REQUESTS_TIMEOUT = int(os.environ.get('REQUESTS_TIMEOUT', '30'))

# CORS settings for local testing (if using django-cors-headers)
# Only set if django-cors-headers is in INSTALLED_APPS
if 'corsheaders' in [app.split('.')[-1] for app in INSTALLED_APPS]:
    CORS_ALLOW_ALL_ORIGINS = True  # For local testing only

# Session and CSRF settings for local testing
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://0.0.0.0:8000',
]

# Security middleware settings for local development
# These should be enabled (True/secure values) in production
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
X_FRAME_OPTIONS = 'SAMEORIGIN'

# Allow external network access for security testing apps
ALLOW_EXTERNAL_REQUESTS = os.environ.get('ALLOW_EXTERNAL_REQUESTS', 'true').lower() == 'true'

# Authentication URLs
LOGIN_URL = '/admin/login/'
LOGIN_REDIRECT_URL = '/'

# Django REST Framework Configuration
# Note: Authentication is applied per-endpoint via decorators
# Scanner endpoints use TokenAuthentication for security
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
}

# Celery Configuration
# Redis is used as both the broker and result backend
# For development: Start Redis with `redis-server`
# For production: Use a dedicated Redis instance
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

# Celery task settings
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes hard limit
CELERY_TASK_SOFT_TIME_LIMIT = 25 * 60  # 25 minutes soft limit
CELERY_RESULT_EXTENDED_ENABLE = True
CELERY_RESULT_EXPIRES = 3600  # Results expire after 1 hour

# Celery serialization
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# For testing: Run tasks synchronously
# This is overridden in tests with @override_settings
CELERY_TASK_ALWAYS_EAGER = os.environ.get('CELERY_TASK_ALWAYS_EAGER', 'False').lower() == 'true'
CELERY_TASK_EAGER_PROPAGATES = True

# ============================================================================
# Django Channels Configuration (WebSocket Support)
# ============================================================================
# Redis is used as the channel layer backend for WebSocket communication
# This enables real-time updates for exploitation results
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [os.environ.get('REDIS_URL', 'redis://localhost:6379/1')],
            'capacity': 1500,  # Maximum number of messages to store
            'expiry': 10,  # Message expiry time in seconds
        },
    },
}

# For testing without Redis, use InMemoryChannelLayer
# Uncomment the following to use in-memory layer (development only)
# CHANNEL_LAYERS = {
#     'default': {
#         'BACKEND': 'channels.layers.InMemoryChannelLayer'
#     }
# }