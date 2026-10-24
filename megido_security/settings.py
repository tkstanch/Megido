"""
Django settings for Megido Security project.

This is a Django 6.0+ compatible settings file for the Megido Security Platform,
a comprehensive web application security testing suite.

For production deployment:
- Set DEBUG = False
- Use environment variables for SECRET_KEY and sensitive settings
- Configure ALLOWED_HOSTS appropriately
- Enable security middleware settings (SSL, HSTS, etc.)
- Use PostgreSQL instead of SQLite
- Configure proper logging and monitoring

For more information on Django settings:
https://docs.djangoproject.com/en/6.0/topics/settings/

For deployment checklist:
https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/
"""
import os
from pathlib import Path

import urllib3
from django.core.exceptions import ImproperlyConfigured

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).resolve().parent.parent


def get_env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and (value is None or value == ""):
        raise ImproperlyConfigured(f"{name} is required")
    return value


SECRET_KEY = get_env("SECRET_KEY", "dev-secret-key-change-me")
DEBUG = get_env("DEBUG", "false").lower() == "true"

if not DEBUG and SECRET_KEY == "dev-secret-key-change-me":
    raise ImproperlyConfigured("SECRET_KEY must be set in production")

ALLOWED_HOSTS = [
    host.strip()
    for host in get_env("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]

INSTALLED_APPS = [
    'daphne',
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
    'forensics',
    'recon',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
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
ASGI_APPLICATION = 'megido_security.asgi.application'

# Database
SQLITE_DB_DIR = BASE_DIR / 'data'
SQLITE_DB_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_DB_PATH = SQLITE_DB_DIR / 'db.sqlite3'

if get_env('USE_SQLITE', 'false').lower() == 'true':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': SQLITE_DB_PATH,
        }
    }
else:
    DB_PASSWORD = get_env('DB_PASSWORD', '')
    if not DEBUG and not DB_PASSWORD:
        raise ImproperlyConfigured('DB_PASSWORD must be set in production when USE_SQLITE=false')

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': get_env('DB_NAME', 'megido_db'),
            'USER': get_env('DB_USER', 'megido_user'),
            'PASSWORD': DB_PASSWORD,
            'HOST': get_env('DB_HOST', 'localhost'),
            'PORT': get_env('DB_PORT', '5432'),
            'CONN_MAX_AGE': 60,
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

SQL_ATTACKER_ENABLE_VISUAL_EVIDENCE = True
SQL_ATTACKER_EVIDENCE_DIR = MEDIA_ROOT / 'sql_attacker' / 'evidence'
SQL_ATTACKER_HEADLESS_BROWSER = True

LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SHODAN_API_KEY = None
HUNTER_IO_KEY = None

ENABLE_WAYBACK_MACHINE = get_env('ENABLE_WAYBACK_MACHINE', 'true').lower() == 'true'
WAYBACK_MACHINE_TIMEOUT = int(get_env('WAYBACK_MACHINE_TIMEOUT', '10'))
WAYBACK_MACHINE_MAX_RETRIES = int(get_env('WAYBACK_MACHINE_MAX_RETRIES', '2'))

CLAMAV_HOST = get_env('CLAMAV_HOST', 'localhost')
CLAMAV_PORT = 3310
CLAMAV_TIMEOUT = 60

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

REQUESTS_VERIFY_SSL = get_env('VERIFY_SSL', 'true' if not DEBUG else 'false').lower() == 'true'
REQUESTS_ALLOW_REDIRECTS = True
REQUESTS_TIMEOUT = int(get_env('REQUESTS_TIMEOUT', '30'))

if 'corsheaders' in [app.split('.')[-1] for app in INSTALLED_APPS]:
    CORS_ALLOW_ALL_ORIGINS = False

CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in get_env('CSRF_TRUSTED_ORIGINS', 'http://localhost:8000,http://127.0.0.1:8000').split(',')
    if origin.strip()
]

NGROK_URL = get_env('NGROK_URL', '')
if NGROK_URL:
    CSRF_TRUSTED_ORIGINS.append(NGROK_URL)

SECURE_SSL_REDIRECT = get_env('SECURE_SSL_REDIRECT', 'true' if not DEBUG else 'false').lower() == 'true'
SESSION_COOKIE_SECURE = get_env('SESSION_COOKIE_SECURE', 'true' if not DEBUG else 'false').lower() == 'true'
CSRF_COOKIE_SECURE = get_env('CSRF_COOKIE_SECURE', 'true' if not DEBUG else 'false').lower() == 'true'
SECURE_HSTS_SECONDS = int(get_env('SECURE_HSTS_SECONDS', '31536000'))
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

ALLOW_EXTERNAL_REQUESTS = get_env('ALLOW_EXTERNAL_REQUESTS', 'false').lower() == 'true'

LOGIN_URL = '/admin/login/'
LOGIN_REDIRECT_URL = '/'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
}

CELERY_BROKER_URL = get_env('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = get_env('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 60 * 60
CELERY_TASK_SOFT_TIME_LIMIT = 58 * 60 + 20
CELERY_RESULT_EXTENDED_ENABLE = True
CELERY_RESULT_EXPIRES = 3600
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_ALWAYS_EAGER = get_env('CELERY_TASK_ALWAYS_EAGER', 'false').lower() == 'true'
CELERY_TASK_EAGER_PROPAGATES = True

if get_env('USE_IN_MEMORY_CHANNELS', 'false').lower() == 'true':
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels.layers.InMemoryChannelLayer',
        },
    }
    CELERY_TASK_ALWAYS_EAGER = True
else:
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels_redis.core.RedisChannelLayer',
            'CONFIG': {
                'hosts': [get_env('REDIS_URL', 'redis://localhost:6379/1')],
                'capacity': 1500,
                'expiry': 10,
            },
        },
    }

XSS_CALLBACK_ENDPOINT = get_env('XSS_CALLBACK_ENDPOINT', '')
XSS_CALLBACK_TIMEOUT = int(get_env('XSS_CALLBACK_TIMEOUT', '30'))
XSS_CALLBACK_VERIFICATION_ENABLED = get_env('XSS_CALLBACK_VERIFICATION_ENABLED', 'true').lower() == 'true'
XSS_CALLBACK_POLL_INTERVAL = int(get_env('XSS_CALLBACK_POLL_INTERVAL', '2'))
XSS_USE_INTERNAL_COLLABORATOR = get_env('XSS_USE_INTERNAL_COLLABORATOR', 'true').lower() == 'true'

NETWORK_MAX_RETRIES = int(get_env('MEGIDO_MAX_RETRIES', '3'))
NETWORK_BASE_DELAY = float(get_env('MEGIDO_BASE_DELAY', '1.0'))
NETWORK_MAX_DELAY = float(get_env('MEGIDO_MAX_DELAY', '30.0'))
NETWORK_JITTER_MAX = float(get_env('MEGIDO_JITTER_MAX', '1.0'))
NETWORK_DEFAULT_TIMEOUT = int(get_env('MEGIDO_DEFAULT_TIMEOUT', '30'))
NETWORK_CONNECT_TIMEOUT = int(get_env('MEGIDO_CONNECT_TIMEOUT', '10'))
NETWORK_READ_TIMEOUT = int(get_env('MEGIDO_READ_TIMEOUT', '30'))
NETWORK_RETRYABLE_STATUS_CODES = [408, 429, 500, 502, 503, 504]
NETWORK_DEGRADED_MODE_ENABLED = get_env('MEGIDO_DEGRADED_MODE', 'true').lower() == 'true'
NETWORK_SERVICE_TIMEOUTS = {
    'fireblocks_api': int(get_env('MEGIDO_TIMEOUT_FIREBLOCKS', '30')),
    'callback_server': int(get_env('MEGIDO_TIMEOUT_CALLBACK', '60')),
    'ngrok_api': int(get_env('MEGIDO_TIMEOUT_NGROK', '15')),
    'collaborator': int(get_env('MEGIDO_TIMEOUT_COLLABORATOR', '45')),
    'interactsh': int(get_env('MEGIDO_TIMEOUT_INTERACTSH', '45')),
}
NETWORK_DETAILED_LOGGING = get_env('MEGIDO_DETAILED_LOGGING', 'true').lower() == 'true'
NETWORK_LOG_LEVEL = get_env('MEGIDO_NETWORK_LOG_LEVEL', 'INFO')

LOGGING['loggers']['scanner.utils'] = {
    'handlers': ['console'],
    'level': NETWORK_LOG_LEVEL,
    'propagate': False,
}
LOGGING['loggers']['spider'] = {
    'handlers': ['console'],
    'level': 'INFO',
    'propagate': False,
}

SHODAN_API_KEY = get_env('SHODAN_API_KEY', SHODAN_API_KEY if 'SHODAN_API_KEY' in vars() else None)
GITHUB_TOKEN = get_env('GITHUB_TOKEN', '')
VIEWDNS_API_KEY = get_env('VIEWDNS_API_KEY', '')
CENSYS_API_ID = get_env('CENSYS_API_ID', '')
CENSYS_API_SECRET = get_env('CENSYS_API_SECRET', '')
IPINFO_TOKEN = get_env('IPINFO_TOKEN', '')

if DEBUG:
    CSRF_TRUSTED_ORIGINS = list(dict.fromkeys(CSRF_TRUSTED_ORIGINS))


# Backward compatibility aliases
# These keep older env names from crashing older code paths.
if not os.environ.get('MEGIDO_MAX_RETRIES'):
    MEGIDO_MAX_RETRIES = NETWORK_MAX_RETRIES
if not os.environ.get('MEGIDO_BASE_DELAY'):
    MEGIDO_BASE_DELAY = NETWORK_BASE_DELAY
if not os.environ.get('MEGIDO_MAX_DELAY'):
    MEGIDO_MAX_DELAY = NETWORK_MAX_DELAY
if not os.environ.get('MEGIDO_DEFAULT_TIMEOUT'):
    MEGIDO_DEFAULT_TIMEOUT = NETWORK_DEFAULT_TIMEOUT
if not os.environ.get('MEGIDO_CONNECT_TIMEOUT'):
    MEGIDO_CONNECT_TIMEOUT = NETWORK_CONNECT_TIMEOUT
if not os.environ.get('MEGIDO_READ_TIMEOUT'):
    MEGIDO_READ_TIMEOUT = NETWORK_READ_TIMEOUT


# End of settings.
