#!/bin/bash
set -e

echo "Waiting for database to be ready..."
until python -c "
import os, sys, psycopg2
try:
    psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        port=os.environ.get('DB_PORT', '5432'),
        dbname=os.environ.get('DB_NAME', 'megido_db'),
        user=os.environ.get('DB_USER', 'megido_user'),
        password=os.environ.get('DB_PASSWORD', 'megido_pass'),
    )
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
    echo "PostgreSQL is unavailable - waiting..."
    sleep 2
done
echo "PostgreSQL is ready."

# Only the web/gunicorn process runs migrations and one-time setup tasks.
# Celery workers start in parallel with the web container; running migrate
# in both concurrently on a fresh database causes race conditions that
# violate the pg_type_typname_nsp_index unique constraint (two processes
# trying to CREATE TABLE the same tables at the same time).
if [ "${1}" != "celery" ]; then
    echo "Running database migrations..."
    python manage.py migrate --noinput

    echo "Collecting static files (including favicon.ico)..."
    python manage.py collectstatic --noinput --clear

    echo "Creating superuser if it doesn't exist..."
    python manage.py shell << END
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin')
    print('Superuser created: username=admin, password=admin')
else:
    print('Superuser already exists')
END
fi

echo "Starting application..."
exec "$@"
