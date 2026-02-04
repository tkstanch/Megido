#!/bin/bash
set -e

echo "Waiting for database to be ready..."
sleep 2

echo "Running database migrations..."
python manage.py migrate --noinput

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

echo "Starting application..."
exec "$@"
