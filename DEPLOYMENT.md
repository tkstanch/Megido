# Production Deployment Guide

## Requirements
- Ubuntu 22.04 or Debian 12
- Python 3.12
- PostgreSQL 15+
- Redis
- Nginx
- systemd

## Setup
1. Clone the project.
2. Create a virtual environment.
3. Install dependencies:
   ```bash
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and populate the values.
5. Run database migrations:
   ```bash
   python manage.py migrate
   ```
6. Collect static files:
   ```bash
   python manage.py collectstatic --noinput
   ```
7. Start the app with Gunicorn or uWSGI:
   ```bash
   gunicorn megido_security.wsgi:application --bind 0.0.0.0:8000
   ```
8. Configure Nginx as a reverse proxy in front of Gunicorn.
9. Terminate TLS with a real certificate provider or reverse proxy.
10. Use a dedicated PostgreSQL database and Redis instance in production.

## Security Notes
- Do not run with `DEBUG=true` in production.
- Keep `SECRET_KEY` out of source control.
- Restrict `ALLOWED_HOSTS` to your real production domains.
- Keep `.env` local and never commit it.
- Use HTTPS only.
- Use a production database with proper credentials and permissions.

## Operational Notes
- Monitor logs and database health.
- Keep Redis and PostgreSQL running as managed services.
- Create a backup and restore procedure for the database.
- Define a support escalation path for application failures.
