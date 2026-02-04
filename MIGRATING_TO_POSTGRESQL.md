# Migrating Megido to PostgreSQL

This guide explains how to migrate from SQLite to PostgreSQL database backend for the Megido Security Testing Platform.

## Overview

The default database configuration has been updated to use PostgreSQL instead of SQLite. PostgreSQL is recommended for production deployments due to its robustness, scalability, and advanced features.

## Prerequisites

1. **PostgreSQL Installed**: You need PostgreSQL installed and running on your system
   - Linux: `sudo apt-get install postgresql postgresql-contrib` (Ubuntu/Debian)
   - macOS: `brew install postgresql`
   - Windows: Download from https://www.postgresql.org/download/windows/

2. **Python Package**: The `psycopg2-binary` package is required (already added to requirements.txt)
   ```bash
   pip install -r requirements.txt
   ```
   
   **Note**: `psycopg2-binary` is a stand-alone package that includes its own PostgreSQL client library and is suitable for development and testing. For production deployments on Linux, consider using `psycopg2` (without `-binary`) which is compiled from source and may have better performance. On Windows and macOS, `psycopg2-binary` is generally recommended.

## Database Configuration

The current database configuration in `megido_security/settings.py` is set to:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'radical',
        'USER': 'tkstanch',
        'PASSWORD': 'YOUR_PASSWORD_HERE',  # See actual password in settings.py
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

**Note**: The actual password is configured in `megido_security/settings.py`. This documentation uses placeholders for security.

## Step-by-Step Migration

### 1. Set Up PostgreSQL Database

First, create the PostgreSQL database and user:

```bash
# Switch to postgres user (Linux/macOS)
sudo -u postgres psql

# Or on Windows, open psql from Start Menu and run:
psql -U postgres
```

Then in the PostgreSQL prompt:

```sql
-- Create the database
CREATE DATABASE radical;

-- Create the user with password (use the password from settings.py)
CREATE USER tkstanch WITH PASSWORD 'YOUR_PASSWORD_HERE';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE radical TO tkstanch;

-- Grant schema privileges (PostgreSQL 15+)
\c radical
GRANT ALL ON SCHEMA public TO tkstanch;

-- Exit
\q
```

### 2. Test Database Connection

Verify that you can connect to the database:

```bash
psql -U tkstanch -d radical -h localhost -p 5432
# Enter password when prompted
```

If the connection is successful, type `\q` to exit.

### 3. Run Django Migrations

Apply all Django migrations to set up the database schema:

```bash
python manage.py migrate
```

This will create all necessary tables in the PostgreSQL database.

### 4. Create a Superuser (Optional)

If you need an admin user for Django admin interface:

```bash
python manage.py createsuperuser
```

Follow the prompts to create your admin account.

### 5. Migrate Data from SQLite (Optional)

If you have existing data in SQLite that you want to migrate:

```bash
# Export data from SQLite
python manage.py dumpdata --natural-foreign --natural-primary -e contenttypes -e auth.Permission --indent 4 > data.json

# Switch to PostgreSQL configuration (already done)
# Load data into PostgreSQL
python manage.py loaddata data.json
```

**Note**: Some data types may not be directly compatible. Test thoroughly after migration.

### 6. Verify the Setup

Start the Django development server:

```bash
python manage.py runserver
```

Access the application at http://localhost:8000 and verify everything works correctly.

## Environment Variables (Production Best Practice)

For production deployments, it's **highly recommended** to use environment variables instead of hardcoding credentials:

### Update settings.py

```python
import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'radical'),
        'USER': os.environ.get('DB_USER', 'tkstanch'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'YOUR_DEFAULT_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}
```

### Set Environment Variables

**Linux/macOS:**
```bash
export DB_NAME=radical
export DB_USER=tkstanch
export DB_PASSWORD='YOUR_PASSWORD_HERE'
export DB_HOST=localhost
export DB_PORT=5432
```

**Windows (Command Prompt):**
```cmd
set DB_NAME=radical
set DB_USER=tkstanch
set DB_PASSWORD=YOUR_PASSWORD_HERE
set DB_HOST=localhost
set DB_PORT=5432
```

**Windows (PowerShell):**
```powershell
$env:DB_NAME="radical"
$env:DB_USER="tkstanch"
$env:DB_PASSWORD="YOUR_PASSWORD_HERE"
$env:DB_HOST="localhost"
$env:DB_PORT="5432"
```

Alternatively, create a `.env` file (not tracked in git) and load it using python-decouple or similar.

## Docker Setup

If using Docker, update your `docker-compose.yml` to include a PostgreSQL service:

```yaml
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: radical
      POSTGRES_USER: tkstanch
      POSTGRES_PASSWORD: YOUR_PASSWORD_HERE  # Use secure password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  web:
    # ... existing web service configuration
    depends_on:
      - db
    environment:
      DB_HOST: db  # Use service name as host in Docker

volumes:
  postgres_data:
```

## Troubleshooting

### Connection Refused

- Verify PostgreSQL is running: `sudo systemctl status postgresql` (Linux) or `pg_ctl status` (Windows)
- Check PostgreSQL is listening on localhost:5432
- Verify `pg_hba.conf` allows local connections

### Authentication Failed

- Double-check username and password
- Ensure the PostgreSQL user was created correctly
- Check `pg_hba.conf` authentication method (should be `md5` or `scram-sha-256`)

### Permission Denied

- Grant necessary privileges to the user:
  ```sql
  GRANT ALL PRIVILEGES ON DATABASE radical TO tkstanch;
  GRANT ALL ON SCHEMA public TO tkstanch;
  ```

### Migration Errors

- Ensure all apps are properly configured in `INSTALLED_APPS`
- Clear any existing migration history conflicts
- Try running migrations one app at a time: `python manage.py migrate app_name`

## Security Considerations

⚠️ **Important Security Notes:**

1. **Never commit database credentials to version control**
2. **Use environment variables or secrets management in production**
3. **Use strong, unique passwords for production databases**
4. **Restrict database access to necessary hosts only**
5. **Enable SSL/TLS for database connections in production**
6. **Regularly backup your database**
7. **Keep PostgreSQL updated with security patches**

## Rollback to SQLite

If you need to rollback to SQLite, update `settings.py`:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
```

Then run migrations again: `python manage.py migrate`

## Additional Resources

- [Django PostgreSQL Notes](https://docs.djangoproject.com/en/6.0/ref/databases/#postgresql-notes)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [psycopg2 Documentation](https://www.psycopg.org/docs/)

## Support

For issues or questions:
- Check the [main README](README.md)
- Review [CONFIGURATION.md](CONFIGURATION.md) for environment setup
- Open an issue on GitHub: https://github.com/tkstanch/Megido/issues
