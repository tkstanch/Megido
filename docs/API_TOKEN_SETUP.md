# API Token Setup Guide

This guide explains how to configure and use API token authentication for secure programmatic access to the Megido Security scanner endpoints.

## Overview

The scanner API endpoints now require authentication using Django REST Framework's Token Authentication. This follows best-practice DRF security for programmatic API clients and ensures that only authorized users can access the vulnerability scanning functionality.

## Why Token Authentication?

Token authentication provides:

- **Security**: Only authenticated users with valid tokens can access scanner APIs
- **Traceability**: All API requests are tied to specific user accounts
- **Simplicity**: No need to send username/password with each request
- **Best Practice**: Follows Django REST Framework's recommended authentication patterns for programmatic clients

## Setup Instructions

### 1. Run the Setup Script

The easiest way to set up secure API access is to run the provided setup script:

```bash
./setup_secure_api.sh
```

This script will:
- Install all required dependencies
- Run database migrations
- Create authentication token tables
- Display next steps

### 2. Create a User Account

If you don't have a user account yet, create one:

```bash
python manage.py createsuperuser
```

Follow the prompts to create your username, email, and password.

### 3. Generate an API Token

Generate an API token for your user:

```bash
python manage.py create_scanner_token --username <your-username>
```

Replace `<your-username>` with your actual username. The command will output your token:

```
======================================================================
API TOKEN:
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
======================================================================

Use this token in your API requests:
  Authorization: Token <your-token-here>

Example with curl:
  curl -H "Authorization: Token a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0" http://localhost:8000/scanner/api/targets/
```

**Important**: Keep your token secure! Anyone with your token can access the API as you.

## Using the API Token

### Option 1: Environment Variable (Recommended)

Set the `MEGIDO_API_TOKEN` environment variable:

```bash
export MEGIDO_API_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```

Then run the demo script:

```bash
python demo.py
```

The demo script will automatically use the token from the environment variable.

### Option 2: Configure in demo.py

Edit `demo.py` and set the `API_TOKEN` variable directly:

```python
API_TOKEN = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'
```

### Option 3: Manual API Requests

Include the token in the Authorization header of your HTTP requests:

#### Using curl:

```bash
curl -H "Authorization: Token <your-token>" \
     http://localhost:8000/scanner/api/targets/
```

#### Using Python requests:

```python
import requests

headers = {
    'Authorization': 'Token a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'
}

# List scan targets
response = requests.get(
    'http://localhost:8000/scanner/api/targets/',
    headers=headers
)

# Create a scan target
response = requests.post(
    'http://localhost:8000/scanner/api/targets/',
    headers=headers,
    json={'url': 'http://example.com', 'name': 'My Scan'}
)

# Start a scan
response = requests.post(
    'http://localhost:8000/scanner/api/targets/1/scan/',
    headers=headers
)
```

## Protected Endpoints

The following scanner endpoints now require authentication:

- `GET/POST /scanner/api/targets/` - List or create scan targets
- `POST /scanner/api/targets/<id>/scan/` - Start a vulnerability scan

The following endpoint remains public for retrieving results:

- `GET /scanner/api/scans/<id>/results/` - Get scan results (no authentication required)

## Troubleshooting

### "Authentication credentials were not provided"

Make sure you're including the Authorization header in your request:

```
Authorization: Token <your-token>
```

### "Invalid token"

Your token may be incorrect or expired. Generate a new token:

```bash
python manage.py create_scanner_token --username <your-username>
```

### Demo script shows warning about missing token

If you see:

```
⚠️  WARNING: No API token configured!
```

Make sure you've set the `MEGIDO_API_TOKEN` environment variable or configured the token in demo.py.

## Security Best Practices

1. **Keep tokens secret**: Never commit tokens to version control
2. **Use environment variables**: Store tokens in environment variables, not in code
3. **Rotate tokens**: Regenerate tokens periodically or if compromised
4. **Limit token scope**: Use separate tokens for different applications or purposes
5. **Use HTTPS in production**: Always use HTTPS when transmitting tokens over the network

## Technical Details

### Implementation

The scanner endpoints use:

- **@csrf_exempt**: Exempts API endpoints from CSRF protection (standard for token-based APIs)
- **@authentication_classes([TokenAuthentication])**: Requires token authentication
- **@permission_classes([IsAuthenticated])**: Requires user to be authenticated

### REST Framework Configuration

The project is configured with DRF token authentication:

```python
# In settings.py
INSTALLED_APPS = [
    ...
    'rest_framework',
    'rest_framework.authtoken',
    ...
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}
```

## Additional Resources

- [Django REST Framework Authentication Documentation](https://www.django-rest-framework.org/api-guide/authentication/)
- [Token Authentication Guide](https://www.django-rest-framework.org/api-guide/authentication/#tokenauthentication)
- [DRF Security Best Practices](https://www.django-rest-framework.org/topics/security/)

## Support

For issues or questions:

1. Check the troubleshooting section above
2. Review the Django REST Framework documentation
3. Open an issue on the project repository
