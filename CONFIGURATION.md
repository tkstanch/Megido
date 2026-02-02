# Megido Security - Environment Configuration

This file documents the environment variables that can be used to configure the application.

## Security Settings

### DJANGO_SECRET_KEY
**Required for production**

The Django secret key used for cryptographic signing.

**Default**: Auto-generated insecure key (for development only)

**Production Example**:
```bash
export DJANGO_SECRET_KEY="your-random-secret-key-here"
```

Generate a secure secret key:
```python
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### DJANGO_DEBUG
Control Django debug mode.

**Default**: `True` (development mode)

**Production**:
```bash
export DJANGO_DEBUG=False
```

### DJANGO_ALLOWED_HOSTS
Comma-separated list of allowed hostnames.

**Default**: `localhost,127.0.0.1`

**Production Example**:
```bash
export DJANGO_ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
```

## Application Settings

### MEGIDO_VERIFY_SSL
Control SSL certificate verification for security testing requests.

**Default**: `False` (disabled for testing purposes)

This is intentionally disabled by default because:
- This is a security testing tool
- Many test environments use self-signed certificates
- Security professionals often need to test against invalid certificates

**To Enable SSL Verification**:
```bash
export MEGIDO_VERIFY_SSL=True
```

**Security Note**: When testing production systems, consider enabling this to model secure practices.

## Usage

### Linux/macOS
Create a `.env` file or export variables:
```bash
export DJANGO_SECRET_KEY="your-secret-key"
export DJANGO_DEBUG=False
export DJANGO_ALLOWED_HOSTS=localhost
export MEGIDO_VERIFY_SSL=False
```

### Windows
Set environment variables:
```cmd
set DJANGO_SECRET_KEY=your-secret-key
set DJANGO_DEBUG=False
set DJANGO_ALLOWED_HOSTS=localhost
set MEGIDO_VERIFY_SSL=False
```

Or use PowerShell:
```powershell
$env:DJANGO_SECRET_KEY="your-secret-key"
$env:DJANGO_DEBUG="False"
$env:DJANGO_ALLOWED_HOSTS="localhost"
$env:MEGIDO_VERIFY_SSL="False"
```

## Production Deployment Checklist

Before deploying to production:

- [ ] Set a strong, random DJANGO_SECRET_KEY
- [ ] Set DJANGO_DEBUG=False
- [ ] Configure DJANGO_ALLOWED_HOSTS with your domain(s)
- [ ] Use a production-grade database (PostgreSQL, MySQL)
- [ ] Set up proper SSL/TLS certificates
- [ ] Configure firewall rules
- [ ] Set up regular backups
- [ ] Review and update security settings
- [ ] Use environment variables or secure configuration management
- [ ] Never commit secrets to version control

## Development vs Production

### Development (Default)
- DEBUG enabled for error messages
- Uses SQLite database
- Includes Django toolbar and development features
- SSL verification disabled for testing
- Insecure secret key (auto-generated)

### Production
- DEBUG disabled
- Uses production database (PostgreSQL/MySQL)
- Secure secret key from environment
- Proper ALLOWED_HOSTS configuration
- SSL verification configurable based on needs
- Rate limiting and security middleware enabled

## Additional Security Recommendations

1. **Use HTTPS**: Always use HTTPS in production
2. **Database Security**: Use strong database passwords
3. **Regular Updates**: Keep Django and dependencies updated
4. **Access Control**: Implement proper authentication and authorization
5. **Rate Limiting**: Add rate limiting for API endpoints
6. **Logging**: Set up comprehensive security logging
7. **Backups**: Regular automated backups
8. **Monitoring**: Monitor for suspicious activity

For more information, see Django's security documentation:
https://docs.djangoproject.com/en/6.0/topics/security/
