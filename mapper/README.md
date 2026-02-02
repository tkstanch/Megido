# Mapper - Attack Surface Mapping Django App

## Overview

The Mapper app is a security-focused Django application designed to demonstrate and implement secure development practices across common web application attack vectors. It serves as both a reference implementation and a practical tool for mapping and mitigating security vulnerabilities in the Megido project.

## Security Features

### 1. Client-side Validation with Server-side Enforcement
- **Model**: `ValidationRule`
- **Implementation**: Server-side validation that mirrors and enforces all client-side rules
- **Protection**: Prevents validation bypass attempts

### 2. SQL Injection Prevention
- **Implementation**: Uses Django ORM with parameterized queries exclusively
- **Views**: `secure_query()` demonstrates safe database querying
- **Protection**: Prevents SQL injection through proper ORM usage

### 3. Secure File Handling
- **Model**: `SecureFileUpload`
- **Features**:
  - UUID-based filenames to prevent path traversal
  - File extension validation
  - File size limits
  - Malware scanning flag
- **Views**: `secure_file_upload()`, `secure_file_download()`
- **Protection**: Path traversal prevention, stored XSS prevention

### 4. XSS Prevention
- **Model**: `SanitizedUserData`
- **Implementation**: All user input is sanitized and escaped
- **Views**: `user_data_view()`, `submit_user_data()`
- **Protection**: Prevents stored and reflected XSS attacks

### 5. Secure Redirects
- **Model**: `RedirectLog`
- **Implementation**: URL whitelist validation
- **Views**: `secure_redirect()`
- **Protection**: Prevents open redirect and header injection vulnerabilities

### 6. Login Security
- **Model**: `LoginAttempt`
- **Features**:
  - Username enumeration prevention with generic error messages
  - Brute force protection via rate limiting
  - Comprehensive login attempt logging
  - IP address and user agent tracking
- **Views**: `secure_login()`
- **Protection**: Prevents username enumeration and brute force attacks

### 7. Strong Password Policies
- **Model**: `PasswordPolicy`
- **Features**:
  - Minimum length requirements
  - Complexity requirements (uppercase, lowercase, digits, special chars)
  - Password age and reuse prevention
- **Function**: `validate_password_strength()`
- **Protection**: Enforces strong passwords

### 8. Secure Session Management
- **Model**: `SecureSessionToken`
- **Features**:
  - Cryptographically secure token generation using `secrets` module
  - Token expiry and activity tracking
  - IP address binding
- **Protection**: Prevents token prediction and session hijacking

### 9. Access Control Logging
- **Model**: `AccessLog`
- **Features**:
  - Logs all access control decisions
  - Tracks both granted and denied access
  - Records resource type, action, and user
- **Protection**: Detects privilege escalation attempts

### 10. Secure Error Handling
- **Model**: `ErrorLog`
- **Features**:
  - Detailed errors logged server-side
  - Generic error messages for users
  - Unique error codes for support reference
- **Protection**: Prevents information leakage

### 11. Dependency Auditing
- **Model**: `DependencyAudit`
- **Features**:
  - Tracks third-party packages and versions
  - Logs known vulnerabilities
  - Tracks patching status
- **Protection**: Monitors for vulnerable dependencies

## Models

### Core Security Models

1. **ValidationRule** - Client-side validation rules with server enforcement
2. **SecureFileUpload** - Secure file upload with path traversal prevention
3. **RedirectLog** - Redirect logging and validation
4. **LoginAttempt** - Login attempt tracking and brute force protection
5. **SecureSessionToken** - Cryptographically secure session tokens
6. **AccessLog** - Access control decision logging
7. **SanitizedUserData** - XSS-safe user data storage
8. **PasswordPolicy** - Password strength enforcement
9. **ErrorLog** - Secure error logging without information leakage
10. **DependencyAudit** - Third-party dependency vulnerability tracking

## Views and Endpoints

- `/mapper/` - Home page with security feature overview
- `/mapper/login/` - Secure login with enumeration prevention
- `/mapper/upload/` - Secure file upload
- `/mapper/download/<uuid>/` - Secure file download with access control
- `/mapper/redirect/` - Validated redirect handler
- `/mapper/user-data/` - XSS-protected user data display
- `/mapper/submit-data/` - Sanitized data submission
- `/mapper/query/` - SQL injection-safe search
- `/mapper/validate/` - Server-side input validation

## Testing

The app includes comprehensive unit tests covering:
- All security models
- Authentication and authorization
- File upload/download security
- XSS prevention
- SQL injection prevention
- CSRF protection
- Password validation
- Session management
- Access control

Run tests with:
```bash
python manage.py test mapper
```

## Security Best Practices Demonstrated

1. **Input Validation**: Always validate on server-side, never trust client
2. **Output Encoding**: Escape all user data before display
3. **Parameterized Queries**: Use ORM, never concatenate SQL
4. **Secure Random**: Use `secrets` module for cryptographic operations
5. **Access Control**: Check permissions before every sensitive operation
6. **Error Handling**: Log detailed errors internally, show generic messages externally
7. **Rate Limiting**: Implement for authentication endpoints
8. **CSRF Protection**: Use Django's CSRF middleware
9. **Secure Headers**: Set appropriate security headers on responses
10. **Dependency Management**: Audit and update dependencies regularly

## Integration with Megido

The Mapper app integrates seamlessly with the Megido security testing platform:
- Uses the same authentication system
- Follows the same URL structure pattern
- Compatible with existing middleware
- Shares the Django admin interface
- Uses consistent coding patterns

## Admin Interface

All models are registered in the Django admin interface with appropriate:
- List displays
- Filters
- Search fields
- Read-only fields for sensitive data

Access via `/admin/mapper/`

## Future Enhancements

Potential areas for expansion:
1. Email injection prevention
2. Command injection prevention
3. Buffer overflow detection
4. Web server hardening checks
5. SSL/TLS configuration validation
6. Security header enforcement
7. Content Security Policy (CSP) implementation
8. Subresource Integrity (SRI) verification

## License

Part of the Megido project. See main project license.
