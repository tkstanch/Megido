# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Purpose and Scope

Megido is a **security testing tool** designed for authorized security professionals. The application intentionally includes functionality to:
- Send HTTP requests to arbitrary URLs (required for security testing)
- Intercept and modify network traffic (core security testing feature)
- Perform vulnerability scanning (intended purpose)

These capabilities are **features, not vulnerabilities**, as they are essential for the tool's purpose. See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for detailed analysis.

## Reporting a Vulnerability

If you discover a security vulnerability **in Megido itself** (not in systems you're testing with it):

### What to Report

Please report issues such as:
- Vulnerabilities in Megido's own code
- Authentication/authorization bypass in the application
- Data leakage or exposure of sensitive information
- Injection vulnerabilities in Megido's interface
- Unauthorized access to Megido's database or files

### What NOT to Report

Please do not report:
- SSRF warnings for the Repeater or Scanner (these are intentional features)
- "Ability to make arbitrary HTTP requests" (this is the tool's purpose)
- SSL verification being disabled by default (documented security testing feature)
- "Can be used for malicious purposes" (any tool can be misused)

### How to Report

1. **GitHub Security Advisory** (Preferred)
   - Go to the repository's Security tab
   - Click "Report a vulnerability"
   - Provide detailed information

2. **Email** (Alternative)
   - Contact the maintainer through GitHub
   - Include detailed reproduction steps
   - Provide proof of concept if applicable

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Varies by severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: 60-90 days

### Disclosure Policy

- **Coordinated Disclosure**: We follow responsible disclosure practices
- **Public Disclosure**: After a fix is released and deployed
- **Credit**: Security researchers will be credited (unless they prefer anonymity)

## Security Best Practices for Users

### For Authorized Testing
1. Obtain written permission before testing any system
2. Define clear scope and boundaries for testing
3. Use in isolated/controlled environments
4. Keep detailed audit logs
5. Follow all applicable laws and regulations

### For Deployment
1. Use strong, unique `DJANGO_SECRET_KEY`
2. Disable `DJANGO_DEBUG` in production
3. Configure `DJANGO_ALLOWED_HOSTS` properly
4. Implement authentication and authorization
5. Use network segmentation and firewalls
6. Enable audit logging
7. Keep dependencies updated
8. Regular security reviews

See [CONFIGURATION.md](CONFIGURATION.md) for detailed configuration guidance.

## Legal and Ethical Use

This tool is provided for:
- ✅ Authorized security testing
- ✅ Educational purposes
- ✅ Security research in controlled environments
- ✅ Internal security assessments with proper authorization

This tool should NOT be used for:
- ❌ Unauthorized testing of third-party systems
- ❌ Malicious activities
- ❌ Violation of laws or regulations
- ❌ Harassment or harm

**Users are solely responsible for ensuring their use complies with all applicable laws and regulations.**

## Known Security Considerations

### Intentional Design Decisions
- **SSRF by Design**: The tool must make requests to user-specified URLs
- **SSL Verification**: Disabled by default for testing self-signed certificates
- **Proxy Functionality**: Intentionally intercepts and modifies traffic

These are **documented features** required for security testing. See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for details.

### User Responsibilities
- Secure the deployment environment
- Implement access controls
- Monitor for misuse
- Maintain audit logs
- Follow security best practices

## Updates and Patches

- Security updates are released as soon as possible
- Critical vulnerabilities receive priority attention
- Subscribe to repository notifications for security updates
- Review [CHANGELOG.md] for security-related changes

## Contact

For security concerns:
- Use GitHub Security Advisory feature
- Check [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) before reporting
- Review documentation to ensure it's not an intended feature

## Acknowledgments

We appreciate responsible disclosure from security researchers who help make Megido more secure.

---

**Remember**: Megido is a tool for security professionals. Like any powerful tool, it must be used responsibly and ethically.
