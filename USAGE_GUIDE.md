# Megido Security - Usage Guide

## Quick Start

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/tkstanch/Megido.git
   cd Megido
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the setup:
   - **Windows**: Double-click `setup.bat` or run `setup.bat` in cmd
   - **Linux/macOS**: Run `./setup.sh` or `bash setup.sh`

### Launching the Application

#### Option 1: Smart Launcher (Recommended)
```bash
python launch.py
```
The launcher will automatically detect your environment and choose the best mode.

#### Option 2: Desktop Mode (Explicit)
```bash
python launch.py desktop
# or
python desktop_app.py
```

#### Option 3: Web Mode (Explicit)
```bash
python launch.py web
# or
python manage.py runserver
```
Then open `http://localhost:8000` in your browser.

## Feature Guides

### 1. HTTP Proxy

The HTTP Proxy captures and logs all HTTP/HTTPS traffic.

**How to use:**
1. Navigate to the **Proxy** section
2. Configure your browser to use the proxy (usually `localhost:8080`)
3. Browse to target websites
4. View captured requests in real-time
5. Click on any request to see full details

**Use cases:**
- Monitor web application traffic
- Analyze API requests and responses
- Debug authentication flows
- Inspect headers and cookies

### 2. Request Interceptor

The Interceptor allows you to capture and modify requests before they reach the server.

**How to use:**
1. Navigate to the **Interceptor** section
2. Requests will appear in the pending queue
3. For each request, you can:
   - **Forward**: Send the request unchanged
   - **Drop**: Block the request
   - **Edit**: Modify the request before sending

**Use cases:**
- Test authorization bypass attempts
- Modify request parameters
- Test input validation
- Bypass client-side restrictions

### 3. HTTP Repeater

The Repeater lets you craft and send custom HTTP requests.

**How to use:**
1. Navigate to the **Repeater** section
2. Configure your request:
   - **Method**: Select HTTP method (GET, POST, PUT, DELETE, etc.)
   - **URL**: Enter target URL
   - **Headers**: Add custom headers in JSON format
   - **Body**: Add request body (for POST/PUT requests)
3. Click **Send Request**
4. View the response with timing information

**Example Headers:**
```json
{
  "Content-Type": "application/json",
  "Authorization": "Bearer your-token-here"
}
```

**Example Body (JSON):**
```json
{
  "username": "test",
  "password": "password123"
}
```

**Use cases:**
- Manual API testing
- Authentication testing
- Parameter manipulation
- Replay attack testing

### 4. Vulnerability Scanner

The Scanner automatically checks for common security vulnerabilities.

**How to use:**
1. Navigate to the **Scanner** section
2. Enter the target URL (e.g., `https://example.com`)
3. Optionally provide a scan name
4. Click **Start Scan**
5. Wait for completion
6. Review discovered vulnerabilities

**What it scans for:**
- Cross-Site Scripting (XSS)
- SQL Injection potential
- CSRF vulnerabilities
- Missing security headers
- SSL/TLS issues
- Information disclosure

**Understanding Results:**
- **Critical**: Requires immediate attention
- **High**: Important security issue
- **Medium**: Should be addressed
- **Low**: Best practice recommendation

## Advanced Usage

### Using the API

All functionality is available via REST API:

#### Proxy API
```bash
# List requests
curl http://localhost:8000/proxy/api/requests/

# Get request details
curl http://localhost:8000/proxy/api/requests/1/
```

#### Scanner API
```bash
# Create target
curl -X POST http://localhost:8000/scanner/api/targets/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "name": "My Target"}'

# Start scan
curl -X POST http://localhost:8000/scanner/api/targets/1/scan/

# Get results
curl http://localhost:8000/scanner/api/scans/1/results/
```

#### Repeater API
```bash
# Create request
curl -X POST http://localhost:8000/repeater/api/requests/ \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.example.com/endpoint",
    "method": "POST",
    "headers": "{\"Content-Type\": \"application/json\"}",
    "body": "{\"key\": \"value\"}"
  }'

# Send request
curl -X POST http://localhost:8000/repeater/api/requests/1/send/
```

### Admin Interface

Access the Django admin interface at `http://localhost:8000/admin/`

To create an admin user:
```bash
python manage.py createsuperuser
```

## Tips and Best Practices

### For Security Testing
1. **Always get authorization** before testing any system
2. Start with passive scanning (Proxy) before active testing
3. Use the Repeater to verify Scanner findings
4. Document all findings with evidence
5. Test in a controlled environment first

### For Development
1. Keep the application updated
2. Review scan results carefully (avoid false positives)
3. Use the API for automated testing
4. Integrate with your CI/CD pipeline

### Performance
1. Limit scan scope to specific URLs
2. Use the Repeater for targeted testing
3. Clear old requests regularly via admin interface
4. Consider using PostgreSQL for large-scale testing

## Troubleshooting

### Desktop mode won't start
- **Issue**: Error about missing display or libEGL
- **Solution**: Use web mode instead: `python launch.py web`

### PySide6 installation fails
- **Solution**: Try installing system packages first:
  - Ubuntu/Debian: `apt-get install python3-pyqt6`
  - Use web mode as alternative

### Port already in use
- **Issue**: Port 8000 is already in use
- **Solution**: Run on different port: `python manage.py runserver 8080`

### Scanner not finding vulnerabilities
- **Note**: The scanner performs basic checks. For comprehensive testing, use multiple tools
- Check that the target URL is accessible
- Review Django logs for errors

### SSL/TLS errors
- The application disables SSL verification for testing
- This is intentional for security testing scenarios
- Always use in controlled environments

## Platform-Specific Notes

### Windows
- Run `setup.bat` to install
- Desktop mode works out of the box
- Use Command Prompt or PowerShell

### macOS
- Run `bash setup.sh` to install
- Desktop mode requires Xcode Command Line Tools
- Grant necessary permissions when prompted

### Linux
- Run `bash setup.sh` to install
- Desktop mode requires X11 or Wayland
- Install Qt dependencies: `apt-get install python3-pyqt6` (Ubuntu/Debian)
- For headless servers, use web mode

## Security Warnings

⚠️ **Important Security Notices:**

1. This tool is for **authorized testing only**
2. Never use on production systems without permission
3. Be aware of legal implications in your jurisdiction
4. The tool includes SSL verification bypass - use responsibly
5. Keep the application and dependencies updated
6. Don't expose the application to untrusted networks
7. Change the Django SECRET_KEY in production

## Getting Help

- Check the [README.md](README.md) for general information
- Review Django logs for errors
- Open an issue on GitHub
- Consult the code documentation

## Contributing

Contributions welcome! See the repository for:
- Feature requests
- Bug reports
- Pull requests
- Documentation improvements
