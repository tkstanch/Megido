# Megido Security Testing Platform

A cutting-edge **cross-platform desktop application** for web and mobile security testing, built with Django and PySide6. Megido provides professional-grade security testing tools similar to Burp Suite Professional, with advanced features for vulnerability scanning, request interception, HTTP proxying, and automated security testing.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Django](https://img.shields.io/badge/django-6.0%2B-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

## 🌟 Features

### Core Security Testing Modules

1. **🔄 HTTP Proxy**
   - Intercept and analyze all HTTP/HTTPS traffic
   - SSL/TLS support for secure connections
   - Real-time traffic monitoring
   - Request/response history with database storage
   - Automatic content type detection

2. **✋ Request Interceptor**
   - Capture HTTP requests in real-time
   - Modify requests before forwarding to server
   - Drop or forward intercepted requests
   - Manual inspection and editing capabilities
   - Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)

3. **🔁 HTTP Repeater**
   - Manual HTTP request crafting and testing
   - Custom header and body support
   - Response time measurement
   - Request history and templating
   - Support for complex authentication scenarios

4. **🔍 Vulnerability Scanner**
   - Automated security vulnerability detection
   - Support for common vulnerability types:
     - Cross-Site Scripting (XSS)
     - SQL Injection
     - CSRF vulnerabilities
     - Security header analysis
     - SSL/TLS configuration issues
     - Information disclosure
     - And more...
   - Severity-based classification (Critical, High, Medium, Low)
   - Detailed remediation recommendations
   - Evidence-based reporting

### Technical Features

- ✅ **Cross-Platform Desktop Application**: Runs natively on Windows, macOS, and Linux
- ✅ **Django Backend**: Robust, scalable backend framework
- ✅ **REST API**: Full API support for automation and integration
- ✅ **Database-Backed**: SQLite database for persistent storage
- ✅ **Modern UI**: Clean, responsive web-based interface
- ✅ **Real-time Updates**: Live monitoring and auto-refresh capabilities
- ✅ **Extensible Architecture**: Easy to add new security testing modules

## 🚀 Installation

### Prerequisites

- Python 3.12 or higher
- pip (Python package manager)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tkstanch/Megido.git
   cd Megido
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run database migrations:**
   ```bash
   python manage.py migrate
   ```

4. **Start the desktop application:**
   ```bash
   python desktop_app.py
   ```

   Or run as a web application:
   ```bash
   python manage.py runserver
   ```
   Then open your browser to `http://localhost:8000`

## 📖 Usage Guide

### Starting the Application

#### Desktop Mode (Recommended)
```bash
python desktop_app.py
```
This launches the full desktop application with an integrated web view.

#### Web Mode
```bash
python manage.py runserver
```
Access the application at `http://localhost:8000` in your web browser.

### Using the HTTP Proxy

1. Navigate to the **Proxy** section
2. Configure your browser to use the proxy (typically `localhost:8080`)
3. Browse to target websites
4. View intercepted requests in real-time
5. Click on any request to view full details

### Using the Interceptor

1. Navigate to the **Interceptor** section
2. Enable interception mode
3. Pending requests will appear for manual inspection
4. Options:
   - **Forward**: Send the request as-is
   - **Drop**: Block the request
   - **Edit**: Modify the request before forwarding

### Using the Repeater

1. Navigate to the **Repeater** section
2. Configure your HTTP request:
   - Select HTTP method (GET, POST, PUT, DELETE, etc.)
   - Enter target URL
   - Add custom headers (JSON format)
   - Add request body if needed
3. Click "Send Request"
4. View the response including:
   - Status code
   - Response headers
   - Response body
   - Response time

### Using the Vulnerability Scanner

1. Navigate to the **Scanner** section
2. Enter target URL
3. Optionally provide a scan name
4. Click "Start Scan"
5. Wait for scan completion
6. Review discovered vulnerabilities:
   - Vulnerability type
   - Severity level
   - Affected URL
   - Evidence
   - Remediation recommendations

## 🏗️ Architecture

### Project Structure

```
Megido/
├── desktop_app.py          # Desktop application entry point
├── manage.py               # Django management script
├── requirements.txt        # Python dependencies
├── megido_security/        # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── proxy/                  # HTTP Proxy module
│   ├── models.py
│   ├── views.py
│   └── urls.py
├── interceptor/            # Request Interceptor module
│   ├── models.py
│   ├── views.py
│   └── urls.py
├── repeater/               # HTTP Repeater module
│   ├── models.py
│   ├── views.py
│   └── urls.py
├── scanner/                # Vulnerability Scanner module
│   ├── models.py
│   ├── views.py
│   └── urls.py
└── templates/              # HTML templates
    ├── base.html
    ├── home.html
    └── [module templates]
```

### Technology Stack

- **Backend**: Django 6.0+ (Python web framework)
- **Desktop Framework**: PySide6 (Qt for Python)
- **Database**: SQLite (can be upgraded to PostgreSQL/MySQL)
- **API**: Django REST Framework
- **HTTP Client**: Requests library
- **HTML Parsing**: BeautifulSoup4
- **Proxy**: mitmproxy (for advanced proxy features)

## 🔧 Configuration

### Django Settings

Edit `megido_security/settings.py` to configure:
- Database settings
- Allowed hosts
- Security settings
- Static files location

### Desktop Application Settings

Edit `desktop_app.py` to configure:
- Server port (default: 8000)
- Window size and position
- Application name and branding

## 🔌 API Reference

### Proxy API

- `GET /proxy/api/requests/` - List all proxy requests
- `GET /proxy/api/requests/<id>/` - Get request details

### Interceptor API

- `GET /interceptor/api/intercepted/` - List intercepted requests
- `GET /interceptor/api/intercepted/<id>/` - Get intercepted request
- `PUT /interceptor/api/intercepted/<id>/` - Update intercepted request

### Repeater API

- `GET /repeater/api/requests/` - List repeater requests
- `POST /repeater/api/requests/` - Create new request
- `POST /repeater/api/requests/<id>/send/` - Send request

### Scanner API

- `GET /scanner/api/targets/` - List scan targets
- `POST /scanner/api/targets/` - Create scan target
- `POST /scanner/api/targets/<id>/scan/` - Start scan
- `GET /scanner/api/scans/<id>/results/` - Get scan results

## 🛡️ Security Considerations

**Important**: This tool is designed for **authorized security testing only**.

- Always obtain proper authorization before testing any system
- Use only on systems you own or have explicit permission to test
- Be aware of legal and ethical implications
- This tool includes SSL verification bypass for testing purposes - use responsibly
- Keep the application updated with the latest security patches

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by Burp Suite Professional and other security testing tools
- Built with Django, PySide6, and other open-source technologies
- Thanks to the security research community

## 📞 Support

For issues, questions, or contributions, please:
- Open an issue on GitHub
- Check existing documentation
- Review the code comments and examples

## 🚀 Future Enhancements

Planned features for future releases:
- Advanced proxy filtering and scope management
- WebSocket support
- Custom vulnerability plugins
- Export reports (PDF, HTML, JSON)
- Collaborative testing features
- Advanced authentication handling (OAuth, JWT, etc.)
- Browser extension for easier proxy configuration
- Performance optimization for large-scale scans
- Machine learning-based vulnerability detection

---

**Disclaimer**: This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations.

